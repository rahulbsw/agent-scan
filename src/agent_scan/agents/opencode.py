"""opencode discoverer: ``~/.config/opencode/opencode.{json,jsonc}`` + skills +
per-project ``opencode.json`` + per-OS managed configs + ``$OPENCODE_CONFIG`` override."""

import logging
import os
import sqlite3
import sys
from pathlib import Path

from agent_scan.agents.base import (
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
)
from agent_scan.models import MCPConfig, OpenCodeConfigFile
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)

# Format union for opencode MCP files. Only one format today; declared as a
# tuple to plug into ``_parse_mcp_file`` uniformly with the other discoverers.
_OPENCODE_MCP_FORMATS: tuple[type[MCPConfig], ...] = (OpenCodeConfigFile,)
# opencode accepts either extension; per https://opencode.ai/docs/config the
# layered-config loader tries each when reading global and project scopes.
_CONFIG_FILENAMES: tuple[str, ...] = ("opencode.json", "opencode.jsonc")


class OpenCodeDiscoverer(AgentDiscoverer):
    """opencode discovery across global, project, managed, and ``$OPENCODE_CONFIG`` scopes.

    Scope sources:

    * Global — ``~/.config/opencode/opencode.{json,jsonc}`` (mcp) and
      ``~/.config/opencode/skills`` (skills). ``~/.config/opencode`` is XDG-style
      on every OS opencode supports, including Windows (verified empirically).
    * Project — for every project root in ``_project_paths_with_ancestors`` (and
      its ancestors): ``<root>/opencode.{json,jsonc}`` plus ``<root>/.opencode/skills``.
    * Managed — per-OS system-wide ``opencode.{json,jsonc}`` (and ``skills/``)
      under ``/Library/Application Support/opencode`` (macOS), ``/etc/opencode``
      (Linux), or ``%ProgramData%\\opencode`` (Windows).
    * Env override — ``$OPENCODE_CONFIG`` names an alternate config file; honored
      only on an own-home scan (the env var reflects the *scanning process's*
      environment, so it must not be applied to other users under
      ``--scan-all-users``).

    Project enumeration is unusual: opencode persists the absolute paths of
    opened projects in a SQLite database at
    ``~/.local/share/opencode/opencode.db`` (Drizzle ``project`` table,
    ``worktree`` column). :meth:`_discover_project_folders` reads it read-only;
    any failure (missing file, lock contention, schema drift) yields an empty
    list rather than aborting discovery.
    """

    name = "opencode"

    _install_path = "~/.config/opencode"
    _data_path = "~/.local/share/opencode"
    _db_filename = "opencode.db"
    _skills_subdir = "skills"
    # Project-scoped skill dirs scanned at every opened project root and its
    # ancestors. ``.opencode/skills`` is opencode's canonical project skills
    # location per https://opencode.ai/docs/skills.
    _project_skills_relative: tuple[str, ...] = (".opencode/skills",)

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = self._global_config_dir()
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(self._discover_global_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        result.update(self._discover_managed_mcp_servers())
        result.update(self._discover_env_override_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skills())
        result.update(self._discover_project_skills())
        result.update(self._discover_managed_skills())
        return result

    # --- folder resolution ---

    def _global_config_dir(self) -> Path:
        return expand_path(Path(self._install_path), self.home_directory)

    def _data_dir(self) -> Path:
        return expand_path(Path(self._data_path), self.home_directory)

    def _managed_config_dir(self) -> Path | None:
        """System-wide opencode config directory, or ``None`` on unsupported OSes."""
        if sys.platform == "darwin":
            return Path("/Library/Application Support/opencode")
        if sys.platform in ("linux", "linux2"):
            return Path("/etc/opencode")
        if sys.platform == "win32":
            program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
            return Path(program_data) / "opencode"
        return None

    def _opencode_config_env_path(self) -> Path | None:
        """Resolved ``$OPENCODE_CONFIG`` path on an own-home scan, else ``None``."""
        if not self._scans_own_home():
            return None
        override = os.environ.get("OPENCODE_CONFIG")
        if not override:
            return None
        return Path(override)

    # --- project enumeration (SQLite db) ---

    def _discover_project_folders(self) -> list[Path]:
        """Project paths from opencode's SQLite db (``project.worktree`` column).

        Opened with ``mode=ro&immutable=1`` so a concurrently-running opencode
        cannot block us on the WAL/SHM lock; any sqlite error (missing file,
        schema drift, permission denied) yields ``[]`` rather than aborting the
        whole discoverer.
        """
        db_path = self._data_dir() / self._db_filename
        try:
            if not db_path.exists():
                return []
        except (PermissionError, OSError):
            return []
        # ``immutable=1`` is what lets us co-exist with a live opencode: it tells
        # SQLite the file will not change, so no WAL/SHM is consulted and no lock
        # is taken. Safe for a read-only inspection.
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        try:
            con = sqlite3.connect(uri, uri=True)
            try:
                cur = con.execute("SELECT worktree FROM project WHERE worktree IS NOT NULL")
                rows = cur.fetchall()
            finally:
                con.close()
        except sqlite3.Error as e:
            logger.warning("Could not read opencode project table from %s: %s", db_path.as_posix(), e)
            return []
        return [Path(row[0]) for row in rows if isinstance(row[0], str) and row[0]]

    # --- MCP discovery ---

    def _scan_config_dir(self, base: Path) -> McpConfigsResult:
        """Try every ``_CONFIG_FILENAMES`` entry under ``base``; record any hits."""
        result: McpConfigsResult = {}
        for filename in _CONFIG_FILENAMES:
            path = base / filename
            # ``skip_unrecognized=True`` so a file lacking an ``mcp`` block (e.g.
            # an opencode config that only sets ``permission`` / ``theme``) is
            # skipped quietly rather than reported as malformed. The
            # ``_looks_like_mcp_payload`` gate covers wrapper-key detection.
            parsed = self._parse_mcp_file(path, formats=_OPENCODE_MCP_FORMATS, skip_unrecognized=True)
            if not parsed:
                continue
            result[path.as_posix()] = parsed
        return result

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        return self._scan_config_dir(self._global_config_dir())

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for project in self._project_paths_with_ancestors():
            result.update(self._scan_config_dir(project))
        return result

    def _discover_managed_mcp_servers(self) -> McpConfigsResult:
        managed_dir = self._managed_config_dir()
        if managed_dir is None:
            return {}
        return self._scan_config_dir(managed_dir)

    def _discover_env_override_mcp_servers(self) -> McpConfigsResult:
        path = self._opencode_config_env_path()
        if path is None:
            return {}
        # An explicitly-named config — do NOT use ``skip_unrecognized``: if the
        # user pointed ``$OPENCODE_CONFIG`` at a file that fails to parse, that's
        # a real signal worth surfacing rather than silently dropping.
        parsed = self._parse_mcp_file(path, formats=_OPENCODE_MCP_FORMATS)
        if not parsed:
            return {}
        return {path.as_posix(): parsed}

    # --- skills discovery ---

    def _discover_global_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        skills_dir = self._global_config_dir() / self._skills_subdir
        entries = self._scan_skills_dir(skills_dir)
        if entries is not None:
            result[skills_dir.as_posix()] = entries
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for project in self._project_paths_with_ancestors():
            for rel in self._project_skills_relative:
                skills_dir = project / rel
                entries = self._scan_skills_dir(skills_dir)
                if entries is not None:
                    result[skills_dir.as_posix()] = entries
        return result

    def _discover_managed_skills(self) -> SkillsDirsResult:
        managed_dir = self._managed_config_dir()
        if managed_dir is None:
            return {}
        result: SkillsDirsResult = {}
        skills_dir = managed_dir / self._skills_subdir
        entries = self._scan_skills_dir(skills_dir)
        if entries is not None:
            result[skills_dir.as_posix()] = entries
        return result
