"""
Install/uninstall the MCP stdio shim into discovered client configs.

The shim wraps each stdio server's command so that the JSON-RPC response
containing tool definitions is captured to a file in /tmp.  The scanner
can later read those files to obtain tool signatures without starting
the servers itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from importlib.resources import files as _resource_files
from pathlib import Path

import pyjson5
from mcp.types import (
    InitializeResult,
    Prompt,
    Resource,
    ResourceTemplate,
    Tool,
)

from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import ServerSignature, StdioServer

logger = logging.getLogger(__name__)

SHIM_MARKER = "snyk_mcp_stdio_local_proxy"
WRAPPER_SENTINEL = "snyk_mcp_stdio_local_proxy_wrapper"
RUNTIME_CONFIG_SHIM_FLAG = "enable-local-stdio-proxy"
# Suffixes used for the materialized shim itself. read_signatures() must
# exclude these so the shim file isn't mistaken for a capture log.
_SHIM_FILE_SUFFIXES = (".sh", ".cmd")

_SHIM_RESOURCE_UNIX = "snyk_mcp_stdio_local_proxy.sh"
_SHIM_RESOURCE_WINDOWS = "snyk_mcp_stdio_local_proxy.cmd"


def _shim_resource_name() -> str:
    return _SHIM_RESOURCE_WINDOWS if sys.platform == "win32" else _SHIM_RESOURCE_UNIX


def _shim_target_suffix() -> str:
    return ".cmd" if sys.platform == "win32" else ".sh"


def _read_shim_source_bytes() -> bytes | None:
    """Read the bundled shim script bytes from the package."""
    try:
        return _resource_files("agent_scan").joinpath(_shim_resource_name()).read_bytes()
    except Exception:
        logger.warning("Failed to read bundled shim script %s", _shim_resource_name(), exc_info=True)
        return None


def _get_shim_target_dir() -> Path:
    """Directory the shim is installed into. Hardcoded per-platform."""
    if sys.platform == "win32":
        return Path(os.environ.get("PUBLIC") or r"C:\Users\Public")
    return Path("/tmp")


def _smoke_test_shim(target: Path) -> bool:
    """Exec smoke test: run the shim with no stdin and a short timeout.

    Any capture artifact written by the shim during this no-op invocation
    is removed afterwards so the smoke test does not pollute the log dir.
    """
    log_dir = _get_shim_log_dir()
    before = {p for p in log_dir.glob(f"{SHIM_MARKER}.*") if p.suffix not in _SHIM_FILE_SUFFIXES}
    try:
        subprocess.run(
            [str(target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return True
    except Exception:
        logger.warning("Shim smoke test failed for %s", target, exc_info=True)
        return False
    finally:
        for stray in log_dir.glob(f"{SHIM_MARKER}.*"):
            if stray.suffix in _SHIM_FILE_SUFFIXES or stray in before:
                continue
            with contextlib.suppress(OSError):
                stray.unlink()


def _get_shim_path() -> Path | None:
    """
    Materialize the bundled shim at a content-addressed, multi-user-readable
    location and return its path.  Returns None if the contract (machine-wide
    read+execute, owner-only modify/delete, no elevation) can't be satisfied.

    Callers must treat None as a directive to skip installation and clean up
    any existing shim wrapping in the target config.
    """
    source = _read_shim_source_bytes()
    if source is None:
        return None

    digest = hashlib.sha256(source).hexdigest()[:12]
    target_dir = _get_shim_target_dir()
    if not target_dir.exists() or not os.access(target_dir, os.W_OK):
        logger.warning("Shim target dir %s missing or not writable", target_dir)
        return None

    target = target_dir / f"{SHIM_MARKER}.{digest}{_shim_target_suffix()}"

    if target.exists():
        try:
            existing = target.read_bytes()
        except OSError:
            logger.warning("Failed to read existing shim at %s", target, exc_info=True)
            return None
        if existing != source:
            logger.warning(
                "Shim target %s exists with content that does not match bundled source — refusing to install",
                target,
            )
            return None
    else:
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=f"{SHIM_MARKER}.", suffix=_shim_target_suffix(), dir=str(target_dir))
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(source)
            except Exception:
                with contextlib.suppress(OSError):
                    os.close(fd)
                raise
            if sys.platform != "win32":
                os.chmod(tmp_name, 0o755)
            os.replace(tmp_name, target)
            tmp_name = None
        except OSError:
            logger.warning("Failed to write shim to %s", target, exc_info=True)
            if tmp_name is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
            return None

    if not os.access(target, os.X_OK):
        logger.warning("Shim at %s is not executable (X_OK denied)", target)
        return None

    if not _smoke_test_shim(target):
        return None

    return target


def _is_shimmed_raw(server: dict) -> bool:
    """True if the server is wrapped by our shim, either form (legacy
    direct-exec or the conditional sh/cmd wrapper)."""
    if SHIM_MARKER in server.get("command", ""):
        return True
    return any(isinstance(a, str) and SHIM_MARKER in a for a in server.get("args", []) or [])


def _unwrap_shimmed(server: dict) -> tuple[str, list[str]] | None:
    """Extract (original_command, original_args) from a shimmed entry.

    Handles both forms produced by past and current versions:
      * Legacy direct-exec: ``command=<shim_path>``, ``args=[orig_cmd, *orig_args]``
      * Conditional Unix:   ``command="/bin/sh"``,
                            ``args=["-c", <script>, <sentinel>, orig_cmd, *orig_args]``
      * Conditional Windows: ``command="cmd"``,
                            ``args=["/d","/s","/c", <script>, orig_cmd, *orig_args]``
    Returns None if the entry is not recognised as shimmed.
    """
    if not _is_shimmed_raw(server):
        return None

    command = server.get("command", "")
    args = list(server.get("args", []) or [])

    # Conditional Unix wrapper
    if (
        command in ("/bin/sh", "sh")
        and len(args) >= 4
        and args[0] == "-c"
        and isinstance(args[1], str)
        and SHIM_MARKER in args[1]
        and args[2] == WRAPPER_SENTINEL
    ):
        return args[3], args[4:]

    # Conditional Windows wrapper
    if (
        command.lower() in ("cmd", "cmd.exe")
        and len(args) >= 5
        and args[:3] == ["/d", "/s", "/c"]
        and isinstance(args[3], str)
        and SHIM_MARKER in args[3]
    ):
        return args[4], args[5:]

    # Legacy direct-exec wrapper
    if SHIM_MARKER in command and args:
        return args[0], args[1:]

    return None


def _wrap_command(shim_path: str, original_command: str, original_args: list[str]) -> tuple[str, list[str]]:
    """Build the (command, args) pair that wraps the original invocation in a
    conditional that falls through to the original command when the shim file
    is missing."""
    if sys.platform == "win32":
        script = f'if exist "{shim_path}" ("{shim_path}" %*) else (%*)'
        return "cmd", ["/d", "/s", "/c", script, original_command, *original_args]
    script = f'P={shim_path}; if [ -x "$P" ]; then exec "$P" "$@"; else exec "$@"; fi'
    return "/bin/sh", ["-c", script, WRAPPER_SENTINEL, original_command, *original_args]


def compute_server_hash(server: StdioServer) -> str:
    """Compute the same hash the shim uses: printf '%s\\0' arg1 arg2 ... | sha256"""
    parts = [server.command, *server.args]
    blob = b"".join(p.encode() + b"\x00" for p in parts)
    return hashlib.sha256(blob).hexdigest()[:12]


async def _get_stdio_server_names(config_path: str) -> set[str]:
    """Use the project's config parser to find which servers are stdio."""
    try:
        mcp_config = await scan_mcp_config_file(config_path)
        return {name for name, server in mcp_config.get_servers().items() if isinstance(server, StdioServer)}
    except Exception:
        logger.exception("Failed to parse config via scan_mcp_config_file: %s", config_path)
        return set()


def _resolve_servers(config: dict) -> dict | None:
    """Walk into config and return the raw servers dict."""
    for key_path in [["mcpServers"], ["servers"], ["mcp", "servers"]]:
        node: dict | None = config
        for key in key_path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                node = None
                break
        if isinstance(node, dict) and node:
            return node

    projects = config.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict) and "mcpServers" in proj:
                return proj["mcpServers"]

    return None


async def install_shim_into_config(config_path: str) -> list[str]:
    """
    Install the shim into a single config file.

    Wraps each stdio server's ``command`` + ``args`` in an inline shell
    conditional that exec's the shim when it exists and falls through to
    the original command otherwise. The shim disappearing from /tmp is a
    silent no-op at runtime — the server keeps working without capture.

    Returns the list of server names that were (re)shimmed.

    If the shim cannot be materialized (``_get_shim_path()`` returns
    ``None``), this acts as a cleanup directive: any existing shim wrapping
    in ``config_path`` is removed and an empty list is returned.
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        logger.warning("Config file not found: %s", path)
        return []

    shim_script = _get_shim_path()
    if shim_script is None:
        # Can't install. Make sure we don't leave a stale shim in this config.
        return await uninstall_shim_from_config(config_path)
    shim_path = str(shim_script.resolve())

    stdio_names = await _get_stdio_server_names(config_path)
    if not stdio_names:
        return []

    try:
        raw = path.read_text(encoding="utf-8")
        config = pyjson5.loads(raw) if raw.strip() else {}
    except Exception:
        logger.exception("Failed to parse config: %s", path)
        return []

    servers = _resolve_servers(config)
    if not servers:
        return []

    shimmed: list[str] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        if name not in stdio_names:
            continue

        existing = _unwrap_shimmed(server)
        if existing is not None:
            orig_command, orig_args = existing
        else:
            orig_command = server.get("command", "")
            orig_args = list(server.get("args", []) or [])

        new_command, new_args = _wrap_command(shim_path, orig_command, orig_args)
        if server.get("command") == new_command and list(server.get("args", []) or []) == new_args:
            # Already in target form with the current shim path — no rewrite needed.
            continue

        server["command"] = new_command
        server["args"] = new_args
        shimmed.append(name)

    if not shimmed:
        return []

    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return shimmed


async def uninstall_shim_from_config(config_path: str) -> list[str]:
    """
    Remove the shim from a single config file.
    Returns a list of server names that were unshimmed.
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        return []

    try:
        raw = path.read_text(encoding="utf-8")
        config = pyjson5.loads(raw) if raw.strip() else {}
    except Exception:
        logger.exception("Failed to parse config: %s", path)
        return []

    servers = _resolve_servers(config)
    if not servers:
        return []

    unshimmed: list[str] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        unwrapped = _unwrap_shimmed(server)
        if unwrapped is None:
            continue
        orig_command, orig_args = unwrapped
        server["command"] = orig_command
        server["args"] = orig_args
        unshimmed.append(name)

    if not unshimmed:
        return []

    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return unshimmed


def _get_shim_log_dir() -> Path:
    if sys.platform == "win32":
        return Path(tempfile.gettempdir())
    return Path("/tmp")


class ServerCapture:
    """Captured capabilities for a single server."""

    def __init__(self) -> None:
        self.metadata: dict | None = None
        self.tools: list[dict] = []
        self.prompts: list[dict] = []
        self.resources: list[dict] = []
        self.resource_templates: list[dict] = []


def read_signatures() -> dict[str, ServerCapture]:
    """
    Read captured signatures from shim log files.
    Returns a dict mapping server hash -> ServerCapture.
    """
    tmp = _get_shim_log_dir()
    # Exclude the materialized shim itself, which now lives alongside the
    # captures at /tmp/snyk_mcp_stdio_local_proxy.<hash>.sh (or .cmd).
    log_files = [f for f in tmp.glob(f"{SHIM_MARKER}.*") if f.suffix not in _SHIM_FILE_SUFFIXES]

    if not log_files:
        return {}

    by_hash: dict[str, list[Path]] = {}
    for f in log_files:
        parts = f.name.split(".")
        if len(parts) >= 3:
            by_hash.setdefault(parts[1], []).append(f)

    results: dict[str, ServerCapture] = {}
    for h, files in by_hash.items():
        best = max(files, key=lambda p: (p.stat().st_size, p.stat().st_mtime))
        capture = ServerCapture()
        content = best.read_text().strip()
        if content:
            for line in content.splitlines():
                try:
                    data = json.loads(line)
                    result = data.get("result", data)
                    if "serverInfo" in result:
                        capture.metadata = result
                    if "tools" in result:
                        capture.tools = result["tools"]
                    if "prompts" in result:
                        capture.prompts = result["prompts"]
                    if "resources" in result:
                        capture.resources = result["resources"]
                    if "resourceTemplates" in result:
                        capture.resource_templates = result["resourceTemplates"]
                except json.JSONDecodeError:
                    pass
        results[h] = capture

    return results


def _capture_to_signature(capture: ServerCapture) -> ServerSignature | None:
    """Convert a shim capture to a ServerSignature, or None if empty."""
    if not capture.metadata:
        return None
    if not capture.tools and not capture.prompts and not capture.resources and not capture.resource_templates:
        return None

    metadata = InitializeResult.model_validate(capture.metadata)

    return ServerSignature(
        metadata=metadata,
        tools=[Tool.model_validate(t) for t in capture.tools],
        prompts=[Prompt.model_validate(p) for p in capture.prompts],
        resources=[Resource.model_validate(r) for r in capture.resources],
        resource_templates=[ResourceTemplate.model_validate(rt) for rt in capture.resource_templates],
    )


def get_signature_for_server(server: StdioServer) -> ServerSignature | None:
    """
    Look up a cached shim signature for a StdioServer.
    Returns a ServerSignature if found and non-empty, else None.
    """
    server_dict = {"command": server.command, "args": list(server.args)}
    unwrapped = _unwrap_shimmed(server_dict)
    if unwrapped is not None:
        orig_command, orig_args = unwrapped
        parts = [orig_command, *orig_args]
    else:
        parts = [server.command, *server.args]

    blob = b"".join(p.encode() + b"\x00" for p in parts)
    h = hashlib.sha256(blob).hexdigest()[:12]

    captures = read_signatures()
    capture = captures.get(h)
    if capture is None:
        return None
    return _capture_to_signature(capture)
