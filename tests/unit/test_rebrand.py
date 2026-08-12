import io
import sys
from pathlib import Path

from agent_scan.run import _maybe_warn_legacy_alias

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_project_metadata_uses_open_agent_scan_identity():
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        project = tomllib.load(f)["project"]

    assert project["name"] == "open-agent-scan"
    assert project["version"] == "0.1.0"
    assert "Open Agent Scan" in project["description"] or "Community-led" in project["description"]


def test_console_scripts_include_primary_command_and_legacy_alias():
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        scripts = tomllib.load(f)["project"]["scripts"]

    assert scripts["open-agent-scan"] == "agent_scan.run:run"
    assert scripts["agent-scan"] == "agent_scan.run:run"


def test_legacy_alias_warns_to_stderr(monkeypatch):
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)

    _maybe_warn_legacy_alias("agent-scan")

    assert "compatibility alias" in stderr.getvalue()
    assert "open-agent-scan" in stderr.getvalue()


def test_primary_command_does_not_warn(monkeypatch):
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)

    _maybe_warn_legacy_alias("open-agent-scan")

    assert stderr.getvalue() == ""
