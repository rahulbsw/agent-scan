import io
import re
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
    assert project["version"] == "0.2.0"
    assert "Open Agent Scan" in project["description"] or "Community-led" in project["description"]


def test_console_scripts_include_primary_command_and_legacy_alias():
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        scripts = tomllib.load(f)["project"]["scripts"]

    assert scripts["open-agent-scan"] == "agent_scan.run:run"
    assert scripts["agent-scan"] == "agent_scan.run:run"


def test_release_workflow_publishes_platform_archives():
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text()

    assert "archive_ext" in workflow
    assert (
        "open-agent-scan-${{ needs.prepare-release.outputs.release_tag }}-${{ matrix.target }}${{ matrix.archive_ext }}"
        in workflow
    )
    assert ".tar.gz" in workflow
    assert ".zip" in workflow
    assert "tar -czf" in workflow
    assert "zipfile.ZipFile" in workflow


def test_binary_build_collects_requests_charset_dependency():
    makefile = (REPO_ROOT / "Makefile").read_text()
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        project = tomllib.load(f)["project"]

    assert any(dependency.startswith("chardet") for dependency in project["dependencies"])
    assert "--hidden-import chardet" in makefile
    assert "--hidden-import charset_normalizer" in makefile
    assert "--collect-all charset_normalizer" in makefile


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


def test_install_examples_use_explicit_release_without_assuming_pypi_publication():
    readme = (REPO_ROOT / "README.md").read_text()
    assert (
        "https://github.com/rahulbsw/agent-scan/releases/download/v0.2.0/open_agent_scan-0.2.0-py3-none-any.whl"
        in readme
    )
    assert "uv tool install" in readme
    assert "uvx --from" in readme
    assert "Trusted Publisher does not publish" in " ".join(readme.split())
    # The publisher guide deliberately tests registry install after a verified upload.
    docs = [
        REPO_ROOT / "README.md",
        *(path for path in (REPO_ROOT / "docs").glob("*.md") if path.name != "pypi-publishing.md"),
    ]
    for path in docs:
        for block in re.findall(r"```[^\n]*\n(.*?)```", path.read_text(), flags=re.DOTALL):
            assert "uvx open-agent-scan@latest" not in block, path
