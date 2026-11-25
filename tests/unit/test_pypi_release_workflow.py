import hashlib
import io
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def validation_script():
    step = next(
        step for step in workflow()["jobs"]["publish-pypi"]["steps"] if step["name"].startswith("Verify distribution")
    )
    return step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


def distributions(tmp_path, *, name="open-agent-scan", version="0.2.0"):
    directory = tmp_path / "dist"
    directory.mkdir()
    metadata = f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n\n".encode()
    wheel = directory / "open_agent_scan-0.2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("open_agent_scan-0.2.0.dist-info/METADATA", metadata)
    source = directory / "open_agent_scan-0.2.0.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        item = tarfile.TarInfo("open_agent_scan-0.2.0/PKG-INFO")
        item.size = len(metadata)
        archive.addfile(item, io.BytesIO(metadata))
    checksums = tmp_path / "release-metadata"
    checksums.mkdir()
    (checksums / "sha256sums.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in (wheel, source))
    )
    return wheel, source


def validate(path, tag="v0.2.0"):
    return subprocess.run(
        [sys.executable, "-c", validation_script()],
        cwd=path,
        env={**os.environ, "RELEASE_TAG": tag},
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_pypi_publisher_is_isolated_and_tokenless():
    config = workflow()
    assert config["permissions"] == {"contents": "read"}
    publisher = config["jobs"]["publish-pypi"]
    assert publisher["permissions"] == {"contents": "read", "id-token": "write"}
    assert publisher["environment"]["name"] == "pypi"
    assert "github.repository == 'rahulbsw/agent-scan'" in publisher["if"]
    assert "github.ref == 'refs/heads/main'" in publisher["if"]
    assert "needs.publish-release.result == 'success'" in publisher["if"]
    assert not any("checkout@" in step.get("uses", "") for step in publisher["steps"])
    publish = publisher["steps"][-1]
    assert publish["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert len(publish["uses"].split("@")[-1]) == 40
    assert publish["with"]["attestations"] is True
    assert not {"username", "password"} & publish["with"].keys()
    assert "OPEN_AGENT_SCAN_PYPI_TOKEN" not in WORKFLOW.read_text()
    assert publisher["concurrency"]["cancel-in-progress"] is False


def test_existing_release_can_be_published_without_rebuilding():
    config = workflow()
    events = config.get("on", config.get(True))
    assert events["workflow_dispatch"]["inputs"]["pypi_only"]["type"] == "boolean"
    assert events["workflow_dispatch"]["inputs"]["pypi_only"]["default"] is False
    for job in ("build-binaries", "build-python-package"):
        assert "!inputs.pypi_only" in config["jobs"][job]["if"]
    publisher = config["jobs"]["publish-pypi"]
    assert "inputs.pypi_only" in publisher["if"]
    assert "!cancelled()" in publisher["if"]
    download = publisher["steps"][0]["run"]
    assert "gh release download" in download
    assert "sha256sums.txt" in download
    assert "--dir dist" in download


def test_valid_release_distributions_are_accepted(tmp_path):
    distributions(tmp_path)
    result = validate(tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name,version", [("another-project", "0.2.0"), ("open-agent-scan", "9.9.9")])
def test_wrong_distribution_identity_is_rejected(tmp_path, name, version):
    distributions(tmp_path, name=name, version=version)
    result = validate(tmp_path)
    assert result.returncode != 0
    assert "Package name/version" in result.stderr


def test_tag_and_artifact_version_must_agree(tmp_path):
    distributions(tmp_path)
    assert validate(tmp_path, tag="v0.2.1").returncode != 0


def test_tampered_distribution_is_rejected(tmp_path):
    wheel, _ = distributions(tmp_path)
    with wheel.open("ab") as stream:
        stream.write(b"tampered")
    result = validate(tmp_path)
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr


def test_extraneous_uploads_are_rejected(tmp_path):
    distributions(tmp_path)
    (tmp_path / "dist/checksums.txt").write_text("not a distribution")
    assert validate(tmp_path).returncode != 0


def test_duplicate_checksum_entries_are_rejected(tmp_path):
    distributions(tmp_path)
    path = tmp_path / "release-metadata/sha256sums.txt"
    with path.open("a") as stream:
        stream.write(path.read_text().splitlines()[0] + "\n")
    result = validate(tmp_path)
    assert result.returncode != 0
    assert "Duplicate checksum" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="Release workflow shell runs on Ubuntu")
def test_release_shell_steps_parse():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True)


@pytest.mark.skipif(os.name == "nt", reason="Release workflow shell runs on Ubuntu")
@pytest.mark.parametrize(
    "tag,accepted",
    [
        ("v0.2.0", True),
        ("v0.2.1rc1", True),
        ("main", False),
        ("v0.2.0\nother=value", False),
        ("v0.2.0;echo bad", False),
        ("v0.2.0/extra", False),
    ],
)
def test_release_tag_validation_prevents_output_injection(tmp_path, tag, accepted):
    script = workflow()["jobs"]["prepare-release"]["steps"][0]["run"]
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash"],
        input=script,
        text=True,
        capture_output=True,
        env={**os.environ, "RAW_TAG": tag, "GITHUB_OUTPUT": str(output)},
    )
    assert (result.returncode == 0) is accepted
    if accepted:
        assert output.read_text().splitlines() == [f"checkout_ref={tag}", f"release_tag={tag}"]
    else:
        assert not output.exists()
