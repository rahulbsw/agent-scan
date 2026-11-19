import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.mark.skipif(sys.platform == "win32", reason="DCO runs in Bash on an Ubuntu runner, not Windows WSL")
def test_dco_accepts_only_unmodified_base_branch_updates(tmp_path):
    workflow = Path(__file__).parents[2] / ".github/workflows/dco.yml"
    script = yaml.safe_load(workflow.read_text())["jobs"]["signoff"]["steps"][1]["run"]

    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    def commit(message, filename):
        (tmp_path / filename).write_text(message)
        git("add", filename)
        git("commit", "-qm", message)
        return git("rev-parse", "HEAD")

    git("init", "-q")
    git("config", "user.name", "DCO Test")
    git("config", "user.email", "dco@example.test")
    git("config", "commit.gpgsign", "false")
    root = commit("base", "base.txt")
    git("checkout", "-qb", "base-update")
    base = commit("base change", "base-update.txt")
    git("checkout", "-qb", "contribution", root)
    commit("feature\n\nSigned-off-by: DCO Test <dco@example.test>", "feature.txt")
    git("merge", "--no-ff", "-m", "Update branch", base)

    def check(expected, base_sha=base):
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=tmp_path,
            env={**os.environ, "BASE_SHA": base_sha, "HEAD_SHA": git("rev-parse", "HEAD"), "HEAD_REF": "feature"},
            capture_output=True,
            text=True,
        )
        assert result.returncode == expected, result.stdout + result.stderr

    check(0)
    check(1, root)  # A merge from outside the PR base must still be signed.
    (tmp_path / "manual.txt").write_text("manual merge edit")
    git("add", "manual.txt")
    git("commit", "--amend", "--no-edit")
    check(1)
