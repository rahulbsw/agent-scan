# Fork Maintenance

This fork is maintained as an independent downstream because upstream
`snyk/agent-scan` is closed to external contributions.

## Remotes

- `origin`: upstream `https://github.com/snyk/agent-scan.git`
- `fork`: maintained fork `https://github.com/rahulbsw/agent-scan.git`

Treat `fork/main` as the canonical branch for this fork. Do not open routine
fork-policy changes as pull requests against upstream.

## Fork Policy

Preserve these decisions during every upstream sync:

- Keep package and command naming as `agent-scan`.
- Do not require `SNYK_TOKEN`.
- Do not prompt users to visit `https://app.snyk.io/account`.
- Keep local analysis as the default behavior.
- Keep remote analysis explicit through `--analysis-mode remote`,
  `--analysis-url`, and caller-provided authorization headers.
- Keep guard hook installation based on a pre-provisioned `--push-key` or
  `PUSH_KEY`; do not mint push keys interactively from a Snyk account token.
- Do not add Snyk release-signing docs or keys unless this fork adds its own
  signing process.
- Do not reintroduce removed bootstrap/upload/runtime-config plumbing unless it
  is reworked to be service-neutral.

## Sync From Upstream

Use merge commits for upstream syncs. Public fork branches should not be rebased.

```bash
git fetch origin main
git fetch fork main
git switch -c sync/upstream-YYYYMMDD fork/main
git merge origin/main
```

Resolve conflicts according to the fork policy above. After verification,
merge the sync branch into `main` and push to the fork:

```bash
git switch main
git merge --ff-only sync/upstream-YYYYMMDD
git push fork main
```

If `--ff-only` fails, inspect the branch graph before choosing a normal merge.
Do not force-push `fork/main` unless the team explicitly agrees to rewrite fork
history.

## Verification

Run these checks after conflict resolution:

```bash
uv run --extra test -m pytest tests/unit
uv run --extra test -m pytest --no-cov -q tests/e2e/test_scan.py tests/e2e/test_guard_install.py
uv run --extra dev ruff check src tests
```

When full `ruff check src tests` is blocked by unrelated upstream fixture or
sample-code lint, run a scoped ruff check over changed Python files and document
the known unrelated failures in the commit or release notes.

Run these policy sweeps before committing:

```bash
rg -n "SNYK_TOKEN|app\\.snyk\\.io/account|snyk-code-signing-public|Verifying Standalone Binaries" README.md docs src tests
rg -n "bootstrap_runtime_config|from agent_scan\\.bootstrap|from agent_scan\\.runtime_config|from agent_scan\\.upload|upload\\(" src tests README.md docs
```

Expected result: no matches, except service-neutral helper code that is
intentionally retained and covered by tests.

## Release Tags

Use fork-specific tags so upstream version tracking remains clear:

```bash
git tag fork-v0.5.14.1
git push fork fork-v0.5.14.1
```

Format: `fork-v<upstream-version>.<fork-patch>`.

Pushing a `fork-v*` tag runs the fork release workflow and publishes GitHub
Release assets for Linux x64, Linux arm64, macOS arm64, macOS x64, and Windows
x64, plus the Python wheel/source distribution and `sha256sums.txt`.

```bash
git tag fork-v0.5.14.1
git push fork fork-v0.5.14.1
```

To rebuild assets for an existing tag, run the `Fork Release` workflow manually
with the same tag. The workflow overwrites existing release assets for that tag.
