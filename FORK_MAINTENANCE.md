# Upstream Sync Guide

Open Agent Scan is an independent downstream derivative of
`snyk/agent-scan`. Keep upstream credit and license notices intact, but preserve
the community identity and local-first behavior during every sync.

## Remotes

- `origin`: upstream `https://github.com/snyk/agent-scan.git`
- `fork`: current downstream repository
- target public home: `https://github.com/open-agent-scan/open-agent-scan`

## Preserve During Sync

- Public project name: Open Agent Scan.
- Primary package and command: `open-agent-scan`.
- Temporary compatibility alias: `agent-scan`.
- No mandatory `SNYK_TOKEN`.
- No prompt directing users to `https://app.snyk.io/account`.
- Default analysis remains local and deterministic.
- Remote analysis requires explicit `--analysis-mode remote`,
  `--analysis-url`, and caller-provided authorization.
- Community contribution docs, DCO policy, governance docs, and rule proposal
  templates remain open.
- Release assets use `open-agent-scan-*` names.

## Sync Process

Use merge commits for upstream sync branches. Do not rewrite public downstream
history unless maintainers explicitly agree.

```bash
git fetch origin main
git fetch fork main
git switch -c sync/upstream-YYYYMMDD fork/main
git merge origin/main
```

Resolve conflicts according to the policy above. After verification, merge into
the downstream main branch and push:

```bash
git switch main
git merge --ff-only sync/upstream-YYYYMMDD
git push fork main
```

## Verification

```bash
uv run --extra test -m pytest tests/unit
uv run --extra test -m pytest --no-cov -q tests/e2e/test_scan.py tests/e2e/test_guard_install.py
uv run --extra dev ruff check src tests
```

Policy sweeps:

```bash
rg -n "SNYK_TOKEN|app\\.snyk\\.io/account|snyk-code-signing-public" README.md docs src tests
rg -n "Agent Scan is closed to contributions|closed to external contributions" README.md docs CONTRIBUTING.md
rg -n "agent-scan-\\$\\{|agent-scan-" .github/workflows Makefile README.md docs
```

Expected result: no public docs or release workflows should reintroduce the
upstream product flow. Internal legacy compatibility code may still contain
`agent-scan` where required.

## Releases

Use standard Open Agent Scan tags:

```bash
git tag v0.1.0
git push fork v0.1.0
```

Release notes must state the upstream base version or commit when relevant.
