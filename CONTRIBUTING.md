# Contributing To Open Agent Scan

Open Agent Scan accepts external contributions from security researchers,
defenders, MCP implementers, agent builders, and maintainers.

## Contribution Requirements

- Contributions are licensed under Apache-2.0, matching the repository license.
- Every commit must include a DCO sign-off:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add this automatically.

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Do not include real credentials, private customer data, exploit payloads that
  phone home, or third-party content without permission.
- Security vulnerabilities in Open Agent Scan itself should be reported through
  [SECURITY.md](SECURITY.md), not public issues.

## What Makes A Good Rule Contribution

Rule changes must be deterministic, evidence-backed, and performance-conscious.
Include:

- a clear threat model and source reference;
- rule metadata in the local rule registry;
- positive and negative fixtures;
- expected issue code, severity, confidence, and evidence;
- a short false-positive rationale;
- docs updates in [docs/issue-codes.md](docs/issue-codes.md) when adding a new
  issue code.

See [docs/rule-authoring.md](docs/rule-authoring.md).

## Local Development

```bash
uv sync --all-extras
uv run open-agent-scan --help
uv run open-agent-scan scan --no-skills
```

Recommended checks:

```bash
uv run --extra test -m pytest tests/unit
uv run --extra test -m pytest --no-cov -q tests/e2e/test_scan.py tests/e2e/test_guard_install.py
uv run --extra dev ruff check src tests
```

## Pull Request Expectations

- Keep changes focused.
- Explain user impact and security rationale.
- Include tests for behavior changes.
- Update docs for public CLI, JSON output, rule IDs, governance, or release
  behavior.
- Mark speculative or low-confidence detection ideas as proposals before
  implementing them.

Maintainers may ask for rule precision improvements before merging. That is
expected for security scanning: noisy rules reduce trust in the tool.
