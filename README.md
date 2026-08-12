# Open Agent Scan

Open Agent Scan is a community-led, local-first security scanner for AI agents,
MCP servers, and agent skills. It discovers installed agent components and
flags high-confidence risks such as prompt injection, tool poisoning, hidden
Unicode, suspicious startup commands, hardcoded secrets, untrusted content
exposure, and destructive capabilities.

Open Agent Scan is an independent downstream derivative of
[`snyk/agent-scan`](https://github.com/snyk/agent-scan). It is not affiliated
with, sponsored by, or endorsed by Snyk or Invariant Labs. Upstream credit and
Apache-2.0 attribution are preserved in [NOTICE](NOTICE) and
[ATTRIBUTION.md](ATTRIBUTION.md).

> **Experimental output**
>
> CLI output, JSON fields, issue codes, severity labels, and rule metadata are
> experimental and may change between releases. Avoid building production
> workflows that depend on undocumented fields.

## Why This Project Exists

Upstream `agent-scan` is developed in public but closed to external
contributions. Open Agent Scan keeps the useful local scanner base while opening
the project to security researchers, MCP implementers, agent builders, and
defenders who want to improve agent security scanning in the open.

The default analysis path is deterministic and local. No account, API token, or
remote analysis service is required.

## Install And Run

Run from PyPI with `uvx`:

```bash
uvx open-agent-scan@latest
```

Scan specific MCP configs, skill files, or skill directories:

```bash
uvx open-agent-scan@latest ~/.vscode/mcp.json
uvx open-agent-scan@latest ~/path/to/my/SKILL.md
uvx open-agent-scan@latest ~/.claude/skills
```

The legacy `agent-scan` command remains as a temporary compatibility alias and
prints a deprecation notice to stderr. New docs and automation should use
`open-agent-scan`.

Standalone binaries are published from GitHub Releases as platform archives:
`open-agent-scan-<version>-<platform>.tar.gz` for macOS/Linux and
`open-agent-scan-<version>-windows-x64.zip` for Windows. Releases include
checksums, SBOMs, and build attestations.

On macOS, extract the archive and run the CLI from Terminal:

```bash
tar -xzf open-agent-scan-v0.1.2-macos-arm64.tar.gz
xattr -d com.apple.quarantine open-agent-scan 2>/dev/null || true
./open-agent-scan --help
```

## Security Warning

Scanning stdio MCP configurations can execute the commands defined in those
configs. This is required to retrieve live tool, prompt, and resource metadata.

Recommended practice:

- Run scans in a sandbox, disposable VM, or container when evaluating untrusted
  MCP configs.
- Review the consent prompt before allowing any stdio MCP server to start.
- Use `--dangerously-run-mcp-servers` only in trusted CI or managed
  environments.
- Prefer `--analysis-mode local` unless you intentionally configured a remote
  analysis endpoint.

## What It Detects

Open Agent Scan currently covers:

- Agent and MCP discovery for Claude, Cursor, Windsurf, Gemini CLI, VS Code,
  Codex, Amazon Q, OpenCode, Kiro, Antigravity, and related clients.
- MCP server risks: prompt injection, suspicious tool descriptions, cross-server
  influence, toxic-flow labels, sensitive data exposure, public sinks,
  destructive capabilities, suspicious startup commands, and hidden content.
- Skill risks: prompt injection indicators, malware-like payloads, hardcoded or
  redacted secrets, unverifiable external dependencies, untrusted content
  exposure, and hidden Unicode.
- CI behavior: JSON output and `--ci` exit codes for automated policy checks.

See [docs/issue-codes.md](docs/issue-codes.md) for the finding reference and
[docs/security-research-map.md](docs/security-research-map.md) for the mapping
to OWASP, MCP, NIST, and OpenSSF guidance.

## Local-First Analysis

Open Agent Scan uses local deterministic rules by default. Rule contributions
must include:

- metadata with severity, confidence, references, and false-positive guidance;
- positive and negative fixtures;
- evidence in `Issue.extra_data`;
- performance-conscious matching;
- no default LLM or remote network dependency.

Remote analysis remains an explicit opt-in:

```bash
uvx open-agent-scan@latest scan \
  --analysis-mode remote \
  --analysis-provider remote \
  --analysis-url "https://analysis.example/scan" \
  --verification-H "Authorization: Bearer token"
```

The legacy `--analysis-provider snyk` value is accepted as a compatibility alias
for `remote`, but should not be used in new workflows.

## CLI Examples

```bash
# Scan all known MCP configs and agent skills
open-agent-scan

# Scan MCP only
open-agent-scan --no-skills

# Inspect tools without analysis
open-agent-scan inspect

# JSON output
open-agent-scan --json ~/.claude/skills

# CI mode
open-agent-scan --ci --dangerously-run-mcp-servers --json

# Managed hook install with a pre-provisioned push key
PUSH_KEY=... open-agent-scan guard install all --url "https://hooks.example"
```

For the full command reference, see [docs/cli-reference.md](docs/cli-reference.md).

## Development

```bash
uv sync --all-extras
uv run open-agent-scan --help
uv run open-agent-scan scan --no-skills
```

Run checks:

```bash
uv run --extra test -m pytest tests/unit
uv run --extra test -m pytest --no-cov -q tests/e2e/test_scan.py tests/e2e/test_guard_install.py
uv run --extra dev ruff check src tests
```

Build artifacts:

```bash
make build      # wheel and source distribution in dist/
make binary     # standalone binary in dist/
make shiv       # zipapp at dist/open-agent-scan.pyz
```

## Contributing

External contributions are welcome. Start with:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [GOVERNANCE.md](GOVERNANCE.md)
- [docs/rule-authoring.md](docs/rule-authoring.md)
- [ROADMAP.md](ROADMAP.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Contributions use Apache-2.0 inbound equals outbound with DCO sign-off. Use
`git commit -s` or otherwise include `Signed-off-by: Name <email>` in every
commit.

## Security Reports

Please do not open public issues for suspected vulnerabilities in the scanner.
Use GitHub Security Advisories as described in [SECURITY.md](SECURITY.md).

## Standards And References

- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/2025-03-26/index)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [OpenSSF Scorecard](https://openssf.org/scorecard/)
- [SPDX](https://spdx.dev/about/overview/)
