# Open Agent Scan

For explicitly scoped scans without MCP execution or remote services, see the
experimental [passive skill scanner](docs/passive-skills.md):
`open-agent-scan skills ./my-skill --format json` (Linux/macOS).

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

Install the published GitHub Release wheel with `uv`:

```bash
uv tool install \
  "open-agent-scan @ https://github.com/rahulbsw/agent-scan/releases/download/v0.2.0/open_agent_scan-0.2.0-py3-none-any.whl"
open-agent-scan --help
```

GitHub Releases and PyPI are separate publication destinations. A Trusted
Publisher does not publish a package until its first upload succeeds. If plain
`uvx open-agent-scan@latest` reports that the package is missing, use the explicit
GitHub wheel above. After the version appears on PyPI, registry-only invocations
are available. See [Trusted Publishing](docs/pypi-publishing.md) for the workflow
and verification steps.
If `uv` reports that its tool bin directory is not on `PATH`, run
`uv tool update-shell` and start a new shell.

For a one-off invocation without a persistent tool install:

```bash
uvx --from \
  https://github.com/rahulbsw/agent-scan/releases/download/v0.2.0/open_agent_scan-0.2.0-py3-none-any.whl \
  open-agent-scan --help
```

Replace `--help` with `skills ./my-skill --format json` for an explicitly scoped
passive scan. Installation downloads Python dependencies; passive scanning does
not contact analysis services or execute MCP startup commands.

Scan specific MCP configs, skill files, or skill directories:

```bash
open-agent-scan ~/.vscode/mcp.json
open-agent-scan ~/path/to/my/SKILL.md
open-agent-scan ~/.claude/skills
```

The legacy `agent-scan` command remains as a temporary compatibility alias and
prints a deprecation notice to stderr. New docs and automation should use
`open-agent-scan`.

Standalone binaries are published from GitHub Releases as platform archives:
`open-agent-scan-<version>-<platform>.tar.gz` for macOS/Linux and
`open-agent-scan-<version>-windows-x64.zip` for Windows. Releases include
checksums, SBOMs, and build attestations.

Official CI and future binary releases target Linux x64/ARM64, Windows x64, and
macOS ARM64 (Apple Silicon). Intel macOS testing and official `macos-x64` binary
builds are retired starting with the next release. Existing release assets,
including v0.2.0's Intel macOS archive, remain available. Python/source installs
on Intel Macs are best-effort and untested; compatible Python and dependencies
are still required. The ARM64 macOS executable does not run natively on Intel.

On macOS, extract the archive and run the CLI from Terminal:

```bash
tar -xzf open-agent-scan-v0.2.0-macos-arm64.tar.gz
xattr -d com.apple.quarantine open-agent-scan 2>/dev/null || true
./open-agent-scan --help
```

## GitHub Actions

Scan repository skills, `AGENTS.md`, Claude/Copilot instructions, and Cursor
rules on pull requests without executing their code. Follow the
[GitHub Actions guide](docs/github-actions.md) and its
[copyable workflow](docs/examples/agent-security.yml). It includes pinned scanner
installation, coverage gates, JSON/HTML artifacts, an Actions job summary, and
optional Security-tab SARIF uploads; no Snyk token is required.

## Use With AI Tools

Install the [Open Agent Scan skill](skills/open-agent-scan/SKILL.md) into a
compatible AI coding tool with the skills CLI (requires Node.js/npm):

```bash
npx skills add rahulbsw/agent-scan --skill open-agent-scan
```

Select your tool in the installer, then ask it to scan a specific MCP config or
skill before adoption. For example: "Use open-agent-scan to review
./my-skill/SKILL.md and explain the findings."

The skill provides instructions; install the scanner separately using the
options above. Your AI tool needs shell access. The workflow keeps analysis local,
requires consent before starting MCP servers or contacting their endpoints, and
reports scan failures as coverage gaps.

Skills are distributed from this GitHub repository. After this change is merged,
the install command uses the default branch. The
[skills.sh directory](https://skills.sh/docs/faq) discovers and ranks skills
through installation telemetry; there is no separate package upload. Directory
appearance is controlled by skills.sh. To disable installer telemetry, set
`DISABLE_TELEMETRY=1`.

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

Local analysis can still contact configured MCP servers during discovery.
Upstream's newer discovery and hook-install safeguards are retained; remote
discovery configuration is queried only for explicitly configured push-key
analysis and is skipped with `--analysis-mode local`.

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
open-agent-scan scan \
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
