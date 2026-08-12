# Open Agent Scan CLI Reference

Complete reference for the `open-agent-scan` command-line interface.

Open Agent Scan runs local analysis by default. Remote analysis and hook uploads are explicit opt-ins configured with URLs, headers, and pre-provisioned push keys.

Unless noted, flags apply to the standalone CLI. When no subcommand is given, `scan` is assumed.

> **Experimental output.** Issue codes, JSON field names, and human-readable output may change between releases. See the [project README](../README.md) for the stability notice.

---

## Commands

| Command | Description |
| --- | --- |
| `scan` | Scan MCP configs, agents, and skills for security issues (default) |
| `inspect` | List tools, prompts, and resources without running security analysis |
| `help` | Print top-level help |
| `guard` | Install, uninstall, or show status of Agent Guard hooks |

### Positional Arguments

Most scan-like commands accept optional config paths:

```bash
open-agent-scan [scan] [CONFIG_FILE ...]
open-agent-scan inspect [CONFIG_FILE ...]
```

| Argument | Applies to | Description |
| --- | --- | --- |
| `CONFIG_FILE ...` | `scan`, `inspect` | One or more MCP config files, `SKILL.md` files, or directories to scan. If omitted, well-known agent config locations on the machine are discovered automatically. |

---

## Global Options

These flags are shared by `scan` and `inspect`.

### Output And Logging

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--json` | boolean | `false` | Emit results as JSON on stdout instead of rich text. Non-JSON status lines are suppressed during the scan. See [JSON output](json-output.md). |
| `--verbose` | boolean | `false` | Enable debug logging to stderr. |
| `--print-errors` | boolean | `false` | Show error details and tracebacks in the human-readable report. |
| `--print-full-descriptions` | boolean | `false` | Show full tool and skill descriptions in output. |

### Discovery And Scope

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--storage-file FILE` | string | `~/.open-agent-scan` | Path for local scan state and cached results. |
| `--no-skills` | boolean | off | Scan MCP servers only. Skills are included by default on every scan and inspect invocation. |
| `--skills` | boolean | on | Deprecated compatibility flag. Prefer omitting it; use `--no-skills` to opt out. |
| `--scan-all-users` | boolean | `false` | Scan all readable user home directories on the machine, not just the current user. |

### Analysis

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--analysis-mode MODE` | `auto`, `local`, `remote` | `auto` | Choose local analysis, remote analysis, or auto. In this fork, `auto` is local unless a push key or remote provider is configured. |
| `--analysis-url URL` | string | empty | Remote analysis endpoint. Used only with `--analysis-mode remote` or an explicit remote provider. |
| `--analysis-provider PROVIDER` | `local`, `remote` | `local` | Provider selection used with analysis mode. The legacy `snyk` value is accepted as an alias for `remote` for one migration window. |
| `--verification-H HEADER` | repeatable | - | Extra HTTP header for the remote analysis request. Format: `Name: value`. |
| `--skip-ssl-verify` | boolean | `false` | Disable TLS certificate verification for remote analysis and upload HTTP calls. |
| `--mcp-oauth-tokens-path PATH` | string | - | JSON file containing MCP OAuth tokens used when connecting to OAuth-protected remote MCP servers. |

---

## Control Server Upload

`scan` and `inspect` accept optional control-server metadata for managed runs. This is service-neutral and only runs when explicitly configured.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--control-server URL` | repeatable | - | Upload destination URL. Each block must include a matching `--control-identifier`. |
| `--control-server-H HEADER` | repeatable | - | HTTP header for the current `--control-server` block. Repeat within a block for multiple headers. |
| `--control-identifier ID` | repeatable | - | Non-anonymous machine identifier for the current `--control-server` block, such as email, hostname, or serial number. |

Options after a `--control-server` apply only to that server until the next `--control-server`:

```bash
open-agent-scan scan \
  --control-server https://server1.example/push \
  --control-server-H "Authorization: Bearer token1" \
  --control-identifier user@example.com \
  --control-server https://server2.example/push \
  --control-server-H "Authorization: Bearer token2" \
  --control-identifier serial-123
```

When a control-server header contains a push key, Open Agent Scan treats the run as unattended. Stdio MCP behavior changes as follows:

| `--dangerously-run-mcp-servers` | Consent prompts | Stdio MCP subprocesses |
| --- | --- | --- |
| not set | skipped | not started |
| set | skipped | started for every stdio server in scanned configs |

Remote MCP servers and skills can still be scanned without starting stdio MCP subprocesses.

---

## CI Mode

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--ci` | boolean | `false` | Exit with code `1` if any analysis issues or runtime failure codes remain after the scan. Requires `--dangerously-run-mcp-servers` in non-interactive environments. |
| `--ignore-issues-codes CODES` | string | - | Comma-separated issue or failure codes to ignore for `--ci` exit status. Only valid with `--ci`. Ignored codes are also removed from JSON output in CI mode. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success; no remaining issues or failures after ignores |
| `1` | `--ci`: findings or unignored runtime failures present |
| `2` | Invalid flag combination |

---

## MCP Server Options

Applies to `scan` and `inspect`.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--server-timeout SECONDS` | float | `10` | Timeout for MCP server connections. |
| `--suppress-mcpserver-io BOOL` | boolean | see below | Suppress stderr from stdio MCP servers. Stdout is always consumed as JSON-RPC and never shown. Accepted values include `true`, `false`, `1`, `0`, `yes`, and `no`. |
| `--dangerously-run-mcp-servers` | boolean | `false` | Skip interactive per-server consent and start every stdio MCP server listed in scanned configs. Required with `--ci` in CI/CD. |

Default for `--suppress-mcpserver-io`:

| Run type | Default |
| --- | --- |
| Interactive (`inspect`, or `scan` without push key) | `false` |
| Unattended push-key scan | `true` |

Handshake and consent matrix for stdio MCP servers:

| Command | Push key | `--dangerously-run-mcp-servers` | Start servers | Consent prompt |
| --- | --- | --- | --- | --- |
| `inspect` | no | no | yes | yes |
| `inspect` | no | yes | yes | no |
| `scan` | no | no | yes | yes |
| `scan` | no | yes | yes | no |
| `scan` | yes | no | no | no |
| `scan` | yes | yes | yes | no |

> Scanning MCP configs executes the commands defined in them. Review consent prompts carefully or run inside a sandbox. See the [Security Warning](../README.md#security-warning) in the README.

---

## Scan-Only Options

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--checks-per-server NUM` | integer | `1` | Number of analysis passes per MCP server. |

`scan` runs the full pipeline: discover, inspect, redact, analyze, and optionally upload.

---

## Inspect

`inspect` uses the same global and MCP options as `scan`, but does not run security analysis. It only discovers configured components and performs MCP handshakes to print tool, prompt, and resource metadata.

---

## Guard

Manage Agent Guard hooks for Claude Code, Cursor, and Codex.

```bash
open-agent-scan guard [install|uninstall] [OPTIONS]
open-agent-scan guard
```

### Guard Install

```bash
open-agent-scan guard install {claude,cursor,codex,all} [OPTIONS]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--url URL` | string | empty | Remote hooks base URL. Required for install. |
| `--push-key KEY` | string | - | Push key provisioned by your hook server administrator. Can also be set with `PUSH_KEY`. |
| `--tenant-id ID` | string | - | Tenant ID to embed in installed hooks when provided. Can also be set with `TENANT_ID`. |
| `--file PATH` | string | - | Override the client config file path. |
| `--managed` | boolean | `false` | Install hooks to the managed admin or MDM config path instead of the user-level path. |
| `--test` | boolean | `false` | Deprecated no-op. |

### Guard Uninstall

```bash
open-agent-scan guard uninstall {claude,cursor,codex,all} [OPTIONS]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--file PATH` | string | - | Override the config file path. |
| `--managed` | boolean | `false` | Uninstall hooks from the managed admin or MDM path. |

Guard environment variables:

| Variable | Purpose |
| --- | --- |
| `PUSH_KEY` | Pre-provisioned push key for hook installation |
| `TENANT_ID` | Tenant ID to embed in installed hooks |
| `HOOK_VERSION` | Override the hook API line version baked into Guard artifacts |

---

## Examples

```bash
# Full machine scan
uvx open-agent-scan@latest

# MCP only, no skills
uvx open-agent-scan@latest --no-skills

# Specific config or skill directory
uvx open-agent-scan@latest ~/.cursor/mcp.json
uvx open-agent-scan@latest ~/.claude/skills

# Inspect without analysis
uvx open-agent-scan@latest inspect

# JSON output
uvx open-agent-scan@latest --json ./my-skill

# CI pipeline
uvx open-agent-scan@latest --ci --dangerously-run-mcp-servers --json

# CI with ignored warnings
uvx open-agent-scan@latest --ci --dangerously-run-mcp-servers \
  --ignore-issues-codes W001,W015

# Explicit remote analysis
uvx open-agent-scan@latest scan \
  --analysis-mode remote \
  --analysis-url "https://analysis.example/scan" \
  --verification-H "Authorization: Bearer token"

# Managed hook install
PUSH_KEY=... open-agent-scan guard install all --url "https://hooks.example"

# MDM managed hook install
PUSH_KEY=... open-agent-scan guard install cursor --managed --url "https://hooks.example"

# Uninstall hooks
open-agent-scan guard uninstall all
```

---

## Release Archives

GitHub Releases publish standalone CLI binaries as archives:

- macOS/Linux: `open-agent-scan-<version>-<platform>.tar.gz`
- Windows: `open-agent-scan-<version>-windows-x64.zip`

For macOS, extract and run from Terminal:

```bash
tar -xzf open-agent-scan-v0.1.2-macos-arm64.tar.gz
xattr -d com.apple.quarantine open-agent-scan 2>/dev/null || true
./open-agent-scan --help
```

---

## Related Documentation

- [Scanning overview](scanning.md)
- [Issue codes](issue-codes.md)
- [JSON output](json-output.md)
