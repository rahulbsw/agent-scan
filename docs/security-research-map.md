# Security Research Map

Open Agent Scan maps scanner coverage to public security guidance. This file is
for maintainers and contributors deciding what to add next.

## Primary References

- OWASP Top 10 for LLM Applications
- OWASP MCP Security Cheat Sheet
- Model Context Protocol specification and security best practices
- NIST AI Risk Management Framework
- NIST Secure Software Development Framework
- OpenSSF Scorecard and best practices

## Current Coverage

| Area | Current coverage |
| --- | --- |
| Prompt injection | Suspicious tool language, hidden instructions, hidden Unicode |
| Tool poisoning | Tool and schema text inspection, cross-server reference signals |
| Sensitive disclosure | Sensitive data source labels, workspace data labels, hardcoded secret markers |
| Supply chain | External skill dependencies, suspicious MCP startup commands, dependency audit |
| Excessive agency | Local and shared destructive capability labels |
| Consent and execution | Interactive MCP startup consent, CI opt-in for stdio execution |
| Release integrity | Checksums, SPDX SBOM generation, GitHub artifact attestations |

## Contribution Priorities

1. High-confidence deterministic rules for MCP config and skill content.
2. Synthetic fixture corpus for known attack patterns.
3. Performance budgets for full-machine scans.
4. Better docs for interpreting findings and reducing false positives.
5. Experimental rules clearly marked as non-blocking.
