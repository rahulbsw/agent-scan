# Security Policy

## Reporting Vulnerabilities

Please report suspected vulnerabilities in Open Agent Scan through GitHub
Security Advisories for this repository. Do not open a public issue for scanner
vulnerabilities, bypasses, or exploitable test cases that include sensitive
details.

Include:

- affected version or commit;
- operating system and install method;
- minimal reproduction steps;
- expected and actual behavior;
- whether the issue affects local scanning, remote analysis, hooks, release
  artifacts, or rule accuracy.

## Scope

In scope:

- vulnerabilities in Open Agent Scan itself;
- unsafe default execution behavior;
- secret leakage in output, logs, artifacts, or telemetry;
- release integrity issues;
- high-confidence false negatives for documented rules.

Out of scope:

- vulnerabilities in third-party MCP servers or skills, unless caused by Open Agent
  Scan behavior;
- reports that require running untrusted code without user consent;
- findings based only on speculative prompts with no reproducible path.
