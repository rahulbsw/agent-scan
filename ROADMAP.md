# Roadmap

## v0.1

- Establish Open Agent Scan identity, package, CLI, governance, and attribution.
- Keep `agent-scan` as a temporary compatibility alias.
- Add local rule metadata with source references, confidence, severity, and
  false-positive rationale.
- Add DCO, Scorecard, SBOM, checksums, and release attestations.

## v0.2

- Expand deterministic MCP startup command analysis.
- Add more negative fixtures to reduce false positives.
- Add rule documentation generation from metadata.
- Publish baseline performance measurements for local analysis.

## v0.3

- Add opt-in experimental rules for lower-confidence emerging threats.
- Improve runtime tool-output scanning design without adding default network or
  LLM dependencies.
- Add organization-level maintainer and release process docs after repository
  migration.

## Backlog

- Rename internal Python package from `agent_scan` only if compatibility costs
  become manageable.
- Add signed release manifests.
- Add richer SPDX/CycloneDX release metadata.
- Build a public corpus of safe synthetic MCP and skill fixtures.
