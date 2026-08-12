# Rule Authoring

Open Agent Scan rules should be local-first, deterministic, explainable, and
fast enough for default scans.

## Required Metadata

Each local rule needs:

- issue code;
- title;
- category;
- severity;
- confidence;
- applicable component types;
- source references;
- false-positive rationale.

The metadata registry lives in `src/agent_scan/rules.py`.

## Required Tests

For each new rule or material rule change, add:

- at least one positive fixture;
- at least one negative fixture;
- assertions for issue code, reference, severity, confidence, and evidence;
- docs updates for new issue codes.

## Performance Rules

- Compile regexes at module import time.
- Reuse extracted text.
- Avoid repeated filesystem walks.
- Do not add network calls to default local analysis.
- Do not add LLM calls to default local analysis.

## Evidence

Findings should include useful evidence in `Issue.extra_data` without exposing
secrets. Prefer categories, matched reason names, character names, and
redacted/summarized context over raw sensitive values.

## Confidence Guidance

- `high`: strong indicator with narrow matching and low expected noise.
- `medium`: meaningful signal requiring user review.
- `low`: weak or broad signal; should not be treated as proof of compromise.
