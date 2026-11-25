# SkillSpector Review and Open Agent Scan Feature Proposal

Date: 2026-11-24. Status: proposal; no scanner behavior changed.

## Decision

Keep Open Agent Scan independent and local-first. Adopt the strongest design
ideas from SkillSpector rather than making its entire engine a core dependency:
bounded collection, honest coverage accounting, contextual code analysis,
auditable suppressions, and standard CI reports. Consider an optional external
engine adapter only after the native reporting contract is stable.

Zero additional cost and zero false positives are not achievable guarantees.
Use measured budgets, explicit limitations, and independently evaluated rules.
Do not advertise a skill as safe merely because a scan exits successfully.

## Scope and Evidence

Reviewed SkillSpector source at commit
`0205488a8257869cac3054397ddd5a5d29180aab` (package metadata: 2.13.7),
and the local Open Agent Scan checkout at
`f9e1ddd8cfb2786f3132b1685f53bf8c0b681849`.
This is an architectural comparison, not a comprehensive security audit or
measured head-to-head benchmark. The latter snapshot is the release preparation
branch, not a claim about the current GitHub default branch.

SkillSpector was cloned into a temporary review directory. Its code was read,
not installed, imported, or executed. Documentation may lag implementation;
advertised detector counts and research prevalence are not accuracy evidence.

Primary sources, pinned to the reviewed revision:

- [Architecture and development](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/docs/DEVELOPMENT.md).
- [Dependency and packaging manifest](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/pyproject.toml).
- [Resource bounds](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/docs/ANALYSIS_RESOURCE_BOUNDS.md).
- [Completeness contract](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/docs/scan-completeness.md).
- [Python data-flow analyzer](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/src/skillspector/nodes/analyzers/behavioral_taint_tracking.py).
- [Least-privilege analyzer](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/src/skillspector/nodes/analyzers/mcp_least_privilege.py).
- [Rug-pull analyzer](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/src/skillspector/nodes/analyzers/mcp_rug_pull.py).
- [Suppression policy](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/docs/SUPPRESSION.md).
- [Live dependency lookups](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/src/skillspector/nodes/analyzers/static_patterns_supply_chain.py).
- [License](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/LICENSE) and
  [third-party notices](https://github.com/NVIDIA/SkillSpector/blob/0205488a8257869cac3054397ddd5a5d29180aab/THIRD_PARTY_NOTICES.md).

## Comparative Findings

| Area | SkillSpector observation | Open Agent Scan observation | Recommended direction |
| --- | --- | --- | --- |
| Architecture | Graph-based analyzer pipeline; shared context; optional semantic stage | Existing discovery/inspection pipelines and small deterministic analyzer | Keep our pipeline; add shared analysis context, not another orchestration framework |
| Code inspection | Python AST and source-to-sink analysis beyond textual matching | Local skill checks mainly use text patterns | Add bounded Python AST first; language parsers later |
| Coverage | Separate execution status, limitations, and coverage accounting | Existing path/server/skill errors, but no comparable per-artifact/analyzer coverage ledger in reviewed local path | Preserve errors and add explicit coverage |
| Input limits | Budgets span discovery, parsing, archives, findings, and time | Collector detects link cycles, but follows linked targets and reads entire text files | Harden before expanding accepted inputs |
| CI reporting | SARIF and reasoned baselines | Current risk-response output; no SARIF/baseline path found in reviewed CLI | Add adapters and caller-owned suppression policy |
| Supply chain | Dependency lookups, package-source checks, and change detection | Startup command heuristics and binary hash markers | Add offline provenance/change checks before live enrichment |
| Installation footprint | Core manifest includes LangGraph, provider SDKs, YARA and native parsers | Smaller local-analysis surface, existing MCP stack | Keep optional features out of the default dependency path |

Important qualification: SkillSpector's `--no-llm` disables semantic analysis,
not every network-capable feature. Its supply-chain analyzer has a live OSV
lookup path. Our design needs independent controls for acquisition, MCP
discovery, vulnerability enrichment, and semantic analysis.

## Immediate Gaps in Our Code

These are code-based observations, not reproduced exploit claims:

1. `src/agent_scan/skill_client.py`: `_walk_skill_regular_files` follows file
   and directory links. Ancestor identities prevent cycles, but do not establish
   containment inside the selected root. Discovery-time boundary checks do not
   cover every nested file later collected. `_read_skill_file_content` reads
   whole text files; collection lacks explicit aggregate file/byte/time budgets.
2. `src/agent_scan/local_analysis.py`: broad words and capability references
   contribute to fixed risk scores. A security tutorial, orchestrator, or benign
   installer can resemble an attack. These signals need contextual evidence and
   should not automatically become confirmed vulnerabilities.
3. `src/agent_scan/rules.py`: useful metadata already exists, but the current
   local analyzer constructs risk-index responses directly without consuming
   `RULES` or `issue_extra`. Metadata presence tests alone do not prove those
   details reach user-visible findings. Integrate this registry; do not rebuild it.
4. `SkillFile` contains redacted text or a synthetic binary hash marker. This
   protects downstream disclosure but does not preserve original source spans
   for richer code analysis. A hash is inventory evidence, not binary inspection.

## Proposed Design

Use the existing pipeline with a bounded, reusable per-scan context:

```text
explicit scope and policy
  -> bounded artifact inventory and one-time reads
  -> local text / syntax views and source maps
  -> deterministic rule registry
  -> findings + coverage + provenance
  -> caller-owned policy and suppressions
  -> existing risk-response adapter / versioned JSON / SARIF
```

Each finding should carry a stable rule ID and revision, severity, independently
assessed confidence, artifact identity, source range, redacted evidence,
rationale, remediation, and references. Keep capabilities, suspicious indicators,
and concrete vulnerability evidence distinguishable. Do not derive confidence
from severity or describe scores as calibrated probabilities.

Add an internal finding model and adapters rather than forcing every new rule
into an unrelated existing risk index. Preserve existing default JSON during
migration; introduce richer output through an explicitly versioned format.
Document mappings and reserve new IDs centrally. Test actual serialized output,
not just metadata definitions. Resolve stale issue-code documentation alongside
the new contract rather than promising compatibility that no longer exists.

Coverage should record file and byte counts, omitted paths, analyzer outcomes,
timeouts, unsupported languages/formats, parsing failures, and policy exclusions.
Define completeness relative to a named scan profile, not universal safety.
Suppression must never erase a coverage gap. A requested analyzer failure remains
visible even when other analyzers finish successfully.

### P0: Bounded Collection and Passive Scanning

- Default to rejecting nested symlinks and other reparse-style escapes from the
  selected root. An opt-in follow policy must check every target, prevent cycles,
  and preserve lexical identity. Address read-time replacement races with
  platform-appropriate no-follow operations or a verified private snapshot.
- Bound enumeration before sorting, depth, files, individual and total bytes,
  frontmatter/YAML complexity, finding output, and processing time. Use bounded
  reads, not only pre-read file sizes. Report why work stopped.
- Add an explicit passive/static profile that neither launches MCP servers nor
  contacts their endpoints. `--analysis-mode local` alone is not this guarantee.
- Keep local scope explicit. Never inherit exclusions, suppressions, Python
  plugins, or executable configuration from the scanned skill by default.
- Establish opt-in strict CI failure on incomplete coverage, with documented
  precedence over policy results; preserve existing exit semantics by default.

Initial configurable ceilings to validate: 10,000 entries, depth 32, 1 MiB per
text file, 32 MiB total input, 10,000 findings, and a 30-second processing budget.
These are proposal values, not current limits or measured completion promises.
Use cancellable workers where parsers or filesystem operations cannot be bounded
reliably; checking a deadline between operations is not hard preemption.

### P1: Rule Quality and Actionable CI

- Connect current rule metadata to emitted findings and source evidence.
- Distinguish instruction text, code, quoted examples, and references. This
  refines confidence; it must not categorically exempt code fences or test files.
- Flag a source-to-sink relationship more strongly than isolated words such as
  `token`, `run`, or `critical`. A documentation URL alone is not remote execution.
- Add JSON schema/version fixtures, SARIF 2.1.0, remediation, and stable finding
  fingerprints. Sanitize terminal control characters and machine-report paths.
- Caller-selected baselines require reason, owner, expiry, rule revision, and
  evidence-bound fingerprints. Changed evidence reactivates a finding. Retain
  suppressed results for auditing. Never silently auto-baseline new findings.

### P2: Native Behavioral and Least-Privilege Rules

- Parse Python once with stdlib `ast` in a bounded worker. Begin with dangerous
  calls and bounded within-function data flow: credentials to network output,
  downloaded bytes to execution, and untrusted data to unsafe deserialization.
- Handle imports/aliases and variable reassignment. Unresolved dynamic calls or
  unsupported constructs are limitations, not proof of harmlessness. Do not
  claim whole-program taint coverage.
- Compare declared permissions with observed read/write/network/exec behavior.
  Distinguish expected capability from unauthorized expansion; absence of a
  permission declaration is not by itself a critical vulnerability.
- Retain raw source only ephemerally for local parsing, with no logs, remote
  forwarding, or persistent raw-source cache. Generate redacted evidence before
  output. Record spans against original source, not shifted redacted strings.
- Defer JS/TS and shell grammar support to an optional extra after profiling;
  do not hand-roll a shell parser. Unsupported code receives an explicit status.

### P3: Offline Supply Chain and Change Awareness

- Parse supported lockfiles without resolving, installing, or running packages.
  Report exact versions, VCS refs, missing integrity, package-index redirection,
  lifecycle scripts, and executable dependencies with contextual severity.
- Save review-approved inventory/tool-schema snapshots. Compare content,
  command/arguments, permissions, endpoint changes, and newly executable files.
  A change is a review signal, not proof of a malicious rug pull.
- Keep trust snapshots separate from finding suppressions and performance caches.
  Do not replace a trusted snapshot automatically after a suspicious scan.
- Reuse file digests for incremental analysis. Cache keys include rule revision,
  analyzer/profile version, parser version, relevant policy, and dependency
  context. Recompute cross-file and cross-server relationships after changes.

### P4: Optional Enrichment and Interoperability

- OSV enrichment is explicitly enabled, batched and cached with source freshness.
  Disclose package coordinates sent externally. Offline/unavailable/stale
  advisory data means unknown coverage, not an all-clear result. Never install
  dependencies merely to inspect them.
- Optional semantic review accepts only selected redacted content under token,
  cost, concurrency, and timeout budgets. No tools, shell, host credentials, or
  autonomous action available to the reviewing model. Preserve deterministic
  findings; store model disagreement separately with model/prompt provenance.
- An external SkillSpector adapter should consume a versioned report from an
  explicitly installed, pinned executable in an isolated worker. Treat report
  paths/content as untrusted, deduplicate overlapping evidence, preserve engine
  identity, and show engine failures. A subprocess alone is not a sandbox.
- Defer direct URL/ZIP/transitive input support until bounded acquisition and
  containment exist. Then enforce redirect/DNS/SSRF policy, no ambient Git
  credentials or hooks, immutable refs, archive traversal/link checks, and
  expansion limits. Do not silently acquire remote inputs in passive mode.

Do not auto-install skills after a favorable report. An MCP scan-tool interface
can follow the same scope/consent policy later; its report is not an install
authorization or a claim of verified safety.

## Accuracy and Performance Gates

Build a licensed, versioned evaluation corpus containing real benign skills,
sanitized malicious examples, multilingual text, security documentation,
orchestrators, legitimate installers, malformed inputs, and mutation/evasion
cases. Deduplicate related projects across development and holdout sets.
Do not use SkillSpector's output as ground truth; use independent human labels.

Promotion gates proposed for review:

- Every rule has positive, negative, boundary, and adversarial fixtures.
- Blocking rules target at least 95% measured precision and at most 1% benign
  skill-level false-positive rate on the holdout set. Publish counts, confidence
  intervals, recall and its denominator; small samples cannot justify promotion.
- Advisory/experimental rules remain nonblocking until evidence supports them.
- Compare old/new recall at the chosen precision, not just total findings.
- A network-denied passive-profile test must pass; no model calls, subprocess
  execution of scanned artifacts, or raw secrets in logs/reports.
- Adversarial fixtures cover symlink escapes/cycles/replacement, huge files,
  YAML amplification, Unicode reconstruction, malicious baselines, parser limits,
  report truncation, and worker failure. Limits must retain incomplete status.

First collect a reproducible baseline. Proposed subsequent budget: no more than
10% p95 regression for the comparable existing text-only profile. Separately
target warm in-process analysis below one second for 100 skills totaling 10 MiB
and 256 MiB peak RSS for the bounded profile on a documented reference runner.
These are acceptance targets, not observations. Report cold CLI startup,
collection, redaction, parsing, rule time, report time, and memory separately.
New AST work cannot be compared as if it did no additional work.

Use fixed corpus hashes, pinned toolchains and matched machines. Run repeated
benchmarks in dedicated CI; use deterministic resource-limit assertions in
ordinary unit tests instead of flaky wall-clock thresholds on shared runners.

## Delivery Plan

Indicative effort for one engineer, excluding community review and labeling:

| PR | Scope | Dependency | Effort | Exit criteria |
| --- | --- | --- | --- | --- |
| 1 | Corpus harness, current behavior/JSON fixtures, benchmark baseline | None | 2-3 days | Repeatable results and documented gaps; no claimed improvement yet |
| 2 | Containment, bounded collector/frontmatter, passive profile, coverage model | PR 1 | 4-6 days | Escape/resource tests and network-denied end-to-end tests pass |
| 3 | Finding/metadata integration, versioned JSON, contextual rule refinements | PR 2 | 3-5 days | Evidence survives serialization; holdout precision/recall reported |
| 4 | SARIF, strict policy gates, auditable baselines | PR 3 | 2-4 days | SARIF validation; suppression cannot conceal incomplete work |
| 5 | Bounded Python AST/data flow and permission checks | PR 3 | 5-8 days | Alias/flow/negative fixtures, worker limits, measured performance |
| 6 | Offline lockfile provenance, reviewed snapshots, incremental cache | PRs 4-5 | 4-6 days | Drift and invalidation tests; no execution or implicit acquisition |
| 7 | Optional OSV, semantic review, or external-engine adapter | Separate approval | Scope later | Explicit consent, isolation, provenance and failure accounting |

Prioritize PRs 1-4 as the first community milestone. Prototype PR 5 behind an
experimental flag. Revisit the schedule after baseline measurements and labeling.
Keep changes in dedicated feature branches; do not attach implementation to a
release-preparation branch. Maintainer review and merge remain required.

## Community, Attribution, and License Handling

SkillSpector declares Apache-2.0. Prefer independent implementation of documented
ideas. For any copied/adapted code or fixtures, review file-level and third-party
terms, retain copyright/license notices, identify modifications, and update our
attribution and release inventory as applicable. Do not assume every dependency,
dataset, signature pack, or paper artifact inherits the repository license.
This is engineering guidance, not legal advice; obtain review before redistribution.

Credit NVIDIA SkillSpector as design inspiration without implying endorsement.
Keep the existing Snyk/Invariant attribution intact. Invite expert contributions
through a rule RFC containing threat model, sources, evidence, benign cases,
limitations, corpus provenance, precision/recall results, and runtime measurements.
Maintain DCO sign-off and private vulnerability reporting. Ordinary users should
not need either a Snyk account or a model-provider account for default scans.

## Approval Requested

Approve the local-first native direction and PRs 1-4 first. Defer provider
integrations, new native parser dependencies, and external-engine bundling until
quality and performance evidence justify their cost. No implementation, new
dependency, GitHub mutation, or release is authorized by this document alone.
