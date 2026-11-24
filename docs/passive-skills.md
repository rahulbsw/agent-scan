# Passive Skill Scanning

`open-agent-scan skills` is an experimental, explicitly scoped text-analysis
profile. It does not discover installed agents, start MCP servers, contact
endpoints, resolve packages, call models, or inherit remote configuration.
The existing `scan`, `inspect`, and `guard` commands are unchanged.
Package-manager provisioning is separate: `uv run` may download dependencies
when preparing an environment. Use an already installed CLI, or a provisioned
environment with `uv run --offline --frozen`, for an offline invocation.

## Usage

```bash
uv run open-agent-scan skills ./my-skill
uv run open-agent-scan skills ./my-skill --format json
uv run open-agent-scan skills ./my-skill --format sarif > /tmp/skill-report.sarif
uv run open-agent-scan skills ./my-skill --fail-on medium --fail-on-incomplete
```

The path must be an explicit local regular file or directory. Directories are
treated as one bounded text bundle, including nested skill directories. This
profile does not validate that a usable `SKILL.md` manifest exists. It scans
frontmatter as text, without YAML expansion or execution. Put redirected report
files outside the target so an existing or shell-created output does not enter
its own scan.

Secure collection currently requires POSIX descriptor-relative no-follow file
operations (Linux/macOS). On platforms without them, including Windows, this
command reports failed coverage and exits 2. It does not fall back to racy
path-based collection. Existing commands retain their cross-platform support.
Windows-native safe collection remains follow-up work.

## Scope and Limitations

Nested links, symlink targets, nonregular files, unreadable entries, changing
files, unsupported binary/encoding content, and exhausted budgets are reported
as coverage gaps. The selected root is the caller's trust boundary; ancestors
above it may resolve through the caller's filesystem. Reads beneath the root
use anchored descriptors and do not follow replacement symlinks. Like other
filesystem scanners, this is not an atomic snapshot of a concurrently changing
directory tree or protection from a hostile kernel/filesystem.

Default limits:

| Resource | Default | Option |
| --- | --- | --- |
| Directory entries | 10,000 | `--max-entries` |
| Nested directory depth | 32 | `--max-depth` |
| Text file bytes | 1 MiB | `--max-file-bytes` |
| Total input bytes | 32 MiB | `--max-total-bytes` |
| Findings | 10,000 | `--max-findings` |
| Cooperative processing budget | 30 seconds | `--max-seconds` |

An oversized file may read one additional probe byte, charged against the total
byte allowance. A file that consumes the exact remaining total allowance is
conservatively marked partial. Enumeration is bounded before sorting. Time
checks run during traversal, reads and per-line analysis; they do not interrupt
a blocked filesystem syscall. Hard worker time/memory isolation is not yet
implemented. Raise limits only for trusted workloads.

The initial rules use the existing rule metadata registry:

- `OAS-SKILL-001`: explicit instruction-hierarchy override language.
- `OAS-SKILL-002`: downloaded content piped into an interpreter.
- `OAS-SKILL-003`: selected zero-width or bidirectional formatting.

All three are experimental indicators, not confirmed vulnerabilities. Quoted
attack examples can still be reported, with a false-positive rationale. Ordinary
security vocabulary and documentation URLs alone do not create findings.
Matching is bounded and intentionally narrow; multiline commands, obfuscation,
data flow, behavioral risks, and unsupported languages can evade these checks.
This profile does not replace a security review or sandbox.

## Reports and Policy

JSON uses schema version `oas.skills/v1` and profile `passive-text-v1`. It is a
separate contract, not a replacement for existing scan JSON. Findings carry
rule revisions, severity, confidence, relative paths, original text locations,
references, remediation, and evidence-bound fingerprints. Reports never contain
source snippets; paths are redacted at serialization and terminal control
characters are escaped. Internal raw UTF-8 text is local and ephemeral.

SARIF 2.1.0 preserves suppressed findings, confidence, experimental status,
coverage, and tool notifications. Partial coverage is not automatically a failed
invocation: execution status and coverage are independent.

Exit precedence:

1. `2`: unsafe/unreadable target, unsupported secure collection, invalid
   arguments/baseline, or baseline write failure.
2. `1`: requested `--fail-on-incomplete` gate or an unsuppressed finding at/above
   the requested `--fail-on` threshold.
3. `0`: processing succeeded and no requested gate failed.

The default threshold is `none`: experimental findings do not fail CI without
explicit policy. Exit 0 and complete profile coverage do not certify safety.

## Reviewed Baselines

```bash
uv run open-agent-scan skills ./my-skill \
  --write-baseline ../reviewed-skill.json \
  --baseline-reason 'Reviewed training example, not an active instruction' \
  --baseline-owner security-team \
  --baseline-expires 2099-01-01

uv run open-agent-scan skills ./my-skill --baseline ../reviewed-skill.json \
  --fail-on medium --fail-on-incomplete
```

Use a short, real review expiry rather than the illustrative date above.
Creation is explicit, accepts the currently observed findings, requires complete
coverage, and creates a new mode-0600 file without overwriting an earlier review.
Keep it outside the target and review it before committing. No author-supplied
baseline is loaded automatically. A caller-selected baseline inside a directory
target is excluded from analysis but makes coverage partial.

Baselines are bounded JSON, not executable configuration. Each acceptance has
an owner, reason, expiry, and fingerprint bound to the file contents, path,
location, rule ID and revision. Any file-content change invalidates its exact
acceptances. Expired entries do not suppress findings. Suppressions remain in
reports and never clear coverage gaps. Existing accepted entries are not a
trusted change snapshot or authorization to install the skill.

## Validation and Delivery Status

Run the focused tests and the synthetic benchmark:

```bash
uv run --extra test -m pytest --no-cov -q tests/unit/test_passive_skills.py
uv run benchmarks/passive_skills.py --repeats 10
```

The original synthetic corpus under `tests/fixtures/passive_skills` has declared
provenance and expected indicators. It is regression coverage, not an independent
precision/recall dataset. The legacy risk-response fixture guards compatibility.
The benchmark records a corpus hash, environment, warm timings, and peak process
RSS. Legacy analysis excludes collection; its timing is not directly comparable
to the new collect-and-analyze profile. Cold-start and holdout accuracy evaluation
remain outstanding. No zero-overhead or calibrated accuracy claim is made.

An initial development run on macOS ARM64 / Python 3.13.14, 10 repetitions,
100 synthetic skills totaling 10,485,800 bytes, recorded a warm passive
collect-and-analyze median of 0.357 seconds and p95 of 0.381 seconds. JSON
rendering p95 was 0.0011 seconds; entire benchmark-process peak RSS was about
79.1 MiB. Corpus SHA-256:
`f37c35ec27ff0d689f3b2624dab68a7b82073be65a885d43580683901b353c5b`.
These are local observations, not portable SLAs or a speedup comparison.
The manually dispatched `Passive skill benchmark` workflow records comparable
environment-tagged results as an artifact; it does not enforce an uncalibrated
wall-clock threshold on shared runners.

This delivers the first vertical slice of the
[SkillSpector-inspired roadmap](proposals/skillspector-feature-roadmap.md):
baseline harness, bounded passive collection, experimental metadata-backed
findings, JSON/SARIF, explicit CI policy, and caller-owned baselines. It does not
complete every item in roadmap PRs 1-4: independent holdout evaluation, richer
context classification, hard worker isolation, Windows-safe collection, and
further contract validation remain. AST/data flow, lockfile provenance, trusted
snapshots, incremental caches, OSV, semantic review and external-engine adapters
are subsequent milestones, not included features.
