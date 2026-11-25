# Scan Repository Skills and Agent Instructions in GitHub Actions

Use the passive `skills` command for pull requests containing untrusted skill
or agent instructions. It reads local files without running the target's code,
starting MCP servers, installing its dependencies, or calling an analysis service.
No Snyk account, `SNYK_TOKEN`, or model-provider key is needed.

## Add the Workflow

Add the [complete example](examples/agent-security.yml) to the consuming
repository as `.github/workflows/agent-security.yml`. It uses an Ubuntu-hosted
runner because secure passive collection currently supports Linux/macOS, not
Windows. Change the `push.branches` value if your default branch is not `main`.

The example checks out the target and scanner into separate directories, installs
only the trusted scanner's locked dependencies, scans a fixed allowlist, and
uploads JSON and self-contained HTML reports even when a policy check fails,
and writes a GitHub Actions job summary. It runs on pull requests, pushes
to `main`, and manual dispatch. Missing optional paths are skipped; finding no
configured paths fails explicitly rather than presenting an empty scan as success.

The scanner is pinned to a full reporting-capable commit in the example workflow,
from [PR #12](https://github.com/rahulbsw/agent-scan/pull/12). This is an explicit
feature revision, not a claim that the command is in the latest published
release or PyPI package. Review the revision before adoption and update it through
reviewed dependency changes. Do not replace it with the pull request's scanner
checkout or an unpinned `main`/`latest` reference. The action versions are also
pinned to verified full commit SHAs and should be kept updated.

The first workflow run may require approval for external contributors under your
repository's Actions policy. This example is documentation for consumers, not
an automatically enabled workflow in this project.

## Select the Scope

Edit the workflow's static `targets` array to match your repository:

| Target | Content inspected |
| --- | --- |
| `skills/` | Skill bundles, including nested `SKILL.md`, scripts and references |
| `agents/` | Project-defined agent instruction bundles |
| `.agents/` | Repository-local shared agent configuration and skills |
| `.claude/skills/`, `.claude/agents/`, `.claude/commands/` | Claude skill, subagent and command files |
| `.github/agents/`, `.github/instructions/`, `.github/prompts/` | Copilot custom agents, instructions and prompts |
| `.cursor/rules/`, `.cursor/agents/`, `.cursorrules` | Cursor agent and rule files |
| `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` | Root-level agent instructions |
| `.github/copilot-instructions.md` | Repository-wide Copilot instructions |

Add monorepo locations explicitly, for example `packages/api/AGENTS.md` or
`apps/web/.claude/skills`. These examples do not automatically find every nested
`AGENTS.md`, inspect contributors' home directories, or discover external agents.
Do not fill shell scripts with pull request titles or other untrusted expressions.
Keep the allowlist reviewed and paths inside the target repository.

Do not scan `.` casually: it includes `.git`, dependencies, generated files and
binary assets. That adds work and can legitimately make this text profile's
coverage incomplete. No author-owned ignore file silently excludes content.
Binary assets, rejected links, read failures and resource limits remain coverage
gaps. The workflow also rejects selected paths resolving outside the repository.

## Decide What Blocks a Pull Request

The workflow runs the CI helper once over the configured targets. Its default
policy is equivalent to the following individual scan:

```bash
open-agent-scan skills PATH --format json --fail-on none --fail-on-incomplete
```

This is an **advisory findings rollout**: experimental indicators are reported
but do not fail the job. Incomplete coverage and operational failures do fail it.
To block on medium-or-higher indicators, change `--fail-on none` to
`--fail-on medium`. `--fail-on high` is a narrower alternative. These are explicit
policy choices, not validated guarantees of maliciousness; quoted attack examples
can trigger a finding. The command's exits are 0 for no requested gate failure,
1 for policy/coverage gates, and 2 for operational or unsafe-input failures.
The helper continues scanning other targets and retains the highest exit status.
To change the threshold, edit `--fail-on none` in the workflow's helper command.
Incomplete coverage blocks by default; do not add `--allow-incomplete` unless
you intentionally accept nonblocking coverage gaps.

After a successful rollout, add the check
`Passive skills and agent instructions` as a required check in the consuming
repository's branch protection/ruleset. Protect the workflow and any acceptance
policy with CODEOWNERS review so contributors cannot silently weaken the gate.
Avoid adding event path filters to a required workflow without handling GitHub's
skipped/pending-check behavior.

For a reviewed false positive, use an explicit baseline as described in
[passive scanning](passive-skills.md#reviewed-baselines). Generate it outside CI,
review the reason/owner/expiry, and protect changes. A baseline loaded from an
unreviewed PR is not an independent trust decision. Keep per-target baselines
outside scanned directories; they never erase incomplete coverage. Do not
automatically accept findings or create baselines during PR runs. The multi-target
CI helper does not currently apply per-target baselines; use separately reviewed
`skills --baseline` invocations when you need baseline-aware gates rather than
assuming the bundled helper will load them.

## Read the Results

Open the Actions run's **Summary** page for a target-by-target table: coverage,
active/suppressed findings, highest active severity, and exit status. Missing
targets are listed as skipped. If scanner setup or report generation fails before
the summary exists, the workflow writes an explicit failure message instead of
an empty success summary. A cancelled/timed-out job may not reach reporting steps.

Download and extract the `agent-security-reports` artifact for details:

| File | Purpose |
| --- | --- |
| `index.html` | Offline repository dashboard linking each target's HTML report |
| `<target-id>.html` | Readable target report with findings, remediation and coverage gaps |
| `<target-id>.json` | Full recorded `oas.skills/v1` report for automation |
| `manifest.json` | `oas.ci/v1` target-to-file mapping and aggregate exit status |
| `summary.md` | The same table published to the Actions job summary |
| `sarif/<target-id>.sarif` | Optional repository-mapped SARIF for complete, successful scopes |

Target IDs are stable hashes to avoid unsafe or colliding filenames. The HTML
contains no scripts or external assets, escapes untrusted text, and shows at most
200 findings and 200 coverage gaps per target; use JSON for the full recorded
lists. Each target is scanned once, then rendered into the requested formats.
Reports remain available when findings or coverage fail the scan step. The
example keeps artifacts for seven days; adjust retention to your data policy.
Reports omit source snippets, but filenames and metadata can still be sensitive.

The helper also works outside GitHub Actions, with a fresh output directory
outside the target repository:

```bash
uv run python -m agent_scan.skill_scanning.ci \
  --root /path/to/repository --reports /tmp/new-agent-reports \
  --fail-on none skills .agents AGENTS.md
```

Add `--sarif` to generate mapped SARIF locally. This command only writes reports;
it never uploads results or changes GitHub permissions.

The current passive profile checks explicit instruction overrides,
download-to-interpreter pipelines and selected hidden formatting. It does **not**
validate an agent's behavior, execute tests, inspect live MCP tool schemas,
perform AST/data-flow analysis, audit all dependencies/CVEs, or certify a repo as
safe. A successful run only describes the configured profile and selected scope.

## Optional SARIF and GitHub Code Scanning

Security-tab publishing is **off by default**. To enable the supplied optional
job, first check that GitHub code scanning is available/enabled for your repo,
then create a repository Actions variable in **Settings > Secrets and variables
> Actions > Variables**:

```text
OPEN_AGENT_SCAN_UPLOAD_SARIF=true
```

Use the exact lowercase string `true`. With this variable enabled, the scan job
generates SARIF alongside JSON/HTML. A separate `upload-sarif` job runs only on
`push` and `workflow_dispatch`, not pull-request events. The scanner job remains
read-only. Only the upload job receives `security-events: write` and
`actions: read`; it checks out source for mapping and uploads reports using a
pinned `github/codeql-action/upload-sarif`. It never runs the target's code.

Fork and same-repository pull requests still receive the default artifact and
summary experience; they do not gain a write-token upload path. Do not switch to
`pull_request_target` to bypass this separation. Upload failures are visible as a
separate job failure and do not erase the scan reports or change its policy gate.
With the variable unset/false, no Security-tab job runs and SARIF generation is
omitted. This is a documented opt-in, not a repository setting changed by this PR.

The helper maps artifact URIs to the consuming repository root (including
single-file targets), assigns a stable distinct SARIF `automationDetails.id` per
target, and configures `checkout_path` for the target checkout. It emits uploadable
SARIF only for successfully executed, completely covered targets, so a partial
or failed scan cannot clear existing alerts by uploading an empty clean result.
JSON/HTML and the summary still record those failed scopes. Missing, removed or
incomplete targets are not refreshed in code scanning; their old alerts may
remain until a complete rescan or explicit analysis cleanup. Standalone
`skills --format sarif` remains available for diagnostic reports, including
partial/failed coverage, but does not itself upload anything.

See GitHub's [SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for repository eligibility and token policy.

## Runner Safety

Use disposable GitHub-hosted runners for untrusted PRs. Do not grant secrets,
write tokens, deployment credentials, or production mounts to the scan job.
Keep checkout credentials disabled and do not run repository install hooks,
actions, scripts or an MCP config just to inspect instructions. The scanner's
environment is installed from its separate pinned checkout, not the target's
`pyproject.toml` or lockfile. Provisioning requires outbound package downloads;
passive scanning itself makes no analysis/network calls.
Do not replace the passive invocation with `scan --ci
--dangerously-run-mcp-servers` for untrusted PRs; that is a different, active
inspection path and can execute configured MCP startup commands.

The example sets a ten-minute job timeout in addition to per-target scanner
budgets. Its processing deadline is cooperative, not hard syscall preemption or
a complete OS sandbox. Do not substitute a persistent privileged self-hosted
runner for this setup without additional isolation. See GitHub's
[secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)
and the scanner's [scope and limits](passive-skills.md#scope-and-limitations).
