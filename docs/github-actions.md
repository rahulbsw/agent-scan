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
uploads JSON reports even when scanning fails. It runs on pull requests, pushes
to `main`, and manual dispatch. Missing optional paths are skipped; finding no
configured paths fails explicitly rather than presenting an empty scan as success.

The scanner is pinned to commit
`2140da75c0dfb999b4f650a829eb7e32a51c64a1`, which introduces the passive command
in [PR #12](https://github.com/rahulbsw/agent-scan/pull/12). This is an explicit
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

The example uses:

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
The example continues scanning other targets and retains the highest exit status.

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
automatically accept findings or create baselines during PR runs.

## Read the Results

Open the Actions run and download `agent-security-reports`. Each scanned target
has a separate `oas.skills/v1` JSON report with severity, confidence, locations,
remediation, suppressed findings, and explicit coverage limitations. The example
keeps artifacts for seven days; adjust retention to your data policy. Reports
omit source snippets, but filenames and metadata can still be sensitive.

The current passive profile checks explicit instruction overrides,
download-to-interpreter pipelines and selected hidden formatting. It does **not**
validate an agent's behavior, execute tests, inspect live MCP tool schemas,
perform AST/data-flow analysis, audit all dependencies/CVEs, or certify a repo as
safe. A successful run only describes the configured profile and selected scope.

## Optional SARIF and GitHub Code Scanning

For downloadable SARIF, replace `--format json` with `--format sarif` and the
output extension `.json` with `.sarif`. The artifact upload works unchanged and
needs no additional permissions. This alone does not create Security-tab alerts.

For GitHub code-scanning ingestion, use
[`github/codeql-action/upload-sarif`](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
after generation, pin the action to a reviewed full SHA, and grant only the
permissions required by your repository/event (including `security-events: write`
where supported). Check code-scanning availability and fork-PR token policy
first. Keep the artifact-only workflow as the low-permission default; do not use
`pull_request_target` as a workaround for permissions.

Before ingestion, normalize each report's relative artifact URIs to the target
repository root: a `skills/SKILL.md` scan emits `SKILL.md`, which must map to
`skills/SKILL.md` in GitHub. Directory targets similarly need their directory
prefix; single files need their parent prefix. When using this example's second
checkout layout, set the upload action's `checkout_path` to
`${{ github.workspace }}/repository`. Multiple reports need stable, distinct
analysis categories/`runAutomationDetails.id` values so one target's results do
not replace another's. The supplied example intentionally does not attempt this
mapping or enable Security-tab uploads; its JSON artifacts are directly usable.

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
