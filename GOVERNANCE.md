# Governance

Open Agent Scan is a maintainer-led community project.

## Maintainers

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). Maintainers can:

- review and merge pull requests;
- triage issues and security reports;
- approve new issue codes and rule categories;
- cut releases;
- update governance when needed.

## Decision Process

Routine fixes can be merged after one maintainer approval and passing checks.

Changes that affect public behavior require documented rationale:

- new issue codes;
- severity or confidence changes;
- CLI or JSON output changes;
- release workflow changes;
- governance or license-related docs.

For significant rule changes, maintainers should prefer consensus. If consensus
does not happen, the active maintainers decide based on evidence, accuracy,
performance, and user safety.

## Rule Quality Bar

Rules should be deterministic by default, explainable, and backed by references
or reproducible research. Rules that are experimental or speculative must be
clearly marked and should not block CI by default.

## Upstream Syncs

Upstream syncs follow [FORK_MAINTENANCE.md](FORK_MAINTENANCE.md). Syncs must not
remove attribution, reintroduce mandatory Snyk account flows, or close external
contributions.
