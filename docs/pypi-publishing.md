# PyPI Trusted Publishing

GitHub Releases do not automatically publish a Python package to PyPI. The
`open-agent-scan` project must receive its first successful wheel/source upload
before registry-only installation works. A **pending publisher** is expected
before that first upload; it is not an installed or published package.

## Publisher Configuration

The publishing job lives in `.github/workflows/release.yml` and matches:

| PyPI field | Value |
| --- | --- |
| Project | `open-agent-scan` |
| Repository owner | `rahulbsw` |
| Repository | `agent-scan` |
| Workflow filename | `release.yml` |
| Environment | `pypi` recommended; an existing `(Any)` setting is broader |

The workflow uses GitHub's `pypi` environment. Configure that environment with a
required owner/maintainer approval and deployment rules permitting version tags
and `main` for manual publication. Restrict the PyPI publisher to environment
`pypi` as well when ready. A publisher with no environment restriction accepts
the job's environment but offers less protection.

No PyPI password or long-lived API token is required by this workflow. The
isolated publishing job has `id-token: write` and `contents: read`; the pinned
official PyPA action exchanges GitHub OIDC identity for short-lived credentials.
Do not put a PyPI token in an issue, README, workflow, or chat.

## Normal Releases

1. Review and merge the version change and release content into `main`.
2. Create a matching `vMAJOR.MINOR.PATCH` tag (or an `aN`, `bN`, `rcN` prerelease).
3. The release workflow builds binaries and Python distributions, produces
   checksums/attestations, and publishes the GitHub release.
4. The separate `publish-pypi` job downloads only that release's wheel and source
   distribution, validates their names, embedded project/version metadata, and
   SHA-256 values against the release checksums, then uploads them to PyPI.
5. Approve the `pypi` environment deployment if configured, and verify the public
   project/version page and installation before claiming PyPI availability.

The publishing job does not check out or execute package source. It only runs for
this repository's version-tag push or manual dispatch from `main`, never a PR or
feature-branch manual dispatch. Its concurrency group serializes same-tag
publication. `skip-existing` supports retrying an interrupted upload without
replacing existing distributions: PyPI versions/files are immutable. Do not use
that option to claim changed bits have replaced a published version; bump the
version instead. Existing PyPI files are not revalidated against GitHub checksums
by this workflow.

## First Upload of Existing v0.2.0

The published `v0.2.0` tag predates the PyPI job. Merely rerunning its old workflow
run will still use the old definition. After merging the workflow change into
`main`, dispatch the current definition with the existing release tag:

```bash
gh workflow run release.yml \
  --repo rahulbsw/agent-scan \
  --ref main \
  -f tag=v0.2.0 \
  -f pypi_only=true
```

Alternatively, use **Actions > Release > Run workflow**, choose `main`, enter
`v0.2.0`, and enable the PyPI-only input. This mode skips binary/package builds
and GitHub release rewriting, preserving existing release assets and custom
notes. It publishes the already released Python files after checksum/metadata
validation. It does not move or recreate the tag.

The configured publisher must authorize the current `release.yml`; approve the
`pypi` environment if the run waits there. Initial publication will convert the
pending publisher/project configuration into a normal project when accepted.
The PR itself does not upload anything; merge and dispatch are distinct steps.

## Verify and Install

Confirm the intended version exists at
[the PyPI project page](https://pypi.org/project/open-agent-scan/), then test:

```bash
uvx --refresh open-agent-scan@0.2.0 --help
uvx --refresh open-agent-scan@latest --help
```

Until the PyPI upload succeeds and registry/cache propagation completes, keep
using the [explicit GitHub wheel installation](../README.md#install-and-run).
The package metadata name must be `open-agent-scan`; do not substitute unrelated
packages with similar names.

## Failures

- **Pending project / package not found:** configuration exists but no upload has
  completed. Inspect the `publish-pypi` job, not just GitHub release success.
- **OIDC publisher mismatch:** compare the repository, workflow filename and
  environment in PyPI with the job. Do not fix this by sharing account tokens.
- **Awaiting approval:** approve the GitHub `pypi` environment deployment as the
  authorized maintainer.
- **Missing GitHub assets/checksum or metadata mismatch:** fix/review the release
  assets and version; never disable verification to force an upload.
- **Existing version:** published files cannot be overwritten. Verify what is
  already on PyPI and publish a new version when content changes.

Primary documentation: [PyPI publisher configuration](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[publishing via OIDC](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
and the [official PyPA action](https://github.com/pypa/gh-action-pypi-publish).
