# Secure

This repository is the central, auditable inventory of security evidence for
the `uug-ai` organization. It gives security officers and engineering teams one
place to review software composition, known vulnerabilities, security-control
coverage, and trends across projects.

This repository contains evidence and assessment status. A missing or stale
record is a coverage gap, not proof that a project has no vulnerabilities.

Keep this repository **private** and limit access to authorized security and
engineering personnel. SBOMs and findings reveal private repository names,
component versions, and potentially exploitable software inventory.

## Evidence inventory

| Area | Location | State |
| --- | --- | --- |
| SPDX SBOMs | [`sboms/`](sboms/) | Automated daily |
| SBOM coverage | [`sboms/index.json`](sboms/index.json) | Automated daily |
| CVE findings | [`cves/`](cves/) | Planned |
| Security metrics | [`metrics/`](metrics/) | Planned |
| Protection controls | [`controls/control-register.md`](controls/control-register.md) | Initial assessment register |

## SBOM collection

The [Collect organization SBOMs](.github/workflows/collect-sboms.yml) workflow
runs daily at 02:17 UTC and can also be started manually. It:

1. Lists all repositories visible to the read-only organization token.
2. Downloads each repository's SPDX SBOM from GitHub's Dependency Graph API.
3. Writes the document to `sboms/<repository>/sbom.spdx.json`.
4. Updates `sboms/index.json` with collection status and coverage totals.
5. Preserves the last successful document and marks it `stale` when a refresh
   fails.
6. Commits changed evidence with the repository-scoped GitHub Actions token.

The `secure` repository itself is excluded to avoid collecting the collector.
Archived and private repositories are included when the token can see them.

### Required setup

Grant the existing `TOKEN` organization secret to this repository. The workflow
uses it only to read organization repositories and their SBOMs. The token should
ideally be owned by a dedicated automation account and limited to:

- Repository access to all repositories in the `uug-ai` organization.
- `Contents: read` repository permission; metadata read access is implicit.
- No write permissions.

An existing token with broader permissions will work, but reducing it to these
permissions limits the impact of accidental exposure or workflow compromise.

The repository's Actions settings must allow `GITHUB_TOKEN` to write contents so
the workflow can push refreshed evidence. If `main` is protected against direct
pushes, grant the security bot an appropriate bypass or change the final step to
open a pull request.

GitHub Dependency Graph must be enabled for each source repository. Repositories
where it is disabled or inaccessible remain visible in the index as
`unavailable` rather than silently disappearing.

## Trust model

- The evidence repository is private and access is reviewed regularly.
- Cross-repository credentials are read-only and scoped to collection.
- Generated records retain their source repository and API endpoint.
- Workflow actions are pinned to immutable commit SHAs.
- Collection errors are evidence and remain visible in the coverage index.
- Changes to controls and manually maintained assessments require review.

Do not store credentials, exploit details, customer data, or other confidential
incident material in this repository. Use the approved private incident process
for sensitive operational information.

## Development

The collector uses only the Go standard library.

```bash
GOWORK=off go test ./...
GH_TOKEN=<read-only-token> GOWORK=off go run ./cmd/collect-sboms
```
