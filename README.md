# Secure

This repository is the central, auditable inventory of security evidence for
the `uug-ai` organization. It gives security officers and engineering teams one
place to review software composition, known vulnerabilities, security-control
coverage, and trends across projects.

This repository is **public by design** so customers, users, security officers,
and engineering teams can inspect the available evidence. A missing or stale
record is a coverage gap, not proof that a project has no vulnerabilities.
Everything committed here is public information and must be approved for
external disclosure.

## Evidence inventory

| Area | Location | State |
| --- | --- | --- |
| SPDX SBOMs | [`sboms/`](sboms/) | Automated daily |
| SBOM coverage | [`sboms/index.json`](sboms/index.json) | Automated daily |
| CVE findings | [`cves/`](cves/) | Planned |
| Security metrics | [`metrics/`](metrics/) | Planned |
| Protection controls | [`controls/control-register.md`](controls/control-register.md) | Initial assessment register |

<!-- SBOM_QUALITY_START -->
## SBOM quality overview

Generated at `2026-08-13T16:25:58Z`. Quality combines document metadata (20%), package identity (30%), licensing (20%), provenance (15%), and relationships (15%).

Legend: 🟢 85-100, 🟡 70-84, 🟠 50-69, 🔴 0-49 or unavailable. This measures SBOM completeness, not vulnerability severity. The Improve column shows missing SPDX fields and the maximum points each can recover.

| Repository | Collection | Quality | Score | Packages | Versioned | Licensed | PURL | Improve | SBOM |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| [factory](https://github.com/uug-ai/factory) | collected | 🟠 Needs work | 66/100 | 162 | 100% | 64% | 100% | declared licenses 0% (+10); download locations 1% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 64% (+4) | [SPDX](sboms/factory/sbom.spdx.json) |
| [hub-anpr](https://github.com/uug-ai/hub-anpr) | collected | 🟠 Needs work | 68/100 | 52 | 100% | 85% | 100% | declared licenses 2% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-anpr/sbom.spdx.json) |
| [hub-api](https://github.com/uug-ai/hub-api) | collected | 🟠 Needs work | 68/100 | 160 | 100% | 89% | 100% | declared licenses 0% (+10); download locations 1% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 89% (+2) | [SPDX](sboms/hub-api/sbom.spdx.json) |
| [hub-cleanup](https://github.com/uug-ai/hub-cleanup) | collected | 🟠 Needs work | 68/100 | 47 | 100% | 83% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-cleanup/sbom.spdx.json) |
| [hub-frontend](https://github.com/uug-ai/hub-frontend) | collected | 🟠 Needs work | 69/100 | 1225 | 100% | 99% | 100% | declared licenses 0% (+10); download locations 0% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 99% (+1) | [SPDX](sboms/hub-frontend/sbom.spdx.json) |
| [hub-loitering](https://github.com/uug-ai/hub-loitering) | collected | 🟠 Needs work | 68/100 | 49 | 100% | 82% | 100% | declared licenses 2% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 80% (+2) | [SPDX](sboms/hub-loitering/sbom.spdx.json) |
| [hub-monitor-device](https://github.com/uug-ai/hub-monitor-device) | collected | 🟠 Needs work | 68/100 | 79 | 100% | 87% | 100% | declared licenses 0% (+10); download locations 1% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 87% (+2) | [SPDX](sboms/hub-monitor-device/sbom.spdx.json) |
| [hub-objecttracking](https://github.com/uug-ai/hub-objecttracking) | collected | 🟠 Needs work | 67/100 | 35 | 100% | 74% | 100% | declared licenses 3% (+10); download locations 3% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 71% (+3) | [SPDX](sboms/hub-objecttracking/sbom.spdx.json) |
| [hub-pipeline-analysis](https://github.com/uug-ai/hub-pipeline-analysis) | collected | 🟠 Needs work | 68/100 | 63 | 100% | 83% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-pipeline-analysis/sbom.spdx.json) |
| [hub-pipeline-classifier](https://github.com/uug-ai/hub-pipeline-classifier) | collected | 🟠 Needs work | 68/100 | 59 | 100% | 88% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 88% (+2) | [SPDX](sboms/hub-pipeline-classifier/sbom.spdx.json) |
| [hub-pipeline-counting](https://github.com/uug-ai/hub-pipeline-counting) | collected | 🟠 Needs work | 68/100 | 48 | 100% | 81% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 81% (+2) | [SPDX](sboms/hub-pipeline-counting/sbom.spdx.json) |
| [hub-pipeline-dominantcolors](https://github.com/uug-ai/hub-pipeline-dominantcolors) | collected | 🟠 Needs work | 68/100 | 60 | 100% | 88% | 100% | declared licenses 2% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 87% (+2) | [SPDX](sboms/hub-pipeline-dominantcolors/sbom.spdx.json) |
| [hub-pipeline-event](https://github.com/uug-ai/hub-pipeline-event) | collected | 🟠 Needs work | 67/100 | 29 | 100% | 79% | 100% | declared licenses 0% (+10); download locations 3% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 79% (+3) | [SPDX](sboms/hub-pipeline-event/sbom.spdx.json) |
| [hub-pipeline-export](https://github.com/uug-ai/hub-pipeline-export) | collected | 🟠 Needs work | 68/100 | 58 | 100% | 84% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 84% (+2) | [SPDX](sboms/hub-pipeline-export/sbom.spdx.json) |
| [hub-pipeline-monitor](https://github.com/uug-ai/hub-pipeline-monitor) | collected | 🟠 Needs work | 68/100 | 65 | 100% | 86% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 86% (+2) | [SPDX](sboms/hub-pipeline-monitor/sbom.spdx.json) |
| [hub-pipeline-notification](https://github.com/uug-ai/hub-pipeline-notification) | collected | 🟠 Needs work | 68/100 | 95 | 100% | 88% | 100% | declared licenses 0% (+10); download locations 1% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 88% (+2) | [SPDX](sboms/hub-pipeline-notification/sbom.spdx.json) |
| [hub-pipeline-notification-test](https://github.com/uug-ai/hub-pipeline-notification-test) | collected | 🟠 Needs work | 68/100 | 65 | 100% | 83% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-pipeline-notification-test/sbom.spdx.json) |
| [hub-pipeline-redaction](https://github.com/uug-ai/hub-pipeline-redaction) | collected | 🟠 Needs work | 68/100 | 49 | 100% | 86% | 100% | declared licenses 2% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 84% (+2) | [SPDX](sboms/hub-pipeline-redaction/sbom.spdx.json) |
| [hub-pipeline-sequence](https://github.com/uug-ai/hub-pipeline-sequence) | collected | 🟠 Needs work | 68/100 | 60 | 100% | 85% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 85% (+2) | [SPDX](sboms/hub-pipeline-sequence/sbom.spdx.json) |
| [hub-pipeline-sprite](https://github.com/uug-ai/hub-pipeline-sprite) | collected | 🟠 Needs work | 68/100 | 58 | 100% | 83% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-pipeline-sprite/sbom.spdx.json) |
| [hub-pipeline-throttler](https://github.com/uug-ai/hub-pipeline-throttler) | collected | 🟠 Needs work | 68/100 | 53 | 100% | 83% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 83% (+2) | [SPDX](sboms/hub-pipeline-throttler/sbom.spdx.json) |
| [hub-pipeline-thumbnail](https://github.com/uug-ai/hub-pipeline-thumbnail) | collected | 🟠 Needs work | 68/100 | 61 | 100% | 85% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 85% (+2) | [SPDX](sboms/hub-pipeline-thumbnail/sbom.spdx.json) |
| [hub-proxy](https://github.com/uug-ai/hub-proxy) | collected | 🟠 Needs work | 65/100 | 26 | 100% | 58% | 100% | declared licenses 0% (+10); download locations 4% (+8); suppliers 0% (+7); concluded licenses 58% (+5); document describes 0% (+5) | [SPDX](sboms/hub-proxy/sbom.spdx.json) |
| [hub-reactivatesubscriptions](https://github.com/uug-ai/hub-reactivatesubscriptions) | collected | 🟠 Needs work | 67/100 | 63 | 100% | 78% | 100% | declared licenses 0% (+10); download locations 2% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 78% (+3) | [SPDX](sboms/hub-reactivatesubscriptions/sbom.spdx.json) |
| [hub-vault-forwarder](https://github.com/uug-ai/hub-vault-forwarder) | collected | 🟠 Needs work | 69/100 | 8 | 100% | 88% | 100% | declared licenses 0% (+10); suppliers 0% (+7); download locations 13% (+7); document describes 0% (+5); concluded licenses 88% (+2) | [SPDX](sboms/hub-vault-forwarder/sbom.spdx.json) |
| [hub-workflows](https://github.com/uug-ai/hub-workflows) | collected | 🟠 Needs work | 68/100 | 85 | 100% | 88% | 100% | declared licenses 1% (+10); download locations 1% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 87% (+2) | [SPDX](sboms/hub-workflows/sbom.spdx.json) |
| [vault](https://github.com/uug-ai/vault) | collected | 🟠 Needs work | 69/100 | 1654 | 100% | 99% | 100% | declared licenses 0% (+10); download locations 0% (+8); suppliers 0% (+7); document describes 0% (+5); concluded licenses 99% (+1) | [SPDX](sboms/vault/sbom.spdx.json) |
<!-- SBOM_QUALITY_END -->

## SBOM collection

The [Collect product SBOMs](.github/workflows/collect-sboms.yml) workflow
runs daily at 02:17 UTC and can also be started manually. It:

1. Lists repositories visible to the read-only organization token and selects
   names beginning with `hub` plus the exact `factory` and `vault` repositories,
   except repositories explicitly excluded after retirement.
2. Downloads each selected repository's SPDX SBOM from GitHub's Dependency
   Graph API.
3. Writes collection metadata to `sboms/<repository>/status.json` and, when
   available, the document to `sboms/<repository>/sbom.spdx.json`.
4. Scores document metadata, package identity, licensing, provenance, and SPDX
   relationships, then updates the quality table above.
5. Updates `sboms/index.json` with collection status, quality metrics, and
   coverage totals.
6. Preserves the last successful document and marks it `stale` when a refresh
   fails.
7. Commits changed evidence with the repository-scoped GitHub Actions token.
   Rejected non-fast-forward pushes are rebased onto the latest `main` and
   retried up to three times.

The collector ignores every repository outside `hub*`, `factory`, and `vault`.
It also excludes the retired `hub-background-notifcation-digest`, `hub-license`,
`hub-mobile`, `hub-pipeline`, `hub-pipeline-classifier-yolov3`, and
`hub-pipeline-licenseplate` repositories. When the scope changes, generated
directories and index entries that are no longer selected are removed during
the next successful collection. Archived or private target repositories are
included when visible to the token, so grant private access only when the
repository name and SBOM are approved for public disclosure.

### Improving an orange score

Orange means the SPDX document is 50-69% complete under this repository's
quality rubric. It does not indicate known vulnerabilities. The Improve column
shows current field coverage and the maximum points available, ordered by
impact. For example, `declared licenses 0% (+10)` means no package has a
declared license and completing that field can add up to 10 points.

Version, PURL, and declared-license gaps can often be improved by committing
complete supported dependency manifests and lock files and by fixing package
metadata upstream. Concluded licenses require license analysis or review.
Supplier, download-location, and document-describes gaps are commonly omitted
by GitHub's Dependency Graph SBOM endpoint and generally require an enriched
SPDX generator or a controlled post-processing step; they cannot necessarily
be fixed in the affected application's source repository.

### Required setup

Grant the existing `TOKEN` organization secret to this repository. The workflow
uses it only to read organization repositories and their SBOMs. The token should
ideally be owned by a dedicated automation account and limited to:

- Repository access to the `hub*`, `factory`, and `vault` repositories whose
   SBOMs are approved for public disclosure.
- `Contents: read` repository permission; metadata read access is implicit.
- No write permissions.

An existing token with broader permissions will work, but reducing it to these
permissions limits the impact of accidental exposure or workflow compromise.

The repository's Actions settings must allow `GITHUB_TOKEN` to write contents so
the workflow can push refreshed evidence. If `main` is protected against direct
pushes, grant the security bot an appropriate bypass or change the final step to
open a pull request.

GitHub Dependency Graph must be enabled for each target repository. Target
repositories where it is disabled or inaccessible remain visible in the index
as `unavailable` rather than silently disappearing.

## Trust model

- The evidence repository is public to provide transparent, reviewable security
   information.
- Cross-repository credentials are read-only and scoped to collection.
- Generated records retain their source repository and API endpoint.
- Workflow actions are pinned to immutable commit SHAs.
- Collection errors are evidence and remain visible in the coverage index.
- Changes to controls and manually maintained assessments require review.

Do not store credentials, private repository evidence that has not been approved
for disclosure, exploit details, customer data, or confidential incident
material in this repository. Use the approved private incident process for
sensitive operational information.

## Development

The collector uses only the Go standard library.

```bash
GOWORK=off go test ./...
GH_TOKEN=<read-only-token> GOWORK=off go run ./cmd/collect-sboms
GOWORK=off go run ./cmd/collect-sboms -refresh-existing
```
