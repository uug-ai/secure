# Security Control Register

This register tracks whether important protections are defined, implemented,
and evidenced across UUG.AI products. It is an assessment queue, not a claim of
certification.

Status meanings:

- **Automated**: evidence is collected continuously by a repository workflow.
- **Partial**: implemented or evidenced for only part of the intended scope.
- **To assess**: scope and evidence still require an owner review.
- **Planned**: desired evidence automation has not been implemented.

| Control | Scope and expected evidence | Status | Evidence or next action |
| --- | --- | --- | --- |
| Software inventory | SPDX SBOM for every organization repository, with stale and unavailable sources visible | Automated | [`../sboms/index.json`](../sboms/index.json) |
| Known vulnerabilities | CVE findings correlated to SBOM components and container images, including fix and age | Planned | Add normalized scanner output under [`../cves/`](../cves/) |
| External TLS | Supported TLS versions, certificate ownership, expiry monitoring, and HTTPS enforcement for public endpoints | To assess | Inventory endpoints from deployment and Helm repositories |
| Service and database TLS | Encryption and certificate verification for queues, MongoDB, object storage, and internal APIs | To assess | Record per-service configuration evidence and exceptions |
| Agent RTSPS | TLS-protected RTSP support, certificate validation behavior, defaults, and deployment guidance | To assess | Review the Kerberos Agent RTSPS/TLS implementation and deployment configuration |
| End-to-end encryption | Defined trust boundaries showing where media and metadata are encrypted and where decryption occurs | To assess | Define the intended end-to-end property; transport TLS alone is not end-to-end encryption |
| Encryption at rest | Storage encryption for recordings, databases, backups, and exported evidence, including key ownership | To assess | Document provider and application controls by data class |
| Secrets management | No repository secrets in source; rotation, least privilege, and workload identity where available | To assess | Inventory GitHub, Kubernetes, and cloud secret paths |
| CI and release integrity | Protected branches, pinned actions, artifact provenance, signing, and controlled release identities | Partial | This collector pins actions; assess source repositories and release workflows |
| Container hardening | Minimal trusted images, non-root execution, read-only filesystems where possible, and image scanning | To assess | Extract deployment posture and scan results per image |
| Security testing | Dependency, container, SAST, and secret scanning with documented triage ownership | Partial | Reusable image scanning exists; central evidence export remains planned |
| Risk acceptance | Time-bounded suppressions with owner, rationale, approval, and expiry | Planned | Define a machine-readable exception schema before CVE automation |
| Incident response | Private reporting route, severity model, escalation ownership, and evidence retention | To assess | Assign security owner and document the private response process |

Each assessed control should eventually identify an owner, review date, target
scope, implementation status per repository or product, evidence links, open
gaps, and accepted risks. Prefer generated evidence over manually copied status.