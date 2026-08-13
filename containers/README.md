# Container image vulnerability scans

This directory contains Trivy vulnerability reports for the newest tagged
`ghcr.io/uug-ai/<repository>` image available for each project in
[`../sboms/index.json`](../sboms/index.json).

```text
containers/
  index.json
  <repository>/
    status.json
    trivy.json  # Present after a successful scan
```

`index.json` is the authoritative scan inventory. Status values are:

- `scanned`: the newest tagged image was scanned in the current run.
- `stale`: discovery or scanning failed and the last successful report remains.
- `unavailable`: no matching tagged GHCR image or prior report is available.

Images are scanned by immutable digest even though the human-readable tag is
retained in status metadata. The score is deliberately severity-based: 100 for
no detected vulnerabilities, 80 when low is highest, 60 for medium, 30 for
high, and 0 for critical. Counts include both fixable and currently unfixable
findings. A score summarizes triage priority; it is not proof that an image is
secure.

The scanner records all Trivy findings in `trivy.json` and exposes critical,
high, medium, low, unknown, and fixable counts in `status.json`. Reports reflect
the vulnerability database available at scan time and can change even when the
image digest does not.