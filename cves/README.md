# Vulnerability Findings

This directory is reserved for normalized CVE and vulnerability findings
derived from the collected SBOMs and container scans.

The next automation should produce:

```text
cves/
  index.json
  <repository>/
    findings.json
```

Each finding should include the repository, package and installed version,
advisory identifier, severity and scoring source, fix availability, first and
last observation times, suppression status, and source scanner. Suppressions
must include an owner, rationale, approval, and expiry date.

Scanner output must be treated as sensitive until reviewed: vulnerability
details can reveal exploitable versions even when no credentials are present.