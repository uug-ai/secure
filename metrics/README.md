# Security Metrics

This directory is reserved for machine-generated organization and repository
metrics. Initial metrics should include:

- SBOM coverage: collected repositories divided by discovered repositories.
- Stale and unavailable SBOM counts.
- Open vulnerabilities by severity and repository.
- Vulnerabilities with a known fix.
- Mean and maximum vulnerability age.
- Expired or soon-to-expire risk acceptances.
- Security-control assessment coverage.

Metrics must identify their generation time, source data, scope, and schema
version. Trends should retain historical snapshots rather than overwriting the
only prior measurement.