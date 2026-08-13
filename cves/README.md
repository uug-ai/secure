# Critical and high vulnerability findings

The container scan workflow replaces this page with a normalized aggregate of
critical and high findings from the latest available Trivy reports.

```text
cves/
  index.json
```

Findings are grouped by advisory identifier. An occurrence is one affected
package record in one image report, so the same advisory can have multiple
occurrences within or across repositories. The index also records the number
of fixable occurrences and the unique affected repositories and package
versions. Medium, low, and unknown findings remain available only in the raw
container reports.

Scanner output must be treated as sensitive until reviewed: vulnerability
details can reveal exploitable versions even when no credentials are present.