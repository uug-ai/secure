package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakePackageAPI struct {
	versions map[string][]packageVersion
	errors   map[string]error
}

func (api *fakePackageAPI) ListPackageVersions(_, name string) ([]packageVersion, error) {
	return api.versions[name], api.errors[name]
}

type fakeScanner struct {
	reports map[string][]byte
	errors  map[string]error
	images  []string
}

func (scanner *fakeScanner) Scan(image string) ([]byte, error) {
	scanner.images = append(scanner.images, image)
	return scanner.reports[image], scanner.errors[image]
}

func testPackageVersion(digest string, tags ...string) packageVersion {
	version := packageVersion{Name: digest, HTMLURL: "https://github.com/orgs/uug-ai/packages/container/test"}
	version.Metadata.Container.Tags = tags
	return version
}

func testTrivyReport(vulnerabilities ...map[string]string) []byte {
	report := map[string]any{
		"ArtifactName": "ghcr.io/uug-ai/vault@sha256:abc",
		"Results":      []any{map[string]any{"Vulnerabilities": vulnerabilities}},
	}
	data, _ := json.Marshal(report)
	return data
}

func writeInventory(t *testing.T, directory string, names ...string) string {
	t.Helper()
	repositories := make([]map[string]string, 0, len(names))
	for _, name := range names {
		repositories = append(repositories, map[string]string{
			"name":          name,
			"repositoryUrl": "https://github.com/uug-ai/" + name,
		})
	}
	path := filepath.Join(directory, "sboms", "index.json")
	if err := writeJSON(path, map[string]any{"repositories": repositories}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSelectPackageVersionUsesNewestTaggedVersion(t *testing.T) {
	versions := []packageVersion{
		testPackageVersion("sha256:untagged"),
		testPackageVersion("sha256:newest", "v1.2.0", "latest"),
		testPackageVersion("sha256:older", "v1.1.0"),
	}
	version, tag, found := selectPackageVersion(versions)
	if !found || version.Name != "sha256:newest" || tag != "latest" {
		t.Fatalf("unexpected selected version: %+v tag=%q found=%t", version, tag, found)
	}
}

func TestAssessReportScoresHighestSeverity(t *testing.T) {
	tests := []struct {
		name   string
		report []byte
		score  int
		rating string
	}{
		{name: "clean", report: testTrivyReport(), score: 100, rating: "Clean"},
		{name: "low", report: testTrivyReport(map[string]string{"Severity": "LOW"}), score: 80, rating: "Low"},
		{name: "medium", report: testTrivyReport(map[string]string{"Severity": "MEDIUM"}), score: 60, rating: "Medium"},
		{name: "high", report: testTrivyReport(map[string]string{"Severity": "HIGH"}), score: 30, rating: "High"},
		{name: "critical", report: testTrivyReport(map[string]string{"Severity": "CRITICAL", "FixedVersion": "1.2.3"}), score: 0, rating: "Critical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vulnerabilities, fixable, score, rating, err := assessReport(test.report)
			if err != nil {
				t.Fatal(err)
			}
			if score != test.score || rating != test.rating {
				t.Fatalf("score=%d rating=%q, want %d %q", score, rating, test.score, test.rating)
			}
			if test.rating == "Critical" && (vulnerabilities.Critical != 1 || fixable.Critical != 1) {
				t.Fatalf("unexpected critical counts: vulnerabilities=%+v fixable=%+v", vulnerabilities, fixable)
			}
		})
	}
}

func TestAggregateCVEsCountsOnlyCriticalAndHighFindings(t *testing.T) {
	reports := map[string][]byte{
		"hub-api": testTrivyReport(
			map[string]string{"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "3.0.0", "FixedVersion": "3.0.1"},
			map[string]string{"VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL", "PkgName": "libc", "InstalledVersion": "1.0.0"},
			map[string]string{"VulnerabilityID": "CVE-2026-0003", "Severity": "MEDIUM", "PkgName": "ignored"},
		),
		"vault": testTrivyReport(
			map[string]string{"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "3.0.0"},
		),
	}

	index, err := aggregateCVEs(reports, "2026-08-13T20:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Totals != (cveTotals{Critical: 1, Findings: 2, High: 1, Occurrences: 3}) {
		t.Fatalf("unexpected totals: %+v", index.Totals)
	}
	if index.Findings[0].ID != "CVE-2026-0001" || index.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("critical finding was not ordered first: %+v", index.Findings)
	}
	high := index.Findings[1]
	if high.ID != "CVE-2026-0002" || high.Occurrences != 2 || high.FixableOccurrences != 1 {
		t.Fatalf("unexpected aggregated high finding: %+v", high)
	}
	if strings.Join(high.Repositories, ",") != "hub-api,vault" || strings.Join(high.Packages, ",") != "openssl@3.0.0" {
		t.Fatalf("unexpected affected scope: %+v", high)
	}
}

func TestWriteCVEEvidenceUsesScannedAndStaleReports(t *testing.T) {
	root := t.TempDir()
	containerDirectory := filepath.Join(root, "containers")
	cveDirectory := filepath.Join(root, "cves")
	for repository, report := range map[string][]byte{
		"hub-api": testTrivyReport(map[string]string{"VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL", "PkgName": "libc", "InstalledVersion": "1.0.0", "PrimaryURL": "https://example.com/CVE-2026-0001"}),
		"vault":   testTrivyReport(map[string]string{"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "3.0.0", "FixedVersion": "3.0.1"}),
	} {
		if err := writeJSON(filepath.Join(containerDirectory, repository, "trivy.json"), json.RawMessage(report)); err != nil {
			t.Fatal(err)
		}
	}
	scan := scanIndex{
		GeneratedAt: "2026-08-13T20:00:00Z",
		Repositories: []scanEntry{
			{Name: "hub-api", ReportPath: "hub-api/trivy.json", Status: "scanned"},
			{Name: "vault", ReportPath: "vault/trivy.json", Status: "stale"},
			{Name: "factory", Status: "unavailable"},
		},
	}

	index, err := writeCVEEvidence(scan, containerDirectory, cveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if index.Totals.Findings != 2 || index.Totals.Occurrences != 2 {
		t.Fatalf("unexpected CVE index: %+v", index)
	}
	readme, err := os.ReadFile(filepath.Join(cveDirectory, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"2 unique findings", "CVE-2026-0001", "CRITICAL", "CVE-2026-0002", "HIGH", "| 1 |"} {
		if !strings.Contains(string(readme), expected) {
			t.Fatalf("CVE README does not contain %q:\n%s", expected, readme)
		}
	}
	var persisted cveIndex
	if err := loadJSON(filepath.Join(cveDirectory, "index.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Totals != index.Totals {
		t.Fatalf("persisted totals differ: %+v != %+v", persisted.Totals, index.Totals)
	}
}

func TestCollectScansReportsAvailableAndUnavailableImages(t *testing.T) {
	root := t.TempDir()
	inventoryPath := writeInventory(t, root, "hub-api", "vault")
	output := filepath.Join(root, "containers")
	image := "ghcr.io/uug-ai/hub-api@sha256:api"
	api := &fakePackageAPI{
		versions: map[string][]packageVersion{"hub-api": {testPackageVersion("sha256:api", "v1.0.0")}},
		errors:   map[string]error{"vault": errPackageNotFound},
	}
	scanner := &fakeScanner{
		reports: map[string][]byte{image: testTrivyReport(map[string]string{"Severity": "HIGH", "FixedVersion": "1.0.1"})},
		errors:  map[string]error{},
	}

	index, err := collectScans(api, scanner, inventoryPath, output, "uug-ai", "2026-08-13T20:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Totals.Repositories != 2 || index.Totals.Scanned != 1 || index.Totals.Unavailable != 1 || index.Totals.High != 1 {
		t.Fatalf("unexpected totals: %+v", index.Totals)
	}
	if len(scanner.images) != 1 || scanner.images[0] != image {
		t.Fatalf("unexpected scanned images: %+v", scanner.images)
	}
	if _, err := os.Stat(filepath.Join(output, "hub-api", "trivy.json")); err != nil {
		t.Fatal(err)
	}
	var unavailable scanEntry
	if err := loadJSON(filepath.Join(output, "vault", "status.json"), &unavailable); err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != "unavailable" || unavailable.Error == "" {
		t.Fatalf("unexpected unavailable status: %+v", unavailable)
	}
}

func TestCollectScansPreservesPreviousReportOnScanFailure(t *testing.T) {
	root := t.TempDir()
	inventoryPath := writeInventory(t, root, "vault")
	output := filepath.Join(root, "containers")
	previous := scanEntry{
		Name: "vault", ReportPath: "vault/trivy.json", Rating: "Clean", Score: 100,
		ScannedAt: "2026-08-12T20:00:00Z", Status: "scanned",
	}
	if err := writeJSON(filepath.Join(output, "index.json"), scanIndex{Repositories: []scanEntry{previous}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(output, "vault", "trivy.json"), map[string]any{"Results": []any{}}); err != nil {
		t.Fatal(err)
	}
	image := "ghcr.io/uug-ai/vault@sha256:vault"
	api := &fakePackageAPI{versions: map[string][]packageVersion{"vault": {testPackageVersion("sha256:vault", "v1.0.0")}}, errors: map[string]error{}}
	scanner := &fakeScanner{reports: map[string][]byte{}, errors: map[string]error{image: errors.New("registry timeout")}}

	index, err := collectScans(api, scanner, inventoryPath, output, "uug-ai", "2026-08-13T20:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	entry := index.Repositories[0]
	if entry.Status != "stale" || entry.ScannedAt != previous.ScannedAt || entry.Error == "" {
		t.Fatalf("unexpected stale entry: %+v", entry)
	}
	if _, err := os.Stat(filepath.Join(output, "vault", "trivy.json")); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateREADMEReplacesContainerSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "README.md")
	if err := os.WriteFile(path, []byte("# Secure\n\nManual content.\n\n<!-- SBOM_QUALITY_START -->\nSBOM\n<!-- SBOM_QUALITY_END -->\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	index := scanIndex{
		GeneratedAt: "2026-08-13T20:00:00Z",
		Repositories: []scanEntry{{
			Name: "vault", RepositoryURL: "https://github.com/uug-ai/vault", Status: "scanned",
			Rating: "High", Score: 30, Tag: "v1.0.0", ReportPath: "vault/trivy.json",
			Vulnerabilities: severityCounts{High: 2}, Fixable: severityCounts{High: 1},
		}},
	}
	if err := updateREADME(path, index); err != nil {
		t.Fatal(err)
	}
	if err := updateREADME(path, index); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Count(content, containerStartMarker) != 1 || strings.Count(content, containerEndMarker) != 1 {
		t.Fatalf("container markers were duplicated:\n%s", content)
	}
	for _, expected := range []string{"Manual content.", "30/100", "v1.0.0", "[Trivy](containers/vault/trivy.json)", "SBOM"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("README does not contain %q:\n%s", expected, content)
		}
	}
}
