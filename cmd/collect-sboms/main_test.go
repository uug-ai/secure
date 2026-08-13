package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGitHubClient struct {
	repositories []repository
	sboms        map[string]json.RawMessage
	errors       map[string]error
}

func (client *fakeGitHubClient) ListOrganizationRepositories(string) ([]repository, error) {
	return client.repositories, nil
}

func (client *fakeGitHubClient) GetRepositorySBOM(_, repository string) (json.RawMessage, error) {
	if err := client.errors[repository]; err != nil {
		return nil, err
	}
	return client.sboms[repository], nil
}

func testRepository(name string) repository {
	return repository{
		DefaultBranch: "main",
		HTMLURL:       "https://github.com/uug-ai/" + name,
		Name:          name,
		Private:       true,
		Visibility:    "private",
	}
}

func TestCollectsOnlyTargetRepositories(t *testing.T) {
	client := &fakeGitHubClient{
		repositories: []repository{
			testRepository("secure"),
			testRepository("cli"),
			testRepository("factory"),
			testRepository("hub-api"),
			testRepository("hub-mobile"),
			testRepository("vault"),
		},
		sboms: map[string]json.RawMessage{
			"factory": json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
			"hub-api": json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
			"vault":   json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
		},
		errors: map[string]error{},
	}
	output := t.TempDir()
	if err := os.Mkdir(filepath.Join(output, "cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "cli", "sbom.spdx.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := collectSBOMs(client, "uug-ai", output, defaultExcludedRepositories(), "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Totals.Repositories != 3 {
		t.Fatalf("unexpected index: %+v", index)
	}
	for indexPosition, expectedName := range []string{"factory", "hub-api", "vault"} {
		entry := index.Repositories[indexPosition]
		if entry.Name != expectedName || entry.Status != "collected" {
			t.Fatalf("unexpected entry at %d: %+v", indexPosition, entry)
		}
		if _, err := os.Stat(filepath.Join(output, expectedName, "sbom.spdx.json")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "cli")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-target repository directory was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(output, "hub-mobile")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excluded repository directory was not removed: %v", err)
	}
}

func TestTargetRepositoryScope(t *testing.T) {
	tests := map[string]bool{
		"factory":      true,
		"hub":          true,
		"hub-api":      true,
		"Hub-Frontend": true,
		"vault":        true,
		"agent":        false,
		"secure":       false,
		"website":      false,
	}
	for repository, expected := range tests {
		if actual := isTargetRepository(repository); actual != expected {
			t.Errorf("isTargetRepository(%q) = %t, want %t", repository, actual, expected)
		}
	}
}

func TestDefaultExcludedRepositories(t *testing.T) {
	excluded := defaultExcludedRepositories()
	for _, repository := range []string{
		"hub-background-notifcation-digest",
		"hub-license",
		"hub-mobile",
		"hub-pipeline",
		"hub-pipeline-classifier-yolov3",
		"hub-pipeline-licenseplate",
	} {
		if !excluded[repository] {
			t.Errorf("default exclusions do not contain %q", repository)
		}
	}
}

func TestPreservesPreviousSBOMWhenRefreshFails(t *testing.T) {
	client := &fakeGitHubClient{
		repositories: []repository{testRepository("vault")},
		sboms:        map[string]json.RawMessage{},
		errors:       map[string]error{"vault": errors.New("dependency graph disabled")},
	}
	output := t.TempDir()
	if err := os.Mkdir(filepath.Join(output, "vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "vault", "sbom.spdx.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := sbomIndex{Repositories: []indexEntry{{Name: "vault", CollectedAt: "2026-08-12T10:00:00Z"}}}
	if err := writeJSON(filepath.Join(output, "index.json"), previous); err != nil {
		t.Fatal(err)
	}

	index, err := collectSBOMs(client, "uug-ai", output, stringSet{"secure": true}, "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	entry := index.Repositories[0]
	if entry.Status != "stale" || entry.CollectedAt != "2026-08-12T10:00:00Z" {
		t.Fatalf("unexpected stale entry: %+v", entry)
	}
	if _, err := os.Stat(filepath.Join(output, "vault", "sbom.spdx.json")); err != nil {
		t.Fatal(err)
	}
}

func TestMarksFirstCollectionFailureAsUnavailable(t *testing.T) {
	client := &fakeGitHubClient{
		repositories: []repository{testRepository("vault")},
		sboms:        map[string]json.RawMessage{},
		errors:       map[string]error{"vault": errors.New("dependency graph disabled")},
	}
	output := t.TempDir()

	index, err := collectSBOMs(client, "uug-ai", output, stringSet{"secure": true}, "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Repositories[0].Status != "unavailable" || index.Totals.Unavailable != 1 {
		t.Fatalf("unexpected unavailable entry: %+v", index)
	}
	statusPath := filepath.Join(output, "vault", "status.json")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	var status indexEntry
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.Name != "vault" || status.Status != "unavailable" || status.Error == "" {
		t.Fatalf("unexpected persisted status: %+v", status)
	}
}

func TestAssessSBOMQuality(t *testing.T) {
	document := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"dataLicense":"CC0-1.0",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"vault",
		"documentNamespace":"https://example.com/vault",
		"creationInfo":{"created":"2026-08-13T10:00:00Z","creators":["Tool: test"]},
		"documentDescribes":["SPDXRef-Package"],
		"relationships":[{"relationshipType":"DESCRIBES"}],
		"packages":[{
			"name":"module",
			"SPDXID":"SPDXRef-Package",
			"versionInfo":"v1.0.0",
			"licenseDeclared":"MIT",
			"licenseConcluded":"MIT",
			"supplier":"Organization: UUG.AI",
			"downloadLocation":"https://github.com/uug-ai/vault",
			"externalRefs":[{"referenceType":"purl"}]
		}]
	}`)

	quality, err := assessSBOM(document)
	if err != nil {
		t.Fatal(err)
	}
	if quality.Score != 100 || quality.Rating != "Excellent" {
		t.Fatalf("unexpected quality: %+v", quality)
	}
	if quality.VersionedPercent != 100 || quality.LicensedPercent != 100 || quality.PURLPercent != 100 {
		t.Fatalf("unexpected package coverage: %+v", quality)
	}
	if len(quality.Improvements) != 0 {
		t.Fatalf("complete SBOM has improvements: %+v", quality.Improvements)
	}
}

func TestAssessSBOMExplainsQualityImprovements(t *testing.T) {
	document := []byte(`{
		"spdxVersion":"SPDX-2.3",
		"dataLicense":"CC0-1.0",
		"documentNamespace":"https://example.com/vault",
		"creationInfo":{"created":"2026-08-13T10:00:00Z","creators":["Tool: test"]},
		"relationships":[{"relationshipType":"DEPENDS_ON"}],
		"packages":[{
			"name":"module",
			"SPDXID":"SPDXRef-Package",
			"versionInfo":"v1.0.0",
			"licenseDeclared":"MIT",
			"externalRefs":[{"referenceType":"purl"}]
		}]
	}`)

	quality, err := assessSBOM(document)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"concluded licenses 0% (+10)",
		"download locations 0% (+8)",
		"suppliers 0% (+7)",
		"document describes 0% (+5)",
	}
	if strings.Join(quality.Improvements, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected improvements: %+v", quality.Improvements)
	}
}

func TestQualityIndicatorColors(t *testing.T) {
	tests := []struct {
		quality  *sbomQuality
		expected string
	}{
		{quality: nil, expected: "🔴 Unavailable"},
		{quality: &sbomQuality{Rating: "Poor"}, expected: "🔴 Poor"},
		{quality: &sbomQuality{Rating: "Needs work"}, expected: "🟠 Needs work"},
		{quality: &sbomQuality{Rating: "Good"}, expected: "🟡 Good"},
		{quality: &sbomQuality{Rating: "Excellent"}, expected: "🟢 Excellent"},
	}
	for _, test := range tests {
		if actual := qualityIndicator(test.quality); actual != test.expected {
			t.Errorf("qualityIndicator(%+v) = %q, want %q", test.quality, actual, test.expected)
		}
	}
}

func TestUpdateREADMECreatesAndReplacesQualityTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "README.md")
	if err := os.WriteFile(path, []byte("# Secure\n\nManual content.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	quality := &sbomQuality{Score: 90, Rating: "Excellent", PackageCount: 4, VersionedPercent: 100, LicensedPercent: 75, PURLPercent: 100, Improvements: []string{"concluded licenses 0% (+10)"}}
	index := sbomIndex{
		GeneratedAt: "2026-08-13T10:00:00Z",
		Repositories: []indexEntry{{
			Name: "vault", RepositoryURL: "https://github.com/uug-ai/vault", Status: "collected", Path: "vault/sbom.spdx.json", Quality: quality,
		}},
	}

	if err := updateREADME(path, index); err != nil {
		t.Fatal(err)
	}
	index.GeneratedAt = "2026-08-14T10:00:00Z"
	if err := updateREADME(path, index); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Count(content, qualityStartMarker) != 1 || strings.Count(content, qualityEndMarker) != 1 {
		t.Fatalf("quality markers were duplicated:\n%s", content)
	}
	for _, expected := range []string{"Manual content.", "🟢 Excellent", "90/100", "concluded licenses 0% (+10)", "[SPDX](sboms/vault/sbom.spdx.json)", "2026-08-14T10:00:00Z"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("README does not contain %q:\n%s", expected, content)
		}
	}
}

func TestRefreshExistingSBOMsReassessesAndRemovesExcludedRepositories(t *testing.T) {
	output := t.TempDir()
	document := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"documentNamespace": "https://example.com/vault",
		"creationInfo": map[string]any{
			"created":  "2026-08-13T10:00:00Z",
			"creators": []string{"Tool: test"},
		},
		"packages": []any{},
	}
	if err := writeJSON(filepath.Join(output, "vault", "sbom.spdx.json"), document); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(output, "hub-mobile", "sbom.spdx.json"), document); err != nil {
		t.Fatal(err)
	}
	index := sbomIndex{
		GeneratedAt:  "2026-08-13T10:00:00Z",
		Organization: "uug-ai",
		Repositories: []indexEntry{
			{Name: "hub-mobile", Path: "hub-mobile/sbom.spdx.json", Status: "collected"},
			{Name: "vault", Path: "vault/sbom.spdx.json", Status: "collected"},
		},
	}
	if err := writeJSON(filepath.Join(output, "index.json"), index); err != nil {
		t.Fatal(err)
	}

	refreshed, err := refreshExistingSBOMs(output, defaultExcludedRepositories())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.GeneratedAt != index.GeneratedAt || refreshed.Totals.Repositories != 1 || refreshed.Repositories[0].Name != "vault" {
		t.Fatalf("unexpected refreshed index: %+v", refreshed)
	}
	if refreshed.Repositories[0].Quality == nil || len(refreshed.Repositories[0].Quality.Improvements) == 0 {
		t.Fatalf("SBOM quality was not reassessed: %+v", refreshed.Repositories[0])
	}
	if _, err := os.Stat(filepath.Join(output, "hub-mobile")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excluded SBOM directory was not removed: %v", err)
	}
}
