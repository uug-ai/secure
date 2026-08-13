package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func TestCollectsSBOMAndExcludesSecureRepository(t *testing.T) {
	client := &fakeGitHubClient{
		repositories: []repository{testRepository("secure"), testRepository("vault")},
		sboms: map[string]json.RawMessage{
			"vault": json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
		},
		errors: map[string]error{},
	}
	output := t.TempDir()

	index, err := collectSBOMs(client, "uug-ai", output, stringSet{"secure": true}, "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Totals.Repositories != 1 || index.Repositories[0].Status != "collected" {
		t.Fatalf("unexpected index: %+v", index)
	}
	data, err := os.ReadFile(filepath.Join(output, "vault", "sbom.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("unexpected SPDX version: %v", document["spdxVersion"])
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

	index, err := collectSBOMs(client, "uug-ai", t.TempDir(), stringSet{"secure": true}, "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if index.Repositories[0].Status != "unavailable" || index.Totals.Unavailable != 1 {
		t.Fatalf("unexpected unavailable entry: %+v", index)
	}
}
