package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRegistry struct {
	licenses  map[string]string
	downloads map[string]string
	err       error
}

func (registry *fakeRegistry) DeclaredLicense(system, name, version string) (string, error) {
	if registry.err != nil {
		return "", registry.err
	}
	return registry.licenses[system+" "+name+" "+version], nil
}

func (registry *fakeRegistry) PyPIDownloadLocation(name, version string) (string, error) {
	if registry.err != nil {
		return "", registry.err
	}
	return registry.downloads[name+" "+version], nil
}

func testPackage(purl string, fields map[string]any) map[string]any {
	pkg := map[string]any{
		"name":             purl,
		"downloadLocation": "NOASSERTION",
		"externalRefs": []any{map[string]any{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceLocator":  purl,
			"referenceType":     "purl",
		}},
	}
	for key, value := range fields {
		pkg[key] = value
	}
	return pkg
}

func TestParsePackageURL(t *testing.T) {
	tests := map[string]packageURL{
		"pkg:golang/github.com/aws/aws-sdk-go@v1.55.8": {
			Type: "golang", Namespace: "github.com/aws", Name: "aws-sdk-go", Version: "v1.55.8",
		},
		"pkg:npm/%40angular/core@17.3.12?arch=x64#lib": {
			Type: "npm", Namespace: "@angular", Name: "core", Version: "17.3.12",
		},
		"pkg:githubactions/actions/checkout@4.%2A.%2A": {
			Type: "githubactions", Namespace: "actions", Name: "checkout", Version: "4.*.*",
		},
		"pkg:PyPI/numpy": {Type: "pypi", Name: "numpy"},
	}
	for value, expected := range tests {
		actual, ok := parsePackageURL(value)
		if !ok || actual != expected {
			t.Errorf("parsePackageURL(%q) = %+v, %t; want %+v", value, actual, ok, expected)
		}
	}
	for _, value := range []string{"", "npm/lodash@4.17.21", "pkg:npm", "pkg:npm/%zz@1.0.0"} {
		if _, ok := parsePackageURL(value); ok {
			t.Errorf("parsePackageURL(%q) accepted an invalid package URL", value)
		}
	}
}

func TestDownloadLocationFromPackageURL(t *testing.T) {
	registry := &fakeRegistry{downloads: map[string]string{
		"requests 2.32.3": "https://files.pythonhosted.org/packages/source/requests-2.32.3.tar.gz",
	}}
	tests := map[string]string{
		"pkg:golang/github.com/aws/aws-sdk-go@v1.55.8":                                         "https://proxy.golang.org/github.com/aws/aws-sdk-go/@v/v1.55.8.zip",
		"pkg:golang/github.com/BurntSushi/toml@1.4.0":                                          "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip",
		"pkg:golang/github.com/golang-jwt/jwt@3.2.2%2Bincompatible":                            "https://proxy.golang.org/github.com/golang-jwt/jwt/@v/v3.2.2+incompatible.zip",
		"pkg:golang/github.com/uug-ai/models@v1.2.0":                                           "git+https://github.com/uug-ai/models@v1.2.0",
		"pkg:golang/github.com/uug-ai/trace/v2@v2.0.0-20250101120000-0123456789ab":             "git+https://github.com/uug-ai/trace@0123456789ab",
		"pkg:golang/github.com/uug-ai/models/internal/sub@v1.0.0":                              "",
		"pkg:npm/lodash@4.17.21":                                                               "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		"pkg:npm/%40angular/core@17.3.12":                                                      "https://registry.npmjs.org/@angular/core/-/core-17.3.12.tgz",
		"pkg:npm/axios@%5E1.6.0":                                                               "",
		"pkg:githubactions/actions/checkout@4.%2A.%2A":                                         "git+https://github.com/actions/checkout",
		"pkg:githubactions/aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1": "git+https://github.com/aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
		"pkg:githubactions/uug-ai/workflows/.github/workflows/pr-build.yml@main":               "git+https://github.com/uug-ai/workflows@main#.github/workflows/pr-build.yml",
		"pkg:pypi/requests@2.32.3":                                                             "https://files.pythonhosted.org/packages/source/requests-2.32.3.tar.gz",
		"pkg:pypi/requests@%3E%3D2.0":                                                          "",
		"pkg:maven/org.apache/commons@1.0.0":                                                   "",
	}
	for value, expected := range tests {
		purl, ok := parsePackageURL(value)
		if !ok {
			t.Fatalf("parsePackageURL(%q) failed", value)
		}
		actual, err := downloadLocation("uug-ai", purl, registry)
		if err != nil || actual != expected {
			t.Errorf("downloadLocation(%q) = %q, %v; want %q", value, actual, err, expected)
		}
		if expected != "" && !validDownloadLocation(actual) {
			t.Errorf("downloadLocation(%q) produced an invalid SPDX location %q", value, actual)
		}
	}
}

func TestLicenseExpression(t *testing.T) {
	tests := []struct {
		licenses []string
		expected string
	}{
		{licenses: nil, expected: ""},
		{licenses: []string{"MIT"}, expected: "MIT"},
		{licenses: []string{"Apache-2.0", "BSD-3-Clause"}, expected: "Apache-2.0 AND BSD-3-Clause"},
		{licenses: []string{"MIT OR Apache-2.0"}, expected: "MIT OR Apache-2.0"},
		{licenses: []string{"MIT OR Apache-2.0", "ISC"}, expected: "(MIT OR Apache-2.0) AND ISC"},
		{licenses: []string{"MIT", "non-standard"}, expected: ""},
	}
	for _, test := range tests {
		if actual := licenseExpression(test.licenses); actual != test.expected {
			t.Errorf("licenseExpression(%q) = %q, want %q", test.licenses, actual, test.expected)
		}
	}
}

func TestEnrichSBOMFillsOnlyUnassertedFields(t *testing.T) {
	document := map[string]any{
		"creationInfo": map[string]any{"creators": []any{"Tool: GitHub.com-Dependency-Graph"}},
		"packages": []any{
			testPackage("pkg:golang/github.com/aws/aws-sdk-go@v1.55.8", map[string]any{"licenseConcluded": "Apache-2.0"}),
			testPackage("pkg:github/uug-ai/hub-api@main", map[string]any{
				"downloadLocation": "git+https://github.com/uug-ai/hub-api",
				"licenseDeclared":  "MIT",
			}),
			testPackage("pkg:npm/left-pad@1.3.0", map[string]any{"licenseDeclared": "NONE"}),
			map[string]any{"name": "no-purl", "downloadLocation": "NOASSERTION"},
		},
	}
	registry := &fakeRegistry{licenses: map[string]string{
		"GO github.com/aws/aws-sdk-go v1.55.8": "Apache-2.0 AND BSD-3-Clause",
		"NPM left-pad 1.3.0":                   "WTFPL",
	}}

	added, err := enrichSBOM(document, "uug-ai", registry)
	if err != nil {
		t.Fatal(err)
	}
	if added.DownloadLocations != 2 || added.DeclaredLicenses != 1 {
		t.Fatalf("unexpected enrichment counts: %+v", added)
	}
	packages := document["packages"].([]any)
	aws := packages[0].(map[string]any)
	if aws["downloadLocation"] != "https://proxy.golang.org/github.com/aws/aws-sdk-go/@v/v1.55.8.zip" ||
		aws["licenseDeclared"] != "Apache-2.0 AND BSD-3-Clause" || aws["licenseConcluded"] != "Apache-2.0" {
		t.Fatalf("dependency was not enriched: %+v", aws)
	}
	root := packages[1].(map[string]any)
	if root["downloadLocation"] != "git+https://github.com/uug-ai/hub-api" || root["licenseDeclared"] != "MIT" {
		t.Fatalf("asserted values were replaced: %+v", root)
	}
	if leftPad := packages[2].(map[string]any); leftPad["licenseDeclared"] != "NONE" {
		t.Fatalf("explicit NONE license was replaced: %+v", leftPad)
	}
	if noPURL := packages[3].(map[string]any); noPURL["downloadLocation"] != "NOASSERTION" {
		t.Fatalf("package without a purl was changed: %+v", noPURL)
	}

	creationInfo := document["creationInfo"].(map[string]any)
	creators := creationInfo["creators"].([]any)
	if len(creators) != 2 || creators[1] != enrichmentCreator {
		t.Fatalf("enrichment was not recorded as a creator: %+v", creators)
	}
	if comment, _ := creationInfo["comment"].(string); !strings.Contains(comment, "download locations to 2 packages") ||
		!strings.Contains(comment, "declared licenses to 1 packages") {
		t.Fatalf("unexpected creation comment: %q", comment)
	}
}

func TestEnrichSBOMLeavesDocumentUnmarkedWithoutChanges(t *testing.T) {
	document := map[string]any{
		"creationInfo": map[string]any{"creators": []any{"Tool: GitHub.com-Dependency-Graph"}},
		"packages":     []any{testPackage("pkg:npm/axios@%5E1.6.0", nil)},
	}
	added, err := enrichSBOM(document, "uug-ai", &fakeRegistry{})
	if err != nil || added != (enrichment{}) {
		t.Fatalf("unexpected enrichment: %+v, %v", added, err)
	}
	creationInfo := document["creationInfo"].(map[string]any)
	if len(creationInfo["creators"].([]any)) != 1 || creationInfo["comment"] != nil {
		t.Fatalf("unchanged document was marked as enriched: %+v", creationInfo)
	}
}

func TestEnrichSBOMReportsLookupFailuresAndKeepsOfflineLocations(t *testing.T) {
	document := map[string]any{
		"packages": []any{testPackage("pkg:golang/github.com/aws/aws-sdk-go@v1.55.8", nil)},
	}
	added, err := enrichSBOM(document, "uug-ai", &fakeRegistry{err: errors.New("deps.dev unavailable")})
	if err == nil || !strings.Contains(err.Error(), "deps.dev unavailable") {
		t.Fatalf("lookup failure was not reported: %v", err)
	}
	pkg := document["packages"].([]any)[0].(map[string]any)
	if added.DownloadLocations != 1 || pkg["licenseDeclared"] != nil {
		t.Fatalf("unexpected partial enrichment: %+v, %+v", added, pkg)
	}
}

func TestRegistryClientLooksUpLicensesAndPythonDistributions(t *testing.T) {
	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests[request.URL.EscapedPath()]++
		switch request.URL.EscapedPath() {
		case "/deps/systems/GO/packages/github.com%2Fgolang-jwt%2Fjwt/versions/v3.2.2+incompatible":
			_, _ = writer.Write([]byte(`{"licenses":["MIT"]}`))
		case "/deps/systems/PYPI/packages/numpy/versions/1.26.4":
			_, _ = writer.Write([]byte(`{"licenses":["non-standard"]}`))
		case "/pypi/pillow/10.4.0/json":
			_, _ = writer.Write([]byte(`{"urls":[
				{"packagetype":"bdist_wheel","filename":"pillow-10.4.0-cp312-cp312-manylinux_2_28_x86_64.whl","url":"https://files.example/wheel"},
				{"packagetype":"sdist","filename":"pillow-10.4.0.tar.gz","url":"https://files.example/sdist"}
			]}`))
		case "/pypi/six/1.16.0/json":
			_, _ = writer.Write([]byte(`{"urls":[
				{"packagetype":"bdist_wheel","filename":"six-1.16.0-py2.py3-none-any.whl","url":"https://files.example/six"}
			]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &registryClient{
		depsDevURL: server.URL + "/deps",
		pypiURL:    server.URL + "/pypi",
		httpClient: server.Client(),
		cache:      map[string]string{},
	}

	for range 2 {
		if license, err := client.DeclaredLicense("GO", "github.com/golang-jwt/jwt", "v3.2.2+incompatible"); err != nil || license != "MIT" {
			t.Fatalf("unexpected Go license: %q, %v", license, err)
		}
	}
	if requests["/deps/systems/GO/packages/github.com%2Fgolang-jwt%2Fjwt/versions/v3.2.2+incompatible"] != 1 {
		t.Fatalf("license lookup was not cached: %+v", requests)
	}
	if license, err := client.DeclaredLicense("PYPI", "numpy", "1.26.4"); err != nil || license != "" {
		t.Fatalf("non-standard license was asserted: %q, %v", license, err)
	}
	if license, err := client.DeclaredLicense("NPM", "missing", "1.0.0"); err != nil || license != "" {
		t.Fatalf("missing package was not treated as unlicensed: %q, %v", license, err)
	}
	if location, err := client.PyPIDownloadLocation("pillow", "10.4.0"); err != nil || location != "https://files.example/sdist" {
		t.Fatalf("source distribution was not preferred: %q, %v", location, err)
	}
	if location, err := client.PyPIDownloadLocation("six", "1.16.0"); err != nil || location != "https://files.example/six" {
		t.Fatalf("universal wheel was not used: %q, %v", location, err)
	}
}

func TestRegistryClientStopsAfterRepeatedFailures(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := &registryClient{depsDevURL: server.URL, pypiURL: server.URL, httpClient: server.Client(), cache: map[string]string{}}

	for attempt := range maximumRegistryFailures + 2 {
		_, err := client.DeclaredLicense("NPM", "lodash", fmt.Sprintf("4.17.%d", attempt))
		if err == nil {
			t.Fatalf("attempt %d did not fail", attempt)
		}
	}
	if calls != maximumRegistryFailures {
		t.Fatalf("registry was called %d times after repeated failures, want %d", calls, maximumRegistryFailures)
	}
	if _, err := client.PyPIDownloadLocation("six", "1.16.0"); !errors.Is(err, errRegistryUnavailable) {
		t.Fatalf("unexpected error after repeated failures: %v", err)
	}
}

func TestCollectSBOMsWritesAndScoresEnrichedDocument(t *testing.T) {
	sbom := `{
		"spdxVersion":"SPDX-2.3",
		"dataLicense":"CC0-1.0",
		"SPDXID":"SPDXRef-DOCUMENT",
		"documentNamespace":"https://example.com/hub-api",
		"creationInfo":{"created":"2026-08-13T10:00:00Z","creators":["Tool: GitHub.com-Dependency-Graph"]},
		"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-root"}],
		"packages":[{
			"name":"github.com/aws/aws-sdk-go",
			"SPDXID":"SPDXRef-aws",
			"versionInfo":"v1.55.8",
			"downloadLocation":"NOASSERTION",
			"licenseConcluded":"Apache-2.0",
			"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/aws/aws-sdk-go@v1.55.8"}]
		}]
	}`
	client := &fakeGitHubClient{
		repositories: []repository{testRepository("hub-api")},
		sboms:        map[string]json.RawMessage{"hub-api": json.RawMessage(sbom)},
		errors:       map[string]error{},
	}
	registry := &fakeRegistry{licenses: map[string]string{"GO github.com/aws/aws-sdk-go v1.55.8": "Apache-2.0"}}
	output := t.TempDir()

	index, err := collectSBOMs(client, registry, "uug-ai", output, stringSet{}, "2026-08-13T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	quality := index.Repositories[0].Quality
	if quality == nil || quality.DownloadPercent != 100 || quality.DeclaredLicensePercent != 100 || quality.Score != 93 {
		t.Fatalf("enriched SBOM was not scored: %+v", quality)
	}
	data, err := os.ReadFile(filepath.Join(output, "hub-api", "sbom.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "https://proxy.golang.org/github.com/aws/aws-sdk-go/@v/v1.55.8.zip") ||
		!strings.Contains(string(data), enrichmentCreator) {
		t.Fatalf("written SBOM was not enriched:\n%s", data)
	}
}
