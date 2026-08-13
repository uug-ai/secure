package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const apiVersion = "2022-11-28"

type githubAPI interface {
	ListOrganizationRepositories(organization string) ([]repository, error)
	GetRepositorySBOM(organization, repository string) (json.RawMessage, error)
}

type githubClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type repository struct {
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Name          string `json:"name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
}

type indexEntry struct {
	Archived      bool         `json:"archived"`
	CollectedAt   string       `json:"collectedAt,omitempty"`
	DefaultBranch string       `json:"defaultBranch,omitempty"`
	Error         string       `json:"error,omitempty"`
	Name          string       `json:"name"`
	Path          string       `json:"path,omitempty"`
	Quality       *sbomQuality `json:"quality,omitempty"`
	RepositoryURL string       `json:"repositoryUrl,omitempty"`
	SourceURL     string       `json:"sourceUrl"`
	Status        string       `json:"status"`
	Visibility    string       `json:"visibility"`
}

type sbomQuality struct {
	LicensedPercent  int    `json:"licensedPercent"`
	PackageCount     int    `json:"packageCount"`
	PURLPercent      int    `json:"purlPercent"`
	Rating           string `json:"rating"`
	Score            int    `json:"score"`
	VersionedPercent int    `json:"versionedPercent"`
}

type spdxDocument struct {
	CreationInfo struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	DataLicense       string        `json:"dataLicense"`
	DocumentDescribes []string      `json:"documentDescribes"`
	DocumentNamespace string        `json:"documentNamespace"`
	Name              string        `json:"name"`
	Packages          []spdxPackage `json:"packages"`
	Relationships     []any         `json:"relationships"`
	SPDXID            string        `json:"SPDXID"`
	SPDXVersion       string        `json:"spdxVersion"`
}

type spdxPackage struct {
	DownloadLocation string `json:"downloadLocation"`
	ExternalRefs     []struct {
		ReferenceType string `json:"referenceType"`
	} `json:"externalRefs"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	Supplier         string `json:"supplier"`
	VersionInfo      string `json:"versionInfo"`
}

type totals struct {
	Collected    int `json:"collected"`
	Repositories int `json:"repositories"`
	Stale        int `json:"stale"`
	Unavailable  int `json:"unavailable"`
}

type sbomIndex struct {
	GeneratedAt  string       `json:"generatedAt"`
	Organization string       `json:"organization"`
	Repositories []indexEntry `json:"repositories"`
	Source       string       `json:"source"`
	Totals       totals       `json:"totals"`
}

type stringSet map[string]bool

func (values stringSet) String() string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func (values stringSet) Set(value string) error {
	values[value] = true
	return nil
}

func (client *githubClient) getJSON(path string, query url.Values, destination any) error {
	requestURL := client.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}

	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("create GitHub API request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("User-Agent", "uug-ai-secure-sbom-collector")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var apiError struct {
			Message string `json:"message"`
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = json.Unmarshal(body, &apiError)
		if apiError.Message == "" {
			apiError.Message = response.Status
		}
		return fmt.Errorf("GitHub API returned %d: %s", response.StatusCode, apiError.Message)
	}

	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return fmt.Errorf("decode GitHub API response: %w", err)
	}
	return nil
}

func (client *githubClient) ListOrganizationRepositories(organization string) ([]repository, error) {
	var repositories []repository
	for page := 1; ; page++ {
		var result []repository
		err := client.getJSON(
			"/orgs/"+url.PathEscape(organization)+"/repos",
			url.Values{
				"page":     {fmt.Sprintf("%d", page)},
				"per_page": {"100"},
				"type":     {"all"},
			},
			&result,
		)
		if err != nil {
			return nil, err
		}
		repositories = append(repositories, result...)
		if len(result) < 100 {
			return repositories, nil
		}
	}
}

func (client *githubClient) GetRepositorySBOM(organization, repository string) (json.RawMessage, error) {
	var response struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	path := fmt.Sprintf(
		"/repos/%s/%s/dependency-graph/sbom",
		url.PathEscape(organization),
		url.PathEscape(repository),
	)
	if err := client.getJSON(path, nil, &response); err != nil {
		return nil, err
	}

	var document struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(response.SBOM, &document); err != nil || document.SPDXVersion == "" {
		return nil, errors.New("GitHub response does not contain a valid SPDX SBOM")
	}
	return response.SBOM, nil
}

func loadPreviousIndex(path string) map[string]indexEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]indexEntry{}
	}
	var index sbomIndex
	if json.Unmarshal(data, &index) != nil {
		return map[string]indexEntry{}
	}
	entries := make(map[string]indexEntry, len(index.Repositories))
	for _, entry := range index.Repositories {
		entries[entry.Name] = entry
	}
	return entries
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func asserted(value string) bool {
	return value != "" && value != "NOASSERTION" && value != "NONE"
}

func percentage(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count*100 + total/2) / total
}

func isTargetRepository(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "hub") || name == "factory" || name == "vault"
}

func assessSBOM(data []byte) (sbomQuality, error) {
	var document spdxDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return sbomQuality{}, err
	}

	documentScore := 0
	for _, present := range []bool{
		document.SPDXVersion != "",
		document.DataLicense != "",
		document.DocumentNamespace != "",
		document.CreationInfo.Created != "",
		len(document.CreationInfo.Creators) > 0,
	} {
		if present {
			documentScore += 4
		}
	}

	var names, identifiers, versions, purls, licensed, declared, concluded, suppliers, downloads int
	for _, pkg := range document.Packages {
		if pkg.Name != "" {
			names++
		}
		if pkg.SPDXID != "" {
			identifiers++
		}
		if asserted(pkg.VersionInfo) {
			versions++
		}
		if asserted(pkg.LicenseDeclared) {
			declared++
		}
		if asserted(pkg.LicenseConcluded) {
			concluded++
		}
		if asserted(pkg.LicenseDeclared) || asserted(pkg.LicenseConcluded) {
			licensed++
		}
		if asserted(pkg.Supplier) {
			suppliers++
		}
		if asserted(pkg.DownloadLocation) {
			downloads++
		}
		for _, reference := range pkg.ExternalRefs {
			if strings.Contains(strings.ToLower(reference.ReferenceType), "purl") {
				purls++
				break
			}
		}
	}

	packageCount := len(document.Packages)
	versionedPercent := percentage(versions, packageCount)
	licensedPercent := percentage(licensed, packageCount)
	purlPercent := percentage(purls, packageCount)
	score := documentScore
	score += percentage(names, packageCount) * 5 / 100
	score += percentage(identifiers, packageCount) * 5 / 100
	score += versionedPercent * 10 / 100
	score += purlPercent * 10 / 100
	score += percentage(declared, packageCount) * 10 / 100
	score += percentage(concluded, packageCount) * 10 / 100
	score += percentage(suppliers, packageCount) * 7 / 100
	score += percentage(downloads, packageCount) * 8 / 100
	if len(document.DocumentDescribes) > 0 {
		score += 5
	}
	if len(document.Relationships) > 0 {
		score += 10
	}

	rating := "Poor"
	switch {
	case score >= 85:
		rating = "Excellent"
	case score >= 70:
		rating = "Good"
	case score >= 50:
		rating = "Needs work"
	}
	return sbomQuality{
		LicensedPercent:  licensedPercent,
		PackageCount:     packageCount,
		PURLPercent:      purlPercent,
		Rating:           rating,
		Score:            score,
		VersionedPercent: versionedPercent,
	}, nil
}

const (
	qualityStartMarker = "<!-- SBOM_QUALITY_START -->"
	qualityEndMarker   = "<!-- SBOM_QUALITY_END -->"
)

func qualityIndicator(quality *sbomQuality) string {
	if quality == nil {
		return "\U0001F534 Unavailable"
	}
	switch quality.Rating {
	case "Excellent":
		return "\U0001F7E2 Excellent"
	case "Good":
		return "\U0001F7E1 Good"
	case "Needs work":
		return "\U0001F7E0 Needs work"
	default:
		return "\U0001F534 Poor"
	}
}

func renderQualitySection(index sbomIndex) string {
	var builder strings.Builder
	builder.WriteString(qualityStartMarker + "\n")
	builder.WriteString("## SBOM quality overview\n\n")
	fmt.Fprintf(&builder, "Generated at `%s`. Quality combines document metadata (20%%), package identity (30%%), licensing (20%%), provenance (15%%), and relationships (15%%).\n\n", index.GeneratedAt)
	builder.WriteString("Legend: \U0001F7E2 85-100, \U0001F7E1 70-84, \U0001F7E0 50-69, \U0001F534 0-49 or unavailable.\n\n")
	builder.WriteString("| Repository | Collection | Quality | Score | Packages | Versioned | Licensed | PURL | SBOM |\n")
	builder.WriteString("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n")
	for _, entry := range index.Repositories {
		repository := entry.Name
		if entry.RepositoryURL != "" {
			repository = fmt.Sprintf("[%s](%s)", entry.Name, entry.RepositoryURL)
		}
		score, packages, versioned, licensed, purl := "0/100", "0", "0%", "0%", "0%"
		if entry.Quality != nil {
			score = fmt.Sprintf("%d/100", entry.Quality.Score)
			packages = fmt.Sprintf("%d", entry.Quality.PackageCount)
			versioned = fmt.Sprintf("%d%%", entry.Quality.VersionedPercent)
			licensed = fmt.Sprintf("%d%%", entry.Quality.LicensedPercent)
			purl = fmt.Sprintf("%d%%", entry.Quality.PURLPercent)
		}
		sbomLink := "-"
		if entry.Path != "" {
			sbomLink = fmt.Sprintf("[SPDX](sboms/%s)", entry.Path)
		}
		fmt.Fprintf(
			&builder,
			"| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			repository,
			entry.Status,
			qualityIndicator(entry.Quality),
			score,
			packages,
			versioned,
			licensed,
			purl,
			sbomLink,
		)
	}
	builder.WriteString(qualityEndMarker)
	return builder.String()
}

func updateREADME(path string, index sbomIndex) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)
	section := renderQualitySection(index)
	start := strings.Index(content, qualityStartMarker)
	end := strings.Index(content, qualityEndMarker)
	if start >= 0 && end >= start {
		end += len(qualityEndMarker)
		content = content[:start] + section + content[end:]
	} else {
		content = strings.TrimRight(content, "\n") + "\n\n" + section + "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func collectSBOMs(client githubAPI, organization, outputDirectory string, excluded stringSet, collectedAt string) (sbomIndex, error) {
	previous := loadPreviousIndex(filepath.Join(outputDirectory, "index.json"))
	repositories, err := client.ListOrganizationRepositories(organization)
	if err != nil {
		return sbomIndex{}, fmt.Errorf("list organization repositories: %w", err)
	}
	sort.Slice(repositories, func(left, right int) bool {
		return strings.ToLower(repositories[left].Name) < strings.ToLower(repositories[right].Name)
	})

	entries := make([]indexEntry, 0, len(repositories))
	activeNames := make(map[string]bool, len(repositories))
	for _, repository := range repositories {
		if excluded[repository.Name] || !isTargetRepository(repository.Name) {
			continue
		}
		if repository.Name == "" || filepath.Base(repository.Name) != repository.Name {
			return sbomIndex{}, fmt.Errorf("invalid repository name %q", repository.Name)
		}

		activeNames[repository.Name] = true
		relativePath := filepath.ToSlash(filepath.Join(repository.Name, "sbom.spdx.json"))
		destination := filepath.Join(outputDirectory, filepath.FromSlash(relativePath))
		visibility := repository.Visibility
		if visibility == "" {
			visibility = "public"
			if repository.Private {
				visibility = "private"
			}
		}
		entry := indexEntry{
			Archived:      repository.Archived,
			DefaultBranch: repository.DefaultBranch,
			Name:          repository.Name,
			RepositoryURL: repository.HTMLURL,
			SourceURL: fmt.Sprintf(
				"https://api.github.com/repos/%s/%s/dependency-graph/sbom",
				organization,
				repository.Name,
			),
			Visibility: visibility,
		}

		sbom, collectionErr := client.GetRepositorySBOM(organization, repository.Name)
		if collectionErr == nil {
			var document any
			if err := json.Unmarshal(sbom, &document); err != nil {
				return sbomIndex{}, fmt.Errorf("decode %s SBOM: %w", repository.Name, err)
			}
			quality, err := assessSBOM(sbom)
			if err != nil {
				return sbomIndex{}, fmt.Errorf("assess %s SBOM: %w", repository.Name, err)
			}
			if err := writeJSON(destination, document); err != nil {
				return sbomIndex{}, fmt.Errorf("write %s SBOM: %w", repository.Name, err)
			}
			entry.CollectedAt = collectedAt
			entry.Path = relativePath
			entry.Quality = &quality
			entry.Status = "collected"
		} else if _, err := os.Stat(destination); err == nil {
			data, readErr := os.ReadFile(destination)
			if readErr == nil {
				quality, assessErr := assessSBOM(data)
				if assessErr == nil {
					entry.Quality = &quality
				}
			}
			entry.CollectedAt = previous[repository.Name].CollectedAt
			entry.Error = collectionErr.Error()
			entry.Path = relativePath
			entry.Status = "stale"
		} else {
			entry.Error = collectionErr.Error()
			entry.Status = "unavailable"
		}
		entries = append(entries, entry)
	}

	directories, err := os.ReadDir(outputDirectory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return sbomIndex{}, fmt.Errorf("read output directory: %w", err)
	}
	for _, directory := range directories {
		if directory.IsDir() && !activeNames[directory.Name()] {
			if err := os.RemoveAll(filepath.Join(outputDirectory, directory.Name())); err != nil {
				return sbomIndex{}, fmt.Errorf("remove obsolete SBOM directory: %w", err)
			}
		}
	}

	index := sbomIndex{
		GeneratedAt:  collectedAt,
		Organization: organization,
		Repositories: entries,
		Source:       "github-dependency-graph",
		Totals:       totals{Repositories: len(entries)},
	}
	for _, entry := range entries {
		switch entry.Status {
		case "collected":
			index.Totals.Collected++
		case "stale":
			index.Totals.Stale++
		case "unavailable":
			index.Totals.Unavailable++
		}
	}
	if err := writeJSON(filepath.Join(outputDirectory, "index.json"), index); err != nil {
		return sbomIndex{}, fmt.Errorf("write SBOM index: %w", err)
	}
	return index, nil
}

func main() {
	organization := flag.String("organization", "uug-ai", "GitHub organization to collect")
	output := flag.String("output", "sboms", "output directory")
	readme := flag.String("readme", "README.md", "README file to update with the quality table")
	excluded := stringSet{"secure": true}
	flag.Var(excluded, "exclude", "repository to exclude (repeatable)")
	flag.Parse()

	token := os.Getenv("GH_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "GH_TOKEN is required")
		os.Exit(1)
	}
	baseURL := os.Getenv("GITHUB_API_URL")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	client := &githubClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
	collectedAt := time.Now().UTC().Format(time.RFC3339)
	index, err := collectSBOMs(client, *organization, *output, excluded, collectedAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SBOM collection failed: %v\n", err)
		os.Exit(1)
	}
	if err := updateREADME(*readme, index); err != nil {
		fmt.Fprintf(os.Stderr, "README update failed: %v\n", err)
		os.Exit(1)
	}
	summary, _ := json.Marshal(index.Totals)
	fmt.Println(string(summary))
}
