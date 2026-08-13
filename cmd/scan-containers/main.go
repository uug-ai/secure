package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const apiVersion = "2022-11-28"

var errPackageNotFound = errors.New("container package not found")

type packageAPI interface {
	ListPackageVersions(organization, name string) ([]packageVersion, error)
}

type imageScanner interface {
	Scan(image string) ([]byte, error)
}

type githubClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type trivyScanner struct {
	binary  string
	timeout time.Duration
}

type packageVersion struct {
	HTMLURL   string `json:"html_url"`
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	UpdatedAt string `json:"updated_at"`
	Metadata  struct {
		Container struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
}

type inventory struct {
	Repositories []struct {
		Name          string `json:"name"`
		RepositoryURL string `json:"repositoryUrl"`
	} `json:"repositories"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	Unknown  int `json:"unknown"`
}

type scanEntry struct {
	AttemptedAt     string         `json:"attemptedAt,omitempty"`
	Digest          string         `json:"digest,omitempty"`
	Error           string         `json:"error,omitempty"`
	Fixable         severityCounts `json:"fixable"`
	Image           string         `json:"image,omitempty"`
	Name            string         `json:"name"`
	PackageURL      string         `json:"packageUrl,omitempty"`
	Rating          string         `json:"rating,omitempty"`
	ReportPath      string         `json:"reportPath,omitempty"`
	RepositoryURL   string         `json:"repositoryUrl,omitempty"`
	ScannedAt       string         `json:"scannedAt,omitempty"`
	Score           int            `json:"score"`
	Status          string         `json:"status"`
	Tag             string         `json:"tag,omitempty"`
	Vulnerabilities severityCounts `json:"vulnerabilities"`
}

type scanTotals struct {
	Clean        int `json:"clean"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Low          int `json:"low"`
	Medium       int `json:"medium"`
	Repositories int `json:"repositories"`
	Scanned      int `json:"scanned"`
	Stale        int `json:"stale"`
	Unavailable  int `json:"unavailable"`
	Unknown      int `json:"unknown"`
}

type scanIndex struct {
	GeneratedAt  string      `json:"generatedAt"`
	Organization string      `json:"organization"`
	Repositories []scanEntry `json:"repositories"`
	Scanner      string      `json:"scanner"`
	Source       string      `json:"source"`
	Totals       scanTotals  `json:"totals"`
}

type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Vulnerabilities []struct {
			FixedVersion string `json:"FixedVersion"`
			Severity     string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (client *githubClient) ListPackageVersions(organization, name string) ([]packageVersion, error) {
	versions := make([]packageVersion, 0)
	for page := 1; ; page++ {
		path := fmt.Sprintf("/orgs/%s/packages/container/%s/versions", url.PathEscape(organization), url.PathEscape(name))
		query := url.Values{"page": {fmt.Sprintf("%d", page)}, "per_page": {"100"}}
		var result []packageVersion
		status, err := client.getJSON(path, query, &result)
		if status == http.StatusNotFound {
			return nil, errPackageNotFound
		}
		if err != nil {
			return nil, err
		}
		versions = append(versions, result...)
		if len(result) < 100 {
			return versions, nil
		}
	}
}

func (client *githubClient) getJSON(path string, query url.Values, destination any) (int, error) {
	requestURL := client.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create GitHub API request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("User-Agent", "uug-ai-secure-container-scanner")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("GitHub API request failed: %w", err)
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
		return response.StatusCode, fmt.Errorf("GitHub API returned %d: %s", response.StatusCode, apiError.Message)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return response.StatusCode, fmt.Errorf("decode GitHub API response: %w", err)
	}
	return response.StatusCode, nil
}

func (scanner *trivyScanner) Scan(image string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scanner.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, scanner.binary, "image", "--disable-telemetry", "--quiet", "--scanners", "vuln", "--format", "json", image)
	output, err := command.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Trivy scan timed out: %w", ctx.Err())
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			message := strings.TrimSpace(string(exitError.Stderr))
			if message != "" {
				return nil, fmt.Errorf("Trivy scan failed: %s", message)
			}
		}
		return nil, fmt.Errorf("Trivy scan failed: %w", err)
	}
	return output, nil
}

func loadJSON(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, destination)
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

func selectPackageVersion(versions []packageVersion) (packageVersion, string, bool) {
	for _, version := range versions {
		if len(version.Metadata.Container.Tags) == 0 {
			continue
		}
		tags := append([]string(nil), version.Metadata.Container.Tags...)
		sort.Strings(tags)
		for _, tag := range tags {
			if tag == "latest" {
				return version, tag, true
			}
		}
		return version, tags[0], true
	}
	return packageVersion{}, "", false
}

func addSeverity(counts *severityCounts, severity string) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		counts.Critical++
	case "HIGH":
		counts.High++
	case "MEDIUM":
		counts.Medium++
	case "LOW":
		counts.Low++
	default:
		counts.Unknown++
	}
}

func assessReport(data []byte) (severityCounts, severityCounts, int, string, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return severityCounts{}, severityCounts{}, 0, "", err
	}
	var vulnerabilities, fixable severityCounts
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			addSeverity(&vulnerabilities, vulnerability.Severity)
			if vulnerability.FixedVersion != "" {
				addSeverity(&fixable, vulnerability.Severity)
			}
		}
	}
	score, rating := 100, "Clean"
	switch {
	case vulnerabilities.Critical > 0:
		score, rating = 0, "Critical"
	case vulnerabilities.High > 0:
		score, rating = 30, "High"
	case vulnerabilities.Unknown > 0:
		score, rating = 40, "Unknown"
	case vulnerabilities.Medium > 0:
		score, rating = 60, "Medium"
	case vulnerabilities.Low > 0:
		score, rating = 80, "Low"
	}
	return vulnerabilities, fixable, score, rating, nil
}

func imageReference(organization, name, tag, digest string) string {
	base := fmt.Sprintf("ghcr.io/%s/%s", strings.ToLower(organization), strings.ToLower(name))
	if strings.HasPrefix(digest, "sha256:") {
		return base + "@" + digest
	}
	return base + ":" + tag
}

func previousEntries(path string) map[string]scanEntry {
	var index scanIndex
	if loadJSON(path, &index) != nil {
		return map[string]scanEntry{}
	}
	entries := make(map[string]scanEntry, len(index.Repositories))
	for _, entry := range index.Repositories {
		entries[entry.Name] = entry
	}
	return entries
}

func staleOrUnavailable(previous scanEntry, name, repositoryURL, attemptedAt string, scanErr error) scanEntry {
	if previous.ReportPath != "" {
		previous.AttemptedAt = attemptedAt
		previous.Error = scanErr.Error()
		previous.Status = "stale"
		return previous
	}
	return scanEntry{
		AttemptedAt:   attemptedAt,
		Error:         scanErr.Error(),
		Name:          name,
		RepositoryURL: repositoryURL,
		Status:        "unavailable",
	}
}

func calculateTotals(entries []scanEntry) scanTotals {
	totals := scanTotals{Repositories: len(entries)}
	for _, entry := range entries {
		switch entry.Status {
		case "scanned":
			totals.Scanned++
		case "stale":
			totals.Stale++
		case "unavailable":
			totals.Unavailable++
		}
		if entry.Status == "scanned" || entry.Status == "stale" {
			switch entry.Rating {
			case "Clean":
				totals.Clean++
			case "Critical":
				totals.Critical++
			case "High":
				totals.High++
			case "Medium":
				totals.Medium++
			case "Low":
				totals.Low++
			default:
				totals.Unknown++
			}
		}
	}
	return totals
}

func collectScans(api packageAPI, scanner imageScanner, inventoryPath, outputDirectory, organization, scannedAt string) (scanIndex, error) {
	var projects inventory
	if err := loadJSON(inventoryPath, &projects); err != nil {
		return scanIndex{}, fmt.Errorf("read project inventory: %w", err)
	}
	previous := previousEntries(filepath.Join(outputDirectory, "index.json"))
	entries := make([]scanEntry, 0, len(projects.Repositories))
	activeNames := make(map[string]bool, len(projects.Repositories))

	for _, project := range projects.Repositories {
		if project.Name == "" || filepath.Base(project.Name) != project.Name {
			return scanIndex{}, fmt.Errorf("invalid repository name %q", project.Name)
		}
		activeNames[project.Name] = true
		versions, err := api.ListPackageVersions(organization, project.Name)
		if errors.Is(err, errPackageNotFound) {
			_ = os.RemoveAll(filepath.Join(outputDirectory, project.Name))
			entry := staleOrUnavailable(scanEntry{}, project.Name, project.RepositoryURL, scannedAt, err)
			if err := writeJSON(filepath.Join(outputDirectory, project.Name, "status.json"), entry); err != nil {
				return scanIndex{}, err
			}
			entries = append(entries, entry)
			continue
		}
		if err != nil {
			entry := staleOrUnavailable(previous[project.Name], project.Name, project.RepositoryURL, scannedAt, err)
			if err := writeJSON(filepath.Join(outputDirectory, project.Name, "status.json"), entry); err != nil {
				return scanIndex{}, err
			}
			entries = append(entries, entry)
			continue
		}
		version, tag, found := selectPackageVersion(versions)
		if !found {
			_ = os.RemoveAll(filepath.Join(outputDirectory, project.Name))
			entry := staleOrUnavailable(scanEntry{}, project.Name, project.RepositoryURL, scannedAt, errors.New("container package has no tagged versions"))
			if err := writeJSON(filepath.Join(outputDirectory, project.Name, "status.json"), entry); err != nil {
				return scanIndex{}, err
			}
			entries = append(entries, entry)
			continue
		}

		image := imageReference(organization, project.Name, tag, version.Name)
		report, err := scanner.Scan(image)
		if err != nil {
			entry := staleOrUnavailable(previous[project.Name], project.Name, project.RepositoryURL, scannedAt, err)
			if err := writeJSON(filepath.Join(outputDirectory, project.Name, "status.json"), entry); err != nil {
				return scanIndex{}, err
			}
			entries = append(entries, entry)
			continue
		}
		vulnerabilities, fixable, score, rating, err := assessReport(report)
		if err != nil {
			return scanIndex{}, fmt.Errorf("assess %s scan: %w", project.Name, err)
		}
		reportPath := filepath.ToSlash(filepath.Join(project.Name, "trivy.json"))
		var normalized any
		if err := json.Unmarshal(report, &normalized); err != nil {
			return scanIndex{}, fmt.Errorf("decode %s scan: %w", project.Name, err)
		}
		if err := writeJSON(filepath.Join(outputDirectory, filepath.FromSlash(reportPath)), normalized); err != nil {
			return scanIndex{}, fmt.Errorf("write %s scan: %w", project.Name, err)
		}
		entry := scanEntry{
			AttemptedAt:     scannedAt,
			Digest:          version.Name,
			Fixable:         fixable,
			Image:           fmt.Sprintf("ghcr.io/%s/%s", strings.ToLower(organization), strings.ToLower(project.Name)),
			Name:            project.Name,
			PackageURL:      version.HTMLURL,
			Rating:          rating,
			ReportPath:      reportPath,
			RepositoryURL:   project.RepositoryURL,
			ScannedAt:       scannedAt,
			Score:           score,
			Status:          "scanned",
			Tag:             tag,
			Vulnerabilities: vulnerabilities,
		}
		if err := writeJSON(filepath.Join(outputDirectory, project.Name, "status.json"), entry); err != nil {
			return scanIndex{}, fmt.Errorf("write %s status: %w", project.Name, err)
		}
		entries = append(entries, entry)
	}

	directories, err := os.ReadDir(outputDirectory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return scanIndex{}, fmt.Errorf("read output directory: %w", err)
	}
	for _, directory := range directories {
		if directory.IsDir() && !activeNames[directory.Name()] {
			if err := os.RemoveAll(filepath.Join(outputDirectory, directory.Name())); err != nil {
				return scanIndex{}, fmt.Errorf("remove obsolete scan directory: %w", err)
			}
		}
	}

	index := scanIndex{
		GeneratedAt:  scannedAt,
		Organization: organization,
		Repositories: entries,
		Scanner:      "Trivy",
		Source:       "ghcr",
		Totals:       calculateTotals(entries),
	}
	if err := writeJSON(filepath.Join(outputDirectory, "index.json"), index); err != nil {
		return scanIndex{}, fmt.Errorf("write scan index: %w", err)
	}
	return index, nil
}

const (
	containerStartMarker = "<!-- CONTAINER_SCAN_START -->"
	containerEndMarker   = "<!-- CONTAINER_SCAN_END -->"
)

func scanIndicator(entry scanEntry) string {
	if entry.Status == "unavailable" {
		return "Unavailable"
	}
	switch entry.Rating {
	case "Clean":
		return "Clean"
	case "Low":
		return "Low"
	case "Medium":
		return "Medium"
	case "High":
		return "High"
	case "Critical":
		return "Critical"
	default:
		return "Unknown"
	}
}

func renderContainerSection(index scanIndex) string {
	var builder strings.Builder
	builder.WriteString(containerStartMarker + "\n")
	builder.WriteString("## Container image security overview\n\n")
	fmt.Fprintf(&builder, "Generated at `%s` from the newest tagged GHCR image available for each approved project. Scores use the highest detected severity: 100 clean, 80 low, 60 medium, 30 high, and 0 critical. An unavailable image is a coverage gap, not a clean result.\n\n", index.GeneratedAt)
	builder.WriteString("| Repository | Scan | Risk | Score | Tag | Critical | High | Medium | Low | Fixable C/H | Report |\n")
	builder.WriteString("| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |\n")
	for _, entry := range index.Repositories {
		repository := entry.Name
		if entry.RepositoryURL != "" {
			repository = fmt.Sprintf("[%s](%s)", entry.Name, entry.RepositoryURL)
		}
		score, tag := "-", "-"
		if entry.Status == "scanned" || entry.Status == "stale" {
			score = fmt.Sprintf("%d/100", entry.Score)
			tag = entry.Tag
		}
		report := "-"
		if entry.ReportPath != "" {
			report = fmt.Sprintf("[Trivy](containers/%s)", entry.ReportPath)
		}
		fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s | %d | %d | %d | %d | %d/%d | %s |\n",
			repository, entry.Status, scanIndicator(entry), score, tag,
			entry.Vulnerabilities.Critical, entry.Vulnerabilities.High, entry.Vulnerabilities.Medium,
			entry.Vulnerabilities.Low, entry.Fixable.Critical, entry.Fixable.High, report)
	}
	builder.WriteString(containerEndMarker)
	return builder.String()
}

func updateREADME(path string, index scanIndex) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)
	section := renderContainerSection(index)
	start := strings.Index(content, containerStartMarker)
	end := strings.Index(content, containerEndMarker)
	if start >= 0 && end >= start {
		end += len(containerEndMarker)
		content = content[:start] + section + content[end:]
	} else {
		anchor := "<!-- SBOM_QUALITY_START -->"
		position := strings.Index(content, anchor)
		if position >= 0 {
			content = content[:position] + section + "\n\n" + content[position:]
		} else {
			content = strings.TrimRight(content, "\n") + "\n\n" + section + "\n"
		}
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func main() {
	organization := flag.String("organization", "uug-ai", "GitHub organization containing the images")
	inventoryPath := flag.String("inventory", "sboms/index.json", "approved project inventory")
	output := flag.String("output", "containers", "container scan output directory")
	readme := flag.String("readme", "README.md", "README file to update")
	trivyBinary := flag.String("trivy", "trivy", "Trivy executable")
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
	api := &githubClient{baseURL: strings.TrimRight(baseURL, "/"), token: token, httpClient: &http.Client{Timeout: 60 * time.Second}}
	scanner := &trivyScanner{binary: *trivyBinary, timeout: 30 * time.Minute}
	scannedAt := time.Now().UTC().Format(time.RFC3339)
	index, err := collectScans(api, scanner, *inventoryPath, *output, *organization, scannedAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "container scan collection failed: %v\n", err)
		os.Exit(1)
	}
	if err := updateREADME(*readme, index); err != nil {
		fmt.Fprintf(os.Stderr, "README update failed: %v\n", err)
		os.Exit(1)
	}
	summary, _ := json.Marshal(index.Totals)
	fmt.Println(string(summary))
}
