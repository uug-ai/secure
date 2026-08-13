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
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			FixedVersion     string `json:"FixedVersion"`
			InstalledVersion string `json:"InstalledVersion"`
			PackageName      string `json:"PkgName"`
			PrimaryURL       string `json:"PrimaryURL"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			VulnerabilityID  string `json:"VulnerabilityID"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type cveFinding struct {
	FixableOccurrences int      `json:"fixableOccurrences"`
	ID                 string   `json:"id"`
	Occurrences        int      `json:"occurrences"`
	Packages           []string `json:"packages"`
	PrimaryURL         string   `json:"primaryUrl,omitempty"`
	Repositories       []string `json:"repositories"`
	Severity           string   `json:"severity"`
	Title              string   `json:"title,omitempty"`
}

type cveTotals struct {
	Critical    int `json:"critical"`
	Findings    int `json:"findings"`
	High        int `json:"high"`
	Occurrences int `json:"occurrences"`
}

type cveIndex struct {
	Findings    []cveFinding `json:"findings"`
	GeneratedAt string       `json:"generatedAt"`
	Source      string       `json:"source"`
	Totals      cveTotals    `json:"totals"`
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

func aggregateCVEs(reports map[string][]byte, generatedAt string) (cveIndex, error) {
	type findingState struct {
		finding      cveFinding
		packages     map[string]bool
		repositories map[string]bool
	}
	states := make(map[string]*findingState)
	repositories := make([]string, 0, len(reports))
	for repository := range reports {
		repositories = append(repositories, repository)
	}
	sort.Strings(repositories)
	for _, repository := range repositories {
		data := reports[repository]
		var report trivyReport
		if err := json.Unmarshal(data, &report); err != nil {
			return cveIndex{}, fmt.Errorf("decode %s Trivy report: %w", repository, err)
		}
		for _, result := range report.Results {
			for _, vulnerability := range result.Vulnerabilities {
				severity := strings.ToUpper(vulnerability.Severity)
				if (severity != "CRITICAL" && severity != "HIGH") || vulnerability.VulnerabilityID == "" {
					continue
				}
				state := states[vulnerability.VulnerabilityID]
				if state == nil {
					state = &findingState{
						finding: cveFinding{
							ID:         vulnerability.VulnerabilityID,
							PrimaryURL: vulnerability.PrimaryURL,
							Severity:   severity,
							Title:      vulnerability.Title,
						},
						packages:     make(map[string]bool),
						repositories: make(map[string]bool),
					}
					states[vulnerability.VulnerabilityID] = state
				}
				if severity == "CRITICAL" {
					state.finding.Severity = severity
				}
				if state.finding.PrimaryURL == "" {
					state.finding.PrimaryURL = vulnerability.PrimaryURL
				}
				if state.finding.Title == "" {
					state.finding.Title = vulnerability.Title
				}
				state.finding.Occurrences++
				if vulnerability.FixedVersion != "" {
					state.finding.FixableOccurrences++
				}
				state.repositories[repository] = true
				packageName := vulnerability.PackageName
				if vulnerability.InstalledVersion != "" {
					packageName += "@" + vulnerability.InstalledVersion
				}
				if packageName != "" {
					state.packages[packageName] = true
				}
			}
		}
	}

	index := cveIndex{
		GeneratedAt: generatedAt,
		Source:      "trivy-container-scans",
		Findings:    make([]cveFinding, 0, len(states)),
	}
	for _, state := range states {
		for repository := range state.repositories {
			state.finding.Repositories = append(state.finding.Repositories, repository)
		}
		for packageName := range state.packages {
			state.finding.Packages = append(state.finding.Packages, packageName)
		}
		sort.Strings(state.finding.Repositories)
		sort.Strings(state.finding.Packages)
		index.Findings = append(index.Findings, state.finding)
		index.Totals.Occurrences += state.finding.Occurrences
		if state.finding.Severity == "CRITICAL" {
			index.Totals.Critical++
		} else {
			index.Totals.High++
		}
	}
	index.Totals.Findings = len(index.Findings)
	sort.Slice(index.Findings, func(left, right int) bool {
		if index.Findings[left].Severity != index.Findings[right].Severity {
			return index.Findings[left].Severity == "CRITICAL"
		}
		if index.Findings[left].Occurrences != index.Findings[right].Occurrences {
			return index.Findings[left].Occurrences > index.Findings[right].Occurrences
		}
		return index.Findings[left].ID < index.Findings[right].ID
	})
	return index, nil
}

func loadScanReports(index scanIndex, outputDirectory string) (map[string][]byte, error) {
	reports := make(map[string][]byte)
	for _, entry := range index.Repositories {
		if entry.ReportPath == "" || (entry.Status != "scanned" && entry.Status != "stale") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDirectory, filepath.FromSlash(entry.ReportPath)))
		if err != nil {
			return nil, fmt.Errorf("read %s Trivy report: %w", entry.Name, err)
		}
		reports[entry.Name] = data
	}
	return reports, nil
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func renderCVEREADME(index cveIndex) string {
	var builder strings.Builder
	builder.WriteString("# Critical and high vulnerability findings\n\n")
	fmt.Fprintf(&builder, "Generated at `%s` from the latest available Trivy container reports. Occurrences count every affected package record across scanned images; one advisory can therefore occur more than once in one or more repositories.\n\n", index.GeneratedAt)
	fmt.Fprintf(&builder, "**%d unique findings**: %d critical and %d high, with %d total occurrences.\n\n", index.Totals.Findings, index.Totals.Critical, index.Totals.High, index.Totals.Occurrences)
	if len(index.Findings) == 0 {
		builder.WriteString("No critical or high findings are present in the available reports.\n")
		return builder.String()
	}
	builder.WriteString("| Severity | Advisory | Occurrences | Fixable | Repositories | Packages |\n")
	builder.WriteString("| --- | --- | ---: | ---: | --- | --- |\n")
	for _, finding := range index.Findings {
		advisory := markdownCell(finding.ID)
		if strings.HasPrefix(finding.PrimaryURL, "https://") || strings.HasPrefix(finding.PrimaryURL, "http://") {
			advisory = fmt.Sprintf("[%s](%s)", advisory, finding.PrimaryURL)
		}
		fmt.Fprintf(&builder, "| %s | %s | %d | %d | %s | %s |\n",
			finding.Severity,
			advisory,
			finding.Occurrences,
			finding.FixableOccurrences,
			markdownCell(strings.Join(finding.Repositories, ", ")),
			markdownCell(strings.Join(finding.Packages, ", ")),
		)
	}
	return builder.String()
}

func writeCVEEvidence(index scanIndex, containerDirectory, cveDirectory string) (cveIndex, error) {
	reports, err := loadScanReports(index, containerDirectory)
	if err != nil {
		return cveIndex{}, err
	}
	cves, err := aggregateCVEs(reports, index.GeneratedAt)
	if err != nil {
		return cveIndex{}, err
	}
	if err := writeJSON(filepath.Join(cveDirectory, "index.json"), cves); err != nil {
		return cveIndex{}, fmt.Errorf("write CVE index: %w", err)
	}
	if err := os.MkdirAll(cveDirectory, 0o755); err != nil {
		return cveIndex{}, fmt.Errorf("create CVE directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cveDirectory, "README.md"), []byte(renderCVEREADME(cves)), 0o644); err != nil {
		return cveIndex{}, fmt.Errorf("write CVE README: %w", err)
	}
	return cves, nil
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
	cveOutput := flag.String("cve-output", "cves", "aggregated critical and high CVE output directory")
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
	if _, err := writeCVEEvidence(index, *output, *cveOutput); err != nil {
		fmt.Fprintf(os.Stderr, "CVE evidence update failed: %v\n", err)
		os.Exit(1)
	}
	if err := updateREADME(*readme, index); err != nil {
		fmt.Fprintf(os.Stderr, "README update failed: %v\n", err)
		os.Exit(1)
	}
	summary, _ := json.Marshal(index.Totals)
	fmt.Println(string(summary))
}
