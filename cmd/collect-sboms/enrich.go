package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

const enrichmentCreator = "Tool: uug-ai-secure-collect-sboms"

// maximumRegistryFailures stops lookups after consecutive failures so an
// unavailable registry costs a few timeouts rather than one per package.
const maximumRegistryFailures = 3

var (
	errRegistryUnavailable = errors.New("package registry lookups disabled after repeated failures")
	majorVersionPattern    = regexp.MustCompile(`^v[0-9]+$`)
	pseudoVersionPattern   = regexp.MustCompile(`[0-9]{14}-([0-9a-f]{12})$`)
)

// depsDevSystems maps package URL types to deps.dev package systems.
var depsDevSystems = map[string]string{
	"golang": "GO",
	"npm":    "NPM",
	"pypi":   "PYPI",
}

type packageRegistry interface {
	DeclaredLicense(system, name, version string) (string, error)
	PyPIDownloadLocation(name, version string) (string, error)
}

// registryClient reads declared licenses from deps.dev and Python
// distribution URLs from PyPI. Results, including misses, are cached for the
// whole collection run because repositories share many dependencies.
type registryClient struct {
	depsDevURL string
	pypiURL    string
	httpClient *http.Client
	cache      map[string]string
	failures   int
}

type packageURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

type enrichment struct {
	DeclaredLicenses  int
	DownloadLocations int
}

func (client *registryClient) getJSON(requestURL string, destination any) (bool, error) {
	if client.failures >= maximumRegistryFailures {
		return false, errRegistryUnavailable
	}
	found, err := client.fetchJSON(requestURL, destination)
	if err != nil {
		client.failures++
		return false, err
	}
	client.failures = 0
	return found, nil
}

func (client *registryClient) fetchJSON(requestURL string, destination any) (bool, error) {
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return false, fmt.Errorf("create registry request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "uug-ai-secure-sbom-collector")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return false, fmt.Errorf("registry request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return false, fmt.Errorf("registry returned %d for %s", response.StatusCode, requestURL)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return false, fmt.Errorf("decode registry response: %w", err)
	}
	return true, nil
}

func (client *registryClient) cached(key string, lookup func() (string, error)) (string, error) {
	if value, found := client.cache[key]; found {
		return value, nil
	}
	value, err := lookup()
	if err != nil {
		return "", err
	}
	client.cache[key] = value
	return value, nil
}

func (client *registryClient) DeclaredLicense(system, name, version string) (string, error) {
	return client.cached("license "+system+" "+name+" "+version, func() (string, error) {
		var response struct {
			Licenses []string `json:"licenses"`
		}
		requestURL := fmt.Sprintf(
			"%s/systems/%s/packages/%s/versions/%s",
			client.depsDevURL,
			url.PathEscape(system),
			url.PathEscape(name),
			url.PathEscape(version),
		)
		if found, err := client.getJSON(requestURL, &response); !found {
			return "", err
		}
		return licenseExpression(response.Licenses), nil
	})
}

func (client *registryClient) PyPIDownloadLocation(name, version string) (string, error) {
	return client.cached("pypi "+name+" "+version, func() (string, error) {
		var response struct {
			URLs []struct {
				Filename    string `json:"filename"`
				PackageType string `json:"packagetype"`
				URL         string `json:"url"`
			} `json:"urls"`
		}
		requestURL := fmt.Sprintf("%s/%s/%s/json", client.pypiURL, url.PathEscape(name), url.PathEscape(version))
		if found, err := client.getJSON(requestURL, &response); !found {
			return "", err
		}
		// Prefer the source distribution; otherwise accept only a
		// platform-independent wheel, which is the same file everywhere.
		location := ""
		for _, file := range response.URLs {
			switch {
			case file.PackageType == "sdist":
				return file.URL, nil
			case location == "" && strings.HasSuffix(file.Filename, "-none-any.whl"):
				location = file.URL
			}
		}
		return location, nil
	})
}

// licenseExpression combines the licenses deps.dev found into one SPDX
// expression. A package with any license deps.dev could not map to SPDX is
// left unasserted rather than reported with only part of its licensing.
func licenseExpression(licenses []string) string {
	terms := make([]string, 0, len(licenses))
	for _, license := range licenses {
		license = strings.TrimSpace(license)
		if license == "" || strings.EqualFold(license, "non-standard") {
			return ""
		}
		if len(licenses) > 1 && strings.Contains(license, " ") && !strings.HasPrefix(license, "(") {
			license = "(" + license + ")"
		}
		terms = append(terms, license)
	}
	return strings.Join(terms, " AND ")
}

func parsePackageURL(value string) (packageURL, bool) {
	rest, found := strings.CutPrefix(value, "pkg:")
	if !found {
		return packageURL{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")

	var purl packageURL
	if separator := strings.LastIndex(rest, "@"); separator >= 0 {
		version, err := url.PathUnescape(rest[separator+1:])
		if err != nil {
			return packageURL{}, false
		}
		purl.Version = version
		rest = rest[:separator]
	}

	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segments) < 2 {
		return packageURL{}, false
	}
	for position, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "" {
			return packageURL{}, false
		}
		segments[position] = decoded
	}
	purl.Type = strings.ToLower(segments[0])
	purl.Name = segments[len(segments)-1]
	purl.Namespace = strings.Join(segments[1:len(segments)-1], "/")
	return purl, true
}

// exactVersion rejects version ranges such as ^1.2.0 or 4.*.*, which GitHub
// reports when a manifest has no lock file. Ranges do not identify one
// artifact, so they cannot be looked up or linked.
func exactVersion(version string) bool {
	return version != "" && !strings.ContainsAny(version, "^~<>=!*,| ")
}

// escapeModulePath applies the Go module proxy's case encoding.
func escapeModulePath(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if unicode.IsUpper(character) {
			builder.WriteByte('!')
			character = unicode.ToLower(character)
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

func goDownloadLocation(organization string, purl packageURL) string {
	module := path.Join(purl.Namespace, purl.Name)
	version := purl.Version
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !exactVersion(version) {
		return ""
	}

	// Builds fetch organization modules directly from GitHub through
	// GOPRIVATE, so the module proxy does not serve the private ones.
	if strings.HasPrefix(strings.ToLower(module), "github.com/"+strings.ToLower(organization)+"/") {
		segments := strings.Split(module, "/")
		if len(segments) > 4 || (len(segments) == 4 && !majorVersionPattern.MatchString(segments[3])) {
			return ""
		}
		reference := strings.TrimSuffix(version, "+incompatible")
		if match := pseudoVersionPattern.FindStringSubmatch(reference); match != nil {
			reference = match[1]
		}
		return "git+https://" + strings.Join(segments[:3], "/") + "@" + reference
	}
	return "https://proxy.golang.org/" + escapeModulePath(module) + "/@v/" + escapeModulePath(version) + ".zip"
}

func downloadLocation(organization string, purl packageURL, registry packageRegistry) (string, error) {
	switch purl.Type {
	case "golang":
		return goDownloadLocation(organization, purl), nil
	case "npm":
		if !exactVersion(purl.Version) {
			return "", nil
		}
		name := path.Join(purl.Namespace, purl.Name)
		return "https://registry.npmjs.org/" + name + "/-/" + purl.Name + "-" + purl.Version + ".tgz", nil
	case "github", "githubactions":
		// Reusable workflows are addressed as owner/repository/path/to/workflow.yml.
		segments := strings.Split(path.Join(purl.Namespace, purl.Name), "/")
		if len(segments) < 2 {
			return "", nil
		}
		location := "git+https://github.com/" + segments[0] + "/" + segments[1]
		if exactVersion(purl.Version) {
			location += "@" + purl.Version
		}
		if len(segments) > 2 {
			location += "#" + strings.Join(segments[2:], "/")
		}
		return location, nil
	case "pypi":
		if registry == nil || !exactVersion(purl.Version) {
			return "", nil
		}
		return registry.PyPIDownloadLocation(purl.Name, purl.Version)
	}
	return "", nil
}

func declaredLicense(purl packageURL, registry packageRegistry) (string, error) {
	system := depsDevSystems[purl.Type]
	if registry == nil || system == "" || !exactVersion(purl.Version) {
		return "", nil
	}
	version := purl.Version
	if purl.Type == "golang" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return registry.DeclaredLicense(system, path.Join(purl.Namespace, purl.Name), version)
}

func unassertedField(value any) bool {
	text, _ := value.(string)
	return text == "" || text == "NOASSERTION"
}

func packageURLOf(pkg map[string]any) (packageURL, bool) {
	references, _ := pkg["externalRefs"].([]any)
	for _, reference := range references {
		fields, _ := reference.(map[string]any)
		referenceType, _ := fields["referenceType"].(string)
		locator, _ := fields["referenceLocator"].(string)
		if strings.Contains(strings.ToLower(referenceType), "purl") {
			return parsePackageURL(locator)
		}
	}
	return packageURL{}, false
}

// enrichSBOM fills download locations and declared licenses that GitHub's
// Dependency Graph leaves as NOASSERTION. It never replaces an asserted value
// or NONE, and records itself as a document creator when it adds anything.
// Lookup failures leave the affected fields unasserted and are reported in
// the returned error after the rest of the document has been enriched.
func enrichSBOM(document map[string]any, organization string, registry packageRegistry) (enrichment, error) {
	var added enrichment
	var failed int
	var firstErr error
	recordFailure := func(err error) {
		failed++
		if firstErr == nil {
			firstErr = err
		}
	}

	packages, _ := document["packages"].([]any)
	for _, item := range packages {
		pkg, _ := item.(map[string]any)
		purl, found := packageURLOf(pkg)
		if pkg == nil || !found {
			continue
		}
		if unassertedField(pkg["downloadLocation"]) {
			location, err := downloadLocation(organization, purl, registry)
			if err != nil {
				recordFailure(err)
			} else if validDownloadLocation(location) {
				pkg["downloadLocation"] = location
				added.DownloadLocations++
			}
		}
		if unassertedField(pkg["licenseDeclared"]) {
			license, err := declaredLicense(purl, registry)
			if err != nil {
				recordFailure(err)
			} else if license != "" {
				pkg["licenseDeclared"] = license
				added.DeclaredLicenses++
			}
		}
	}

	if added.DownloadLocations > 0 || added.DeclaredLicenses > 0 {
		creationInfo, _ := document["creationInfo"].(map[string]any)
		if creationInfo == nil {
			creationInfo = map[string]any{}
			document["creationInfo"] = creationInfo
		}
		creators, _ := creationInfo["creators"].([]any)
		creationInfo["creators"] = append(creators, enrichmentCreator)
		comment := fmt.Sprintf(
			"uug-ai/secure added download locations to %d packages from their package URLs and PyPI, and declared licenses to %d packages from deps.dev.",
			added.DownloadLocations,
			added.DeclaredLicenses,
		)
		if existing, _ := creationInfo["comment"].(string); existing != "" {
			comment = existing + " " + comment
		}
		creationInfo["comment"] = comment
	}

	if failed > 0 {
		return added, fmt.Errorf("%d package lookups failed: %w", failed, firstErr)
	}
	return added, nil
}
