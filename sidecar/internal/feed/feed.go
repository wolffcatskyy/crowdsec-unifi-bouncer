// Package feed parses blocklist-import feed provenance out of CrowdSec
// scenario names so the scorer can rank imported decisions by feed quality.
//
// Two scenario formats are recognized:
//
//	Structured (crowdsec-blocklist-import SCENARIO_FORMAT=structured):
//	    <prefix>/<feed-slug>[/c<confidence>]
//	    e.g. external/blocklist-import/spamhaus-drop/c95
//
//	Legacy (crowdsec-blocklist-import default):
//	    <legacy-prefix> (<Feed Name>)
//	    e.g. external/blocklist (Spamhaus DROP)
//
// Feed slugs are lowercase ASCII letters and digits joined by single hyphens.
// Confidence is an integer 0-100 describing how likely an entry from that feed
// is a real, current threat. Legacy names never carry a confidence; one can
// still be supplied per feed slug in config.
package feed

import (
	"regexp"
	"strconv"
	"strings"
)

// Info is the provenance parsed from a scenario name.
type Info struct {
	// Slug is the normalized feed identifier, e.g. "spamhaus-drop".
	Slug string
	// Confidence is 0-100. Only meaningful when HasConfidence is true.
	Confidence int
	// HasConfidence reports whether the scenario carried a confidence value.
	HasConfidence bool
	// Legacy reports whether the scenario used the legacy "prefix (Name)" format.
	Legacy bool
}

var (
	structuredTail = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*)(?:/c([0-9]{1,3}))?$`)
	legacyForm     = regexp.MustCompile(`^(.+) \(([^()]+)\)$`)
	nonAlnum       = regexp.MustCompile(`[^a-z0-9]+`)
)

// Slugify normalizes a human feed name ("Tor (dan.me.uk)") to a slug
// ("tor-dan-me-uk"). It must stay in sync with feed_slug() in
// crowdsec-blocklist-import.
func Slugify(name string) string {
	s := nonAlnum.ReplaceAllString(strings.ToLower(name), "-")
	return strings.Trim(s, "-")
}

// Parser recognizes blocklist-import scenario names for a set of prefixes.
type Parser struct {
	prefixes       []string
	legacyPrefixes []string
}

// NewParser returns a Parser. Prefixes are matched exactly (a trailing slash
// is optional in config and is stripped here).
func NewParser(prefixes, legacyPrefixes []string) *Parser {
	p := &Parser{}
	for _, pr := range prefixes {
		pr = strings.TrimRight(strings.TrimSpace(pr), "/")
		if pr != "" {
			p.prefixes = append(p.prefixes, pr)
		}
	}
	for _, pr := range legacyPrefixes {
		pr = strings.TrimSpace(pr)
		if pr != "" {
			p.legacyPrefixes = append(p.legacyPrefixes, pr)
		}
	}
	return p
}

// Parse extracts feed provenance from a scenario name. ok is false when the
// scenario is not a recognized blocklist-import scenario; callers must then
// leave the decision's score untouched.
func (p *Parser) Parse(scenario string) (Info, bool) {
	for _, pr := range p.prefixes {
		if !strings.HasPrefix(scenario, pr+"/") {
			continue
		}
		m := structuredTail.FindStringSubmatch(scenario[len(pr)+1:])
		if m == nil {
			continue
		}
		info := Info{Slug: m[1]}
		if m[2] != "" {
			c, err := strconv.Atoi(m[2])
			if err == nil && c >= 0 && c <= 100 {
				info.Confidence = c
				info.HasConfidence = true
			}
		}
		return info, true
	}

	if len(p.legacyPrefixes) > 0 {
		if m := legacyForm.FindStringSubmatch(scenario); m != nil {
			for _, pr := range p.legacyPrefixes {
				if m[1] == pr {
					slug := Slugify(m[2])
					if slug == "" {
						return Info{}, false
					}
					return Info{Slug: slug, Legacy: true}, true
				}
			}
		}
	}

	return Info{}, false
}
