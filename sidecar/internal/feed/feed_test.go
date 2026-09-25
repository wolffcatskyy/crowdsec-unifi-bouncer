package feed

import "testing"

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Spamhaus DROP":               "spamhaus-drop",
		"Tor (dan.me.uk)":             "tor-dan-me-uk",
		"Blocklist.de all":            "blocklist-de-all",
		"Static scanner IPs (Censys)": "static-scanner-ips-censys",
		"  IPsum level4 ":             "ipsum-level4",
		"all sources":                 "all-sources",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	p := NewParser([]string{"external/blocklist-import/"}, []string{"external/blocklist"})

	tests := []struct {
		scenario string
		ok       bool
		want     Info
	}{
		{"external/blocklist-import/spamhaus-drop/c95", true, Info{Slug: "spamhaus-drop", Confidence: 95, HasConfidence: true}},
		{"external/blocklist-import/tor-exit-nodes/c0", true, Info{Slug: "tor-exit-nodes", Confidence: 0, HasConfidence: true}},
		{"external/blocklist-import/firehol-level1/c100", true, Info{Slug: "firehol-level1", Confidence: 100, HasConfidence: true}},
		{"external/blocklist-import/spamhaus-drop", true, Info{Slug: "spamhaus-drop"}},
		{"external/blocklist-import/all-sources", true, Info{Slug: "all-sources"}},
		// Out-of-range confidence: feed still recognized, confidence ignored.
		{"external/blocklist-import/spamhaus-drop/c101", true, Info{Slug: "spamhaus-drop"}},
		{"external/blocklist (Spamhaus DROP)", true, Info{Slug: "spamhaus-drop", Legacy: true}},
		{"external/blocklist (all sources)", true, Info{Slug: "all-sources", Legacy: true}},
		// Not blocklist-import scenarios.
		{"crowdsecurity/ssh-bf", false, Info{}},
		{"ssh-bf", false, Info{}},
		{"external/blocklist", false, Info{}},
		{"external/blocklist-import/", false, Info{}},
		{"external/blocklist-import/Bad_Slug/c50", false, Info{}},
		{"external/blocklist-import/spamhaus-drop/c95/extra", false, Info{}},
		{"external/malware (Spamhaus DROP)", false, Info{}},
		{"external/blocklist-importer/spamhaus-drop/c95", false, Info{}},
	}
	for _, tt := range tests {
		got, ok := p.Parse(tt.scenario)
		if ok != tt.ok || got != tt.want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v, %v", tt.scenario, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseLegacyDisabled(t *testing.T) {
	p := NewParser([]string{"external/blocklist-import"}, nil)
	if _, ok := p.Parse("external/blocklist (Spamhaus DROP)"); ok {
		t.Error("legacy scenario parsed with no legacy prefixes configured")
	}
}
