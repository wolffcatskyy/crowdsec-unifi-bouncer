package scorer

import (
	"testing"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

func TestScorer_Score(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":              50,
			"http-probing":        30,
			"http-bad-user-agent": 20,
			"default":             10,
		},
		Origins: map[string]int{
			"CAPI":     10,
			"cscli":    20,
			"crowdsec": 25,
		},
		ScenarioMultiplier: 2.0,
		DecisionTypes: map[string]int{
			"ban":     5,
			"captcha": 0,
		},
		TTLScoring: config.TTLScoringConfig{
			Enabled:  true,
			MaxBonus: 10,
			MaxTTL:   168 * time.Hour, // 7 days
		},
	}

	s := New(cfg)

	tests := []struct {
		name     string
		decision lapi.Decision
		want     int
	}{
		{
			name: "SSH brute force from CAPI with long TTL and ban type",
			decision: lapi.Decision{
				Scenario:       "ssh-bf",
				Origin:         "CAPI",
				Type:           "ban",
				Scope:          "ip",
				ParsedDuration: 168 * time.Hour,
			},
			// scenario(50*2.0) + origin(10) + TTL(10) + type(5) + CIDR(/32=0)
			want: 100 + 10 + 10 + 5,
		},
		{
			name: "HTTP probing from crowdsec with short TTL",
			decision: lapi.Decision{
				Scenario:       "http-probing",
				Origin:         "crowdsec",
				Type:           "ban",
				Scope:          "ip",
				ParsedDuration: 4 * time.Hour,
			},
			// scenario(30*2.0) + origin(25) + TTL(~0) + type(5)
			want: 60 + 25 + 0 + 5,
		},
		{
			name: "Unknown scenario from cscli",
			decision: lapi.Decision{
				Scenario:       "custom/my-scenario",
				Origin:         "cscli",
				Type:           "ban",
				Scope:          "ip",
				ParsedDuration: 24 * time.Hour,
			},
			// scenario(10*2.0) + origin(20) + TTL(~1) + type(5)
			want: 20 + 20 + 1 + 5,
		},
		{
			name: "Unknown origin with no TTL",
			decision: lapi.Decision{
				Scenario: "ssh-bf",
				Origin:   "unknown",
				Scope:    "ip",
			},
			// scenario(50*2.0) + origin(0) + TTL(0) + type(0)
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Score(&tt.decision)
			if got != tt.want {
				t.Errorf("Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScorer_ScoreAndSort(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":       50,
			"http-probing": 30,
			"default":      10,
		},
		Origins: map[string]int{
			"CAPI": 10,
		},
		ScenarioMultiplier: 2.0,
		TTLScoring: config.TTLScoringConfig{
			Enabled: false,
		},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "http-probing", Origin: "crowdsec", Scope: "ip"}, // score: 60
		{ID: 2, Scenario: "ssh-bf", Origin: "CAPI", Scope: "ip"},          // score: 110
		{ID: 3, Scenario: "unknown", Origin: "CAPI", Scope: "ip"},         // score: 30
		{ID: 4, Scenario: "ssh-bf", Origin: "crowdsec", Scope: "ip"},      // score: 100
	}

	sorted := s.ScoreAndSort(decisions)

	// Should be sorted by score descending
	expectedOrder := []int{2, 4, 1, 3}
	for i, d := range sorted {
		if d.ID != expectedOrder[i] {
			t.Errorf("Position %d: got ID %d (score %d), want ID %d", i, d.ID, d.Score, expectedOrder[i])
		}
	}
}

func TestScorer_ScoreAndTruncate(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":  50,
			"default": 10,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "default", Scope: "ip"},
		{ID: 2, Scenario: "ssh-bf", Scope: "ip"},
		{ID: 3, Scenario: "default", Scope: "ip"},
		{ID: 4, Scenario: "ssh-bf", Scope: "ip"},
		{ID: 5, Scenario: "default", Scope: "ip"},
	}

	truncated := s.ScoreAndTruncate(decisions, 2)

	if len(truncated) != 2 {
		t.Errorf("Expected 2 decisions, got %d", len(truncated))
	}

	// Should keep the two ssh-bf decisions (highest score)
	for _, d := range truncated {
		if d.Scenario != "ssh-bf" {
			t.Errorf("Expected ssh-bf scenario, got %s", d.Scenario)
		}
	}
}

func TestScorer_ScoreAndTruncateWithStats(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":  50,
			"default": 10,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "default", Scope: "ip"},
		{ID: 2, Scenario: "ssh-bf", Scope: "ip"},
		{ID: 3, Scenario: "default", Scope: "ip"},
		{ID: 4, Scenario: "ssh-bf", Scope: "ip"},
		{ID: 5, Scenario: "default", Scope: "ip"},
	}

	truncated, stats := s.ScoreAndTruncateWithStats(decisions, 3)

	if stats.TotalDecisions != 5 {
		t.Errorf("TotalDecisions = %d, want 5", stats.TotalDecisions)
	}
	if stats.ReturnedDecisions != 3 {
		t.Errorf("ReturnedDecisions = %d, want 3", stats.ReturnedDecisions)
	}
	if stats.DroppedDecisions != 2 {
		t.Errorf("DroppedDecisions = %d, want 2", stats.DroppedDecisions)
	}
	// MaxScore: ssh-bf with 2x multiplier = 100
	if stats.MaxScore != 100 {
		t.Errorf("MaxScore = %d, want 100", stats.MaxScore)
	}
	// MinScore: default with 2x multiplier = 20
	if stats.MinScore != 20 {
		t.Errorf("MinScore = %d, want 20", stats.MinScore)
	}

	if len(truncated) != 3 {
		t.Errorf("Expected 3 decisions, got %d", len(truncated))
	}
}

func TestScorer_TTLBonus(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"default": 0,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		TTLScoring: config.TTLScoringConfig{
			Enabled:  true,
			MaxBonus: 10,
			MaxTTL:   168 * time.Hour, // 7 days
		},
	}

	s := New(cfg)

	tests := []struct {
		ttl      time.Duration
		expected int
	}{
		{0, 0},
		{24 * time.Hour, 1},   // 1 day = ~1.4 -> 1
		{84 * time.Hour, 5},   // 3.5 days = 5
		{168 * time.Hour, 10}, // 7 days = max
		{336 * time.Hour, 10}, // 14 days = max (capped)
	}

	for _, tt := range tests {
		d := &lapi.Decision{Scenario: "default", ParsedDuration: tt.ttl, Scope: "ip"}
		score := s.Score(d)
		if score != tt.expected {
			t.Errorf("TTL %v: got score %d, want %d", tt.ttl, score, tt.expected)
		}
	}
}

func TestScorer_Recidivism(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":  50,
			"default": 10,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		RecidivismBonus:    15,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "ssh-bf", Value: "1.2.3.4", Scope: "ip"},   // appears 2x: base=100 + recidivism=15
		{ID: 2, Scenario: "default", Value: "1.2.3.4", Scope: "ip"},  // appears 2x: base=20 + recidivism=15
		{ID: 3, Scenario: "default", Value: "5.6.7.8", Scope: "ip"},  // appears 1x: base=20, no recidivism
		{ID: 4, Scenario: "ssh-bf", Value: "9.8.7.6", Scope: "ip"},   // appears 3x: base=100 + recidivism=30
		{ID: 5, Scenario: "default", Value: "9.8.7.6", Scope: "ip"},  // appears 3x: base=20 + recidivism=30
		{ID: 6, Scenario: "default", Value: "9.8.7.6", Scope: "ip"},  // appears 3x: base=20 + recidivism=30
	}

	sorted := s.ScoreAndSort(decisions)

	// ID 4: 100 + 30 = 130 (ssh-bf, 3 occurrences of 9.8.7.6)
	if sorted[0].ID != 4 || sorted[0].Score != 130 {
		t.Errorf("Position 0: got ID %d score %d, want ID 4 score 130", sorted[0].ID, sorted[0].Score)
	}

	// ID 1: 100 + 15 = 115 (ssh-bf, 2 occurrences of 1.2.3.4)
	if sorted[1].ID != 1 || sorted[1].Score != 115 {
		t.Errorf("Position 1: got ID %d score %d, want ID 1 score 115", sorted[1].ID, sorted[1].Score)
	}

	// IDs 5 and 6: 20 + 30 = 50 each (default, 3 occurrences of 9.8.7.6)
	if sorted[2].Score != 50 {
		t.Errorf("Position 2: got score %d, want 50", sorted[2].Score)
	}

	// ID 2: 20 + 15 = 35 (default, 2 occurrences of 1.2.3.4)
	if sorted[4].ID != 2 || sorted[4].Score != 35 {
		t.Errorf("Position 4: got ID %d score %d, want ID 2 score 35", sorted[4].ID, sorted[4].Score)
	}

	// ID 3: 20 + 0 = 20 (default, 1 occurrence = no recidivism)
	if sorted[5].ID != 3 || sorted[5].Score != 20 {
		t.Errorf("Position 5: got ID %d score %d, want ID 3 score 20", sorted[5].ID, sorted[5].Score)
	}
}

func TestScorer_FreshnessBonus(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"default": 0,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		FreshnessBonuses: []config.FreshnessBonus{
			{MaxAge: "1h", Bonus: 15},
			{MaxAge: "24h", Bonus: 10},
			{MaxAge: "168h", Bonus: 5},
		},
		TTLScoring: config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	tests := []struct {
		name     string
		age      time.Duration
		expected int
	}{
		{"30 minutes old", 30 * time.Minute, 15},
		{"2 hours old", 2 * time.Hour, 10},
		{"12 hours old", 12 * time.Hour, 10},
		{"3 days old", 72 * time.Hour, 5},
		{"10 days old", 240 * time.Hour, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &lapi.Decision{
				Scenario:      "default",
				Scope:         "ip",
				ParsedCreated: time.Now().Add(-tt.age),
			}
			score := s.Score(d)
			if score != tt.expected {
				t.Errorf("Freshness bonus for %v: got score %d, want %d", tt.age, score, tt.expected)
			}
		})
	}
}

func TestScorer_CIDRBonus(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"default": 0,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		CIDRBonuses: []config.CIDRBonus{
			{MinPrefix: 0, MaxPrefix: 16, Bonus: 20},
			{MinPrefix: 17, MaxPrefix: 24, Bonus: 10},
			{MinPrefix: 25, MaxPrefix: 32, Bonus: 0},
		},
		TTLScoring: config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	tests := []struct {
		name     string
		value    string
		scope    string
		expected int
	}{
		{"single IP", "1.2.3.4", "ip", 0},             // /32 -> 0
		{"/24 range", "1.2.3.0/24", "range", 10},      // /24 -> 10
		{"/16 range", "1.2.0.0/16", "range", 20},      // /16 -> 20
		{"/8 range", "1.0.0.0/8", "range", 20},         // /8 -> 20
		{"/28 range", "1.2.3.0/28", "range", 0},        // /28 -> 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &lapi.Decision{
				Scenario: "default",
				Value:    tt.value,
				Scope:    tt.scope,
			}
			score := s.Score(d)
			if score != tt.expected {
				t.Errorf("CIDR bonus for %s: got score %d, want %d", tt.value, score, tt.expected)
			}
		})
	}
}

func TestScorer_DecisionType(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"default": 0,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		DecisionTypes: map[string]int{
			"ban":     5,
			"captcha": 0,
		},
		TTLScoring: config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	ban := &lapi.Decision{Scenario: "default", Type: "ban", Scope: "ip"}
	captcha := &lapi.Decision{Scenario: "default", Type: "captcha", Scope: "ip"}
	unknown := &lapi.Decision{Scenario: "default", Type: "throttle", Scope: "ip"}

	if got := s.Score(ban); got != 5 {
		t.Errorf("ban type: got %d, want 5", got)
	}
	if got := s.Score(captcha); got != 0 {
		t.Errorf("captcha type: got %d, want 0", got)
	}
	if got := s.Score(unknown); got != 0 {
		t.Errorf("unknown type: got %d, want 0", got)
	}
}

func TestParsePrefixLen(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"1.2.3.4/32", 32},
		{"1.2.3.0/24", 24},
		{"1.2.0.0/16", 16},
		{"1.0.0.0/8", 8},
		{"1.2.3.4", 32},
		{"invalid", 32},
	}

	for _, tt := range tests {
		got := parsePrefixLen(tt.input)
		if got != tt.expected {
			t.Errorf("parsePrefixLen(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}
