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
		{ID: 1, Scenario: "default", Scope: "ip", Value: "1.1.1.1"},
		{ID: 2, Scenario: "ssh-bf", Scope: "ip", Value: "2.2.2.2"},
		{ID: 3, Scenario: "default", Scope: "ip", Value: "3.3.3.3"},
		{ID: 4, Scenario: "ssh-bf", Scope: "ip", Value: "4.4.4.4"},
		{ID: 5, Scenario: "default", Scope: "ip", Value: "5.5.5.5"},
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

func TestScorer_ScoreAndTruncateWithStats_EffectivenessMetrics(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":       50,
			"http-probing": 30,
			"default":      10,
		},
		Origins: map[string]int{
			"crowdsec": 25,
			"CAPI":     10,
		},
		ScenarioMultiplier: 2.0,
		RecidivismBonus:    15,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
		DecisionTypes: map[string]int{
			"ban": 5,
		},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "ssh-bf", Origin: "crowdsec", Type: "ban", Scope: "ip", Value: "1.1.1.1"},     // score: 100+25+5 = 130
		{ID: 2, Scenario: "ssh-bf", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "2.2.2.2"},         // score: 100+10+5 = 115
		{ID: 3, Scenario: "http-probing", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "3.3.3.3"},   // score: 60+10+5 = 75
		{ID: 4, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "4.4.4.4"},        // score: 20+10+5 = 35
		{ID: 5, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "5.5.5.5"},        // score: 20+10+5 = 35
		{ID: 6, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "2.2.2.2"},        // score: 20+10+5+15 = 50 (recidivism for 2.2.2.2)
	}

	// max 4 → keeps top 4, drops 2
	truncated, stats := s.ScoreAndTruncateWithStats(decisions, 4)

	// Basic counts
	if stats.TotalDecisions != 6 {
		t.Errorf("TotalDecisions = %d, want 6", stats.TotalDecisions)
	}
	if stats.ReturnedDecisions != 4 {
		t.Errorf("ReturnedDecisions = %d, want 4", stats.ReturnedDecisions)
	}
	if stats.DroppedDecisions != 2 {
		t.Errorf("DroppedDecisions = %d, want 2", stats.DroppedDecisions)
	}
	if len(truncated) != 4 {
		t.Errorf("Expected 4 decisions, got %d", len(truncated))
	}

	// Origin kept: crowdsec should be 100% preserved
	if stats.OriginKept["crowdsec"] != 1 {
		t.Errorf("OriginKept[crowdsec] = %d, want 1", stats.OriginKept["crowdsec"])
	}
	if stats.OriginDropped["crowdsec"] != 0 {
		t.Errorf("OriginDropped[crowdsec] = %d, want 0", stats.OriginDropped["crowdsec"])
	}

	// Score cutoff: should be the lowest score of kept decisions
	if stats.ScoreCutoff <= 0 {
		t.Errorf("ScoreCutoff = %d, should be > 0", stats.ScoreCutoff)
	}

	// Median should be reasonable (between min and max)
	if stats.MedianScore < stats.MinScore || stats.MedianScore > stats.MaxScore {
		t.Errorf("MedianScore = %d, should be between %d and %d", stats.MedianScore, stats.MinScore, stats.MaxScore)
	}

	// Score buckets should be populated
	if len(stats.ScoreBuckets) == 0 {
		t.Error("ScoreBuckets should not be empty")
	}
	// le=200 should equal TotalDecisions (all scores <= 200)
	if stats.ScoreBuckets[200] != stats.TotalDecisions {
		t.Errorf("ScoreBuckets[200] = %d, want %d (all decisions)", stats.ScoreBuckets[200], stats.TotalDecisions)
	}
	// Buckets should be monotonically increasing
	prev := 0
	for _, threshold := range ScoreBucketThresholds {
		count := stats.ScoreBuckets[threshold]
		if count < prev {
			t.Errorf("ScoreBuckets[%d] = %d < previous %d (not monotonically increasing)", threshold, count, prev)
		}
		prev = count
	}

	// Recidivism: IP 2.2.2.2 appears twice → 1 recidivism IP
	if stats.RecidivismIPs != 1 {
		t.Errorf("RecidivismIPs = %d, want 1", stats.RecidivismIPs)
	}
	// Recidivism boosts: IP 2.2.2.2 count=2, bonus=15, total = 15*(2-1)*2 = 30
	if stats.RecidivismBoosts != 30 {
		t.Errorf("RecidivismBoosts = %d, want 30", stats.RecidivismBoosts)
	}

	// Dropped IPs should contain the 2 dropped IPs
	if len(stats.DroppedIPs) != 2 {
		t.Errorf("DroppedIPs count = %d, want 2", len(stats.DroppedIPs))
	}

	// Scenario kept/dropped should be populated
	if len(stats.ScenarioKept) == 0 {
		t.Error("ScenarioKept should not be empty")
	}
}

func TestScorer_ScoreAndTruncateWithStats_NoTruncation(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf": 50,
		},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	decisions := []lapi.Decision{
		{ID: 1, Scenario: "ssh-bf", Scope: "ip", Value: "1.1.1.1"},
		{ID: 2, Scenario: "ssh-bf", Scope: "ip", Value: "2.2.2.2"},
	}

	result, stats := s.ScoreAndTruncateWithStats(decisions, 100)

	if stats.ReturnedDecisions != 2 {
		t.Errorf("ReturnedDecisions = %d, want 2", stats.ReturnedDecisions)
	}
	if stats.DroppedDecisions != 0 {
		t.Errorf("DroppedDecisions = %d, want 0", stats.DroppedDecisions)
	}
	if len(stats.DroppedIPs) != 0 {
		t.Errorf("DroppedIPs = %d, want 0", len(stats.DroppedIPs))
	}
	if len(stats.OriginDropped) != 0 {
		t.Errorf("OriginDropped should be empty, got %v", stats.OriginDropped)
	}
	// ScoreCutoff should be the lowest score (all kept)
	if stats.ScoreCutoff != 100 {
		t.Errorf("ScoreCutoff = %d, want 100", stats.ScoreCutoff)
	}
	if len(result) != 2 {
		t.Errorf("Expected 2 results, got %d", len(result))
	}
}

func TestScorer_ScoreAndTruncateWithStats_EmptyDecisions(t *testing.T) {
	cfg := &config.ScoringConfig{
		Scenarios:          map[string]int{"default": 10},
		Origins:            map[string]int{},
		ScenarioMultiplier: 2.0,
		TTLScoring:         config.TTLScoringConfig{Enabled: false},
	}

	s := New(cfg)

	result, stats := s.ScoreAndTruncateWithStats([]lapi.Decision{}, 100)

	if stats.TotalDecisions != 0 {
		t.Errorf("TotalDecisions = %d, want 0", stats.TotalDecisions)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 results, got %d", len(result))
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
