package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
listen_addr: "127.0.0.1:8082"
upstream_lapi_url: "http://localhost:8080"
upstream_lapi_key: "test-api-key"
max_decisions: 10000
cache_ttl: 30s
log_level: "debug"

scoring:
  scenario_multiplier: 2.5
  recidivism_bonus: 20
  scenarios:
    ssh-bf: 50
    http-probing: 30
    default: 10
  origins:
    CAPI: 10
    cscli: 20
  decision_types:
    ban: 5
    captcha: 0
  freshness_bonuses:
    - max_age: "1h"
      bonus: 15
    - max_age: "24h"
      bonus: 10
  cidr_bonuses:
    - min_prefix: 0
      max_prefix: 16
      bonus: 20
    - min_prefix: 17
      max_prefix: 32
      bonus: 0
  ttl_scoring:
    enabled: true
    max_bonus: 10
    max_ttl: 168h

health:
  enabled: true
  path: "/healthz"

metrics:
  enabled: false
  path: "/metrics"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check basic values
	if cfg.ListenAddr != "127.0.0.1:8082" {
		t.Errorf("ListenAddr = %v, want 127.0.0.1:8082", cfg.ListenAddr)
	}
	if cfg.UpstreamLAPIURL != "http://localhost:8080" {
		t.Errorf("UpstreamLAPIURL = %v, want http://localhost:8080", cfg.UpstreamLAPIURL)
	}
	if cfg.MaxDecisions != 10000 {
		t.Errorf("MaxDecisions = %v, want 10000", cfg.MaxDecisions)
	}
	if cfg.CacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v, want 30s", cfg.CacheTTL)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}

	// Check scoring
	if cfg.Scoring.Scenarios["ssh-bf"] != 50 {
		t.Errorf("Scoring.Scenarios[ssh-bf] = %v, want 50", cfg.Scoring.Scenarios["ssh-bf"])
	}
	if cfg.Scoring.Origins["CAPI"] != 10 {
		t.Errorf("Scoring.Origins[CAPI] = %v, want 10", cfg.Scoring.Origins["CAPI"])
	}
	if cfg.Scoring.ScenarioMultiplier != 2.5 {
		t.Errorf("Scoring.ScenarioMultiplier = %v, want 2.5", cfg.Scoring.ScenarioMultiplier)
	}
	if cfg.Scoring.RecidivismBonus != 20 {
		t.Errorf("Scoring.RecidivismBonus = %v, want 20", cfg.Scoring.RecidivismBonus)
	}
	if cfg.Scoring.DecisionTypes["ban"] != 5 {
		t.Errorf("Scoring.DecisionTypes[ban] = %v, want 5", cfg.Scoring.DecisionTypes["ban"])
	}
	if len(cfg.Scoring.FreshnessBonuses) != 2 {
		t.Errorf("Scoring.FreshnessBonuses length = %v, want 2", len(cfg.Scoring.FreshnessBonuses))
	}
	if len(cfg.Scoring.CIDRBonuses) != 2 {
		t.Errorf("Scoring.CIDRBonuses length = %v, want 2", len(cfg.Scoring.CIDRBonuses))
	}

	// Check health/metrics
	if !cfg.Health.Enabled {
		t.Error("Health.Enabled should be true")
	}
	if cfg.Health.Path != "/healthz" {
		t.Errorf("Health.Path = %v, want /healthz", cfg.Health.Path)
	}
	if cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled should be false")
	}
}

func TestLoad_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Minimal config
	configContent := `
upstream_lapi_url: "http://localhost:8080"
upstream_lapi_key: "test-api-key"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check defaults
	if cfg.ListenAddr != "127.0.0.1:8081" {
		t.Errorf("ListenAddr default = %v, want 127.0.0.1:8081", cfg.ListenAddr)
	}
	if cfg.MaxDecisions != 15000 {
		t.Errorf("MaxDecisions default = %v, want 15000", cfg.MaxDecisions)
	}
	if cfg.CacheTTL != 60*time.Second {
		t.Errorf("CacheTTL default = %v, want 60s", cfg.CacheTTL)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %v, want info", cfg.LogLevel)
	}
	if cfg.Scoring.ScenarioMultiplier != 2.0 {
		t.Errorf("ScenarioMultiplier default = %v, want 2.0", cfg.Scoring.ScenarioMultiplier)
	}
	if cfg.Scoring.RecidivismBonus != 15 {
		t.Errorf("RecidivismBonus default = %v, want 15", cfg.Scoring.RecidivismBonus)
	}

	// Check effectiveness defaults
	if cfg.Effectiveness.TopScenarios != 20 {
		t.Errorf("Effectiveness.TopScenarios default = %v, want 20", cfg.Effectiveness.TopScenarios)
	}
	if !cfg.Effectiveness.FalseNegativeCheck.Enabled {
		t.Error("Effectiveness.FalseNegativeCheck.Enabled default should be true")
	}
	if cfg.Effectiveness.FalseNegativeCheck.Interval != 5*time.Minute {
		t.Errorf("Effectiveness.FalseNegativeCheck.Interval default = %v, want 5m", cfg.Effectiveness.FalseNegativeCheck.Interval)
	}
	if cfg.Effectiveness.FalseNegativeCheck.Lookback != 15*time.Minute {
		t.Errorf("Effectiveness.FalseNegativeCheck.Lookback default = %v, want 15m", cfg.Effectiveness.FalseNegativeCheck.Lookback)
	}
}

func TestLoad_EffectivenessOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
upstream_lapi_url: "http://localhost:8080"
upstream_lapi_key: "test-api-key"

effectiveness:
  top_scenarios: 10
  false_negative_check:
    enabled: false
    interval: 10m
    lookback: 30m
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Effectiveness.TopScenarios != 10 {
		t.Errorf("TopScenarios = %v, want 10", cfg.Effectiveness.TopScenarios)
	}
	if cfg.Effectiveness.FalseNegativeCheck.Enabled {
		t.Error("FalseNegativeCheck.Enabled should be false")
	}
	if cfg.Effectiveness.FalseNegativeCheck.Interval != 10*time.Minute {
		t.Errorf("FalseNegativeCheck.Interval = %v, want 10m", cfg.Effectiveness.FalseNegativeCheck.Interval)
	}
	if cfg.Effectiveness.FalseNegativeCheck.Lookback != 30*time.Minute {
		t.Errorf("FalseNegativeCheck.Lookback = %v, want 30m", cfg.Effectiveness.FalseNegativeCheck.Lookback)
	}
}

func TestLoad_Validation(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "missing upstream_lapi_url",
			content: `
upstream_lapi_key: "test"
`,
			wantErr: true,
		},
		{
			name: "missing upstream_lapi_key",
			content: `
upstream_lapi_url: "http://localhost:8080"
`,
			wantErr: true,
		},
		{
			name: "negative max_decisions",
			content: `
upstream_lapi_url: "http://localhost:8080"
upstream_lapi_key: "test"
max_decisions: -1
`,
			wantErr: true,
		},
		{
			name: "valid minimal config",
			content: `
upstream_lapi_url: "http://localhost:8080"
upstream_lapi_key: "test"
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(tmpDir, tt.name+".yaml")
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			_, err := Load(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScoringConfig_GetScenarioScore(t *testing.T) {
	cfg := &ScoringConfig{
		Scenarios: map[string]int{
			"ssh-bf":       50,
			"http-cve-.*":  55, // regex pattern
			"http-probing": 30,
			"default":      10,
		},
	}

	// Compile patterns
	if err := cfg.compilePatterns(); err != nil {
		t.Fatalf("compilePatterns() error = %v", err)
	}

	tests := []struct {
		scenario string
		want     int
	}{
		{"ssh-bf", 50},             // exact match
		{"http-probing", 30},       // exact match
		{"http-cve-2024-1234", 55}, // regex match
		{"http-cve-2023-5678", 55}, // regex match
		{"unknown", 10},            // default
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			got := cfg.GetScenarioScore(tt.scenario)
			if got != tt.want {
				t.Errorf("GetScenarioScore(%q) = %v, want %v", tt.scenario, got, tt.want)
			}
		})
	}
}

func TestScoringConfig_GetOriginScore(t *testing.T) {
	cfg := &ScoringConfig{
		Origins: map[string]int{
			"CAPI":     10,
			"cscli":    20,
			"crowdsec": 25,
		},
	}

	tests := []struct {
		origin string
		want   int
	}{
		{"CAPI", 10},
		{"cscli", 20},
		{"crowdsec", 25},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			got := cfg.GetOriginScore(tt.origin)
			if got != tt.want {
				t.Errorf("GetOriginScore(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestScoringConfig_GetDecisionTypeScore(t *testing.T) {
	cfg := &ScoringConfig{
		DecisionTypes: map[string]int{
			"ban":     5,
			"captcha": 0,
		},
	}

	tests := []struct {
		dtype string
		want  int
	}{
		{"ban", 5},
		{"captcha", 0},
		{"throttle", 0},
	}

	for _, tt := range tests {
		t.Run(tt.dtype, func(t *testing.T) {
			got := cfg.GetDecisionTypeScore(tt.dtype)
			if got != tt.want {
				t.Errorf("GetDecisionTypeScore(%q) = %v, want %v", tt.dtype, got, tt.want)
			}
		})
	}
}

func TestScoringConfig_GetFreshnessBonus(t *testing.T) {
	cfg := &ScoringConfig{
		FreshnessBonuses: []FreshnessBonus{
			{MaxAge: "1h", Bonus: 15},
			{MaxAge: "24h", Bonus: 10},
			{MaxAge: "168h", Bonus: 5},
		},
	}

	tests := []struct {
		age  time.Duration
		want int
	}{
		{30 * time.Minute, 15},  // < 1h -> 15
		{2 * time.Hour, 10},     // < 24h -> 10
		{100 * time.Hour, 5},    // < 168h -> 5
		{200 * time.Hour, 0},    // > 168h -> 0
	}

	for _, tt := range tests {
		got := cfg.GetFreshnessBonus(tt.age)
		if got != tt.want {
			t.Errorf("GetFreshnessBonus(%v) = %v, want %v", tt.age, got, tt.want)
		}
	}
}

func TestScoringConfig_GetCIDRBonus(t *testing.T) {
	cfg := &ScoringConfig{
		CIDRBonuses: []CIDRBonus{
			{MinPrefix: 0, MaxPrefix: 16, Bonus: 20},
			{MinPrefix: 17, MaxPrefix: 24, Bonus: 10},
			{MinPrefix: 25, MaxPrefix: 32, Bonus: 0},
		},
	}

	tests := []struct {
		prefix int
		want   int
	}{
		{8, 20},   // /8 -> 20
		{16, 20},  // /16 -> 20
		{24, 10},  // /24 -> 10
		{32, 0},   // /32 -> 0
	}

	for _, tt := range tests {
		got := cfg.GetCIDRBonus(tt.prefix)
		if got != tt.want {
			t.Errorf("GetCIDRBonus(%d) = %v, want %v", tt.prefix, got, tt.want)
		}
	}
}

func TestScoringConfig_GetScenarioMultiplier(t *testing.T) {
	cfg1 := &ScoringConfig{ScenarioMultiplier: 3.0}
	if got := cfg1.GetScenarioMultiplier(); got != 3.0 {
		t.Errorf("GetScenarioMultiplier() = %v, want 3.0", got)
	}

	cfg2 := &ScoringConfig{ScenarioMultiplier: 0}
	if got := cfg2.GetScenarioMultiplier(); got != 2.0 {
		t.Errorf("GetScenarioMultiplier() default = %v, want 2.0", got)
	}
}
