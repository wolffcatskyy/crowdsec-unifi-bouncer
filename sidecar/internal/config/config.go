// Package config handles loading and parsing of the sidecar configuration.
package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/abuseipdb"
	"gopkg.in/yaml.v3"
)

// Config represents the complete sidecar configuration.
type Config struct {
	ListenAddr      string              `yaml:"listen_addr"`
	UpstreamLAPIURL string              `yaml:"upstream_lapi_url"`
	UpstreamLAPIKey string              `yaml:"upstream_lapi_key"`
	MaxDecisions    int                 `yaml:"max_decisions"`
	MaxDecisionsV6  int                 `yaml:"max_decisions_v6"`
	EvictionMode    string              `yaml:"eviction_mode"` // "cap" (default) or "evict"
	CacheTTL        time.Duration       `yaml:"cache_ttl"`
	UpstreamTimeout time.Duration       `yaml:"upstream_timeout"`
	LogLevel        string              `yaml:"log_level"`
	Scoring         ScoringConfig       `yaml:"scoring"`
	Health          HealthConfig        `yaml:"health"`
	Metrics         MetricsConfig       `yaml:"metrics"`
	Effectiveness   EffectivenessConfig `yaml:"effectiveness"`
	AbuseIPDB       abuseipdb.Config    `yaml:"abuseipdb"`
}

// FreshnessBonus awards extra points for recently created decisions.
type FreshnessBonus struct {
	MaxAge string `yaml:"max_age"` // e.g. "1h", "24h"
	Bonus  int    `yaml:"bonus"`
}

// CIDRBonus awards extra points based on CIDR prefix length.
type CIDRBonus struct {
	MinPrefix int `yaml:"min_prefix"` // e.g. 16
	MaxPrefix int `yaml:"max_prefix"` // e.g. 24
	Bonus     int `yaml:"bonus"`
}

// ScoringConfig contains all scoring-related settings.
type ScoringConfig struct {
	Scenarios          map[string]int   `yaml:"scenarios"`
	Origins            map[string]int   `yaml:"origins"`
	TTLScoring         TTLScoringConfig `yaml:"ttl_scoring"`
	DecisionTypes      map[string]int   `yaml:"decision_types"`
	ScenarioMultiplier float64          `yaml:"scenario_multiplier"`
	FreshnessBonuses   []FreshnessBonus `yaml:"freshness_bonuses"`
	CIDRBonuses        []CIDRBonus      `yaml:"cidr_bonuses"`
	RecidivismBonus    int              `yaml:"recidivism_bonus"`
	FeedScoring        FeedScoringConfig `yaml:"feed_scoring"`

	// Compiled regex patterns (not from YAML)
	compiledScenarios []scenarioPattern
}

type scenarioPattern struct {
	pattern *regexp.Regexp
	score   int
	raw     string
}

// TTLScoringConfig controls how remaining ban duration affects score.
type TTLScoringConfig struct {
	Enabled  bool          `yaml:"enabled"`
	MaxBonus int           `yaml:"max_bonus"`
	MaxTTL   time.Duration `yaml:"max_ttl"`
}

// FeedScoringConfig ranks crowdsec-blocklist-import decisions by the quality
// of the feed they came from. Feed and confidence are read from the scenario
// name (see internal/feed). The adjustment is a penalty only: a decision from
// a 100-confidence feed keeps its score, a 0-confidence feed loses MaxPenalty
// points. Imported IPs therefore never climb above where they scored before,
// so local detections, manual bans and CAPI keep their priority.
// Decisions with no known confidence are left untouched.
type FeedScoringConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxPenalty is the points removed from a 0-confidence feed decision.
	MaxPenalty int `yaml:"max_penalty"`
	// Prefixes are the structured scenario prefixes to recognize
	// (<prefix>/<feed-slug>[/c<confidence>]).
	Prefixes []string `yaml:"prefixes"`
	// LegacyPrefixes are the legacy scenario bases to recognize
	// ("<base> (<Feed Name>)"). Legacy names carry no confidence, so they
	// only get adjusted when the feed slug is listed in Feeds.
	LegacyPrefixes []string `yaml:"legacy_prefixes"`
	// Feeds overrides confidence per feed slug (0-100). Takes precedence over
	// the confidence embedded in the scenario name.
	Feeds map[string]int `yaml:"feeds"`
}

// Penalty returns the points to subtract for a feed with the given confidence.
func (f *FeedScoringConfig) Penalty(confidence int) int {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	// Round half up: (100-c)*max/100
	return ((100-confidence)*f.MaxPenalty + 50) / 100
}

// HealthConfig controls the health check endpoint.
type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// MetricsConfig controls the metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// EffectivenessConfig controls effectiveness metrics collection.
type EffectivenessConfig struct {
	TopScenarios       int                 `yaml:"top_scenarios"`
	FalseNegativeCheck FalseNegativeConfig `yaml:"false_negative_check"`
}

// FalseNegativeConfig controls the background false-negative detection.
type FalseNegativeConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Lookback time.Duration `yaml:"lookback"`
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{
		// Defaults
		ListenAddr:      "127.0.0.1:8081",
		MaxDecisions:    15000,
		CacheTTL:        60 * time.Second,
		UpstreamTimeout: 120 * time.Second,
		LogLevel:        "info",
		Health: HealthConfig{
			Enabled: true,
			Path:    "/health",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
		},
		Effectiveness: EffectivenessConfig{
			TopScenarios: 20,
			FalseNegativeCheck: FalseNegativeConfig{
				Enabled:  true,
				Interval: 5 * time.Minute,
				Lookback: 15 * time.Minute,
			},
		},
		Scoring: ScoringConfig{
			ScenarioMultiplier: 2.0,
			RecidivismBonus:    15,
			FeedScoring: FeedScoringConfig{
				Enabled:        true,
				MaxPenalty:     30,
				Prefixes:       []string{"external/blocklist-import"},
				LegacyPrefixes: []string{"external/blocklist"},
			},
			TTLScoring: TTLScoringConfig{
				Enabled:  true,
				MaxBonus: 10,
				MaxTTL:   168 * time.Hour,
			},
			DecisionTypes: map[string]int{
				"ban":     5,
				"captcha": 0,
			},
			FreshnessBonuses: []FreshnessBonus{
				{MaxAge: "1h", Bonus: 15},
				{MaxAge: "24h", Bonus: 10},
				{MaxAge: "168h", Bonus: 5},
			},
			CIDRBonuses: []CIDRBonus{
				{MinPrefix: 0, MaxPrefix: 16, Bonus: 20},
				{MinPrefix: 17, MaxPrefix: 24, Bonus: 10},
				{MinPrefix: 25, MaxPrefix: 32, Bonus: 0},
			},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Environment variable overrides
	if envMode := os.Getenv("EVICTION_MODE"); envMode != "" {
		cfg.EvictionMode = envMode
	}
	if cfg.EvictionMode == "" {
		cfg.EvictionMode = "cap"
	}

	// AbuseIPDB environment variable overrides
	if envKey := os.Getenv("ABUSEIPDB_API_KEY"); envKey != "" {
		cfg.AbuseIPDB.APIKey = envKey
	}
	if envEnabled := os.Getenv("ABUSEIPDB_REPORT_ENABLED"); envEnabled != "" {
		cfg.AbuseIPDB.Enabled = envEnabled == "true" || envEnabled == "1"
	}
	// Auto-enable if API key is provided but enabled was not explicitly set.
	if cfg.AbuseIPDB.APIKey != "" && !cfg.AbuseIPDB.Enabled {
		// Check if enabled was explicitly set to false in the config file.
		// If it wasn't set at all (zero value), auto-enable.
		// Since bool zero value is false, we check if the key was provided
		// as a signal that the user wants reporting.
		// Only auto-enable via env var override (already handled above).
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.Scoring.compilePatterns(); err != nil {
		return nil, fmt.Errorf("compiling scenario patterns: %w", err)
	}

	return cfg, nil
}

// EffectiveMaxDecisionsV6 returns the IPv6 decision cap. The v4 and v6
// ipsets have separate maxelem, so their caps are independent; when
// max_decisions_v6 is unset (0) it defaults to 1,000, leaving headroom
// beneath the default 2,000-entry IPv6 ipset. Explicit overrides remain independent.
func (c *Config) EffectiveMaxDecisionsV6() int {
	if c.MaxDecisionsV6 > 0 {
		return c.MaxDecisionsV6
	}
	return 1000
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.UpstreamLAPIURL == "" {
		return fmt.Errorf("upstream_lapi_url is required")
	}
	if c.UpstreamLAPIKey == "" {
		return fmt.Errorf("upstream_lapi_key is required")
	}
	if c.MaxDecisions <= 0 {
		return fmt.Errorf("max_decisions must be positive")
	}
	if c.MaxDecisionsV6 < 0 {
		return fmt.Errorf("max_decisions_v6 cannot be negative")
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("cache_ttl cannot be negative")
	}
	if c.EvictionMode != "" && c.EvictionMode != "cap" && c.EvictionMode != "evict" {
		return fmt.Errorf("eviction_mode must be 'cap' or 'evict', got %q", c.EvictionMode)
	}
	if c.Scoring.FeedScoring.MaxPenalty < 0 {
		return fmt.Errorf("scoring.feed_scoring.max_penalty cannot be negative")
	}
	for slug, conf := range c.Scoring.FeedScoring.Feeds {
		if conf < 0 || conf > 100 {
			return fmt.Errorf("scoring.feed_scoring.feeds[%q] must be 0-100, got %d", slug, conf)
		}
	}
	return nil
}

// compilePatterns compiles scenario name patterns into regexes.
func (s *ScoringConfig) compilePatterns() error {
	s.compiledScenarios = make([]scenarioPattern, 0, len(s.Scenarios))

	for pattern, score := range s.Scenarios {
		if pattern == "default" {
			continue
		}

		re, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			return fmt.Errorf("invalid scenario pattern %q: %w", pattern, err)
		}

		s.compiledScenarios = append(s.compiledScenarios, scenarioPattern{
			pattern: re,
			score:   score,
			raw:     pattern,
		})
	}

	return nil
}

// GetScenarioScore returns the score for a given scenario name.
func (s *ScoringConfig) GetScenarioScore(scenario string) int {
	// Try exact match first
	if score, ok := s.Scenarios[scenario]; ok {
		return score
	}

	// Try pattern match
	for _, sp := range s.compiledScenarios {
		if sp.pattern.MatchString(scenario) {
			return sp.score
		}
	}

	// Fall back to default
	if score, ok := s.Scenarios["default"]; ok {
		return score
	}

	return 0
}

// GetOriginScore returns the score for a given decision origin.
func (s *ScoringConfig) GetOriginScore(origin string) int {
	if score, ok := s.Origins[origin]; ok {
		return score
	}
	return 0
}

// GetDecisionTypeScore returns the score for a given decision type (ban, captcha, etc).
func (s *ScoringConfig) GetDecisionTypeScore(decisionType string) int {
	if s.DecisionTypes == nil {
		return 0
	}
	if score, ok := s.DecisionTypes[decisionType]; ok {
		return score
	}
	return 0
}

// GetFreshnessBonus returns the bonus points for a decision based on when it was created.
func (s *ScoringConfig) GetFreshnessBonus(age time.Duration) int {
	for _, fb := range s.FreshnessBonuses {
		maxAge, err := time.ParseDuration(fb.MaxAge)
		if err != nil {
			continue
		}
		if age <= maxAge {
			return fb.Bonus
		}
	}
	return 0
}

// GetCIDRBonus returns the bonus points based on CIDR prefix length.
// Broader ranges (smaller prefix) get higher scores since they block more addresses.
func (s *ScoringConfig) GetCIDRBonus(prefixLen int) int {
	for _, cb := range s.CIDRBonuses {
		if prefixLen >= cb.MinPrefix && prefixLen <= cb.MaxPrefix {
			return cb.Bonus
		}
	}
	return 0
}

// GetScenarioMultiplier returns the scenario multiplier (default 2.0).
func (s *ScoringConfig) GetScenarioMultiplier() float64 {
	if s.ScenarioMultiplier <= 0 {
		return 2.0
	}
	return s.ScenarioMultiplier
}
