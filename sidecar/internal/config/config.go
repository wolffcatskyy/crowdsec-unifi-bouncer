// Package config handles loading and parsing of the sidecar configuration.
package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete sidecar configuration.
type Config struct {
	ListenAddr      string        `yaml:"listen_addr"`
	UpstreamLAPIURL string        `yaml:"upstream_lapi_url"`
	UpstreamLAPIKey string        `yaml:"upstream_lapi_key"`
	MaxDecisions    int           `yaml:"max_decisions"`
	CacheTTL        time.Duration `yaml:"cache_ttl"`
	UpstreamTimeout time.Duration `yaml:"upstream_timeout"`
	LogLevel        string        `yaml:"log_level"`
	Scoring         ScoringConfig `yaml:"scoring"`
	Health          HealthConfig  `yaml:"health"`
	Metrics         MetricsConfig `yaml:"metrics"`
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
	Scenarios          map[string]int `yaml:"scenarios"`
	Origins            map[string]int `yaml:"origins"`
	TTLScoring         TTLScoringConfig `yaml:"ttl_scoring"`
	DecisionTypes      map[string]int   `yaml:"decision_types"`
	ScenarioMultiplier float64          `yaml:"scenario_multiplier"`
	FreshnessBonuses   []FreshnessBonus `yaml:"freshness_bonuses"`
	CIDRBonuses        []CIDRBonus      `yaml:"cidr_bonuses"`
	RecidivismBonus    int              `yaml:"recidivism_bonus"`

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
		Scoring: ScoringConfig{
			ScenarioMultiplier: 2.0,
			RecidivismBonus:    15,
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

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.Scoring.compilePatterns(); err != nil {
		return nil, fmt.Errorf("compiling scenario patterns: %w", err)
	}

	return cfg, nil
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
	if c.CacheTTL < 0 {
		return fmt.Errorf("cache_ttl cannot be negative")
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
