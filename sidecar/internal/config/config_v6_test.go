package config

import "testing"

func TestEffectiveMaxDecisionsV6FallsBack(t *testing.T) {
	c := &Config{MaxDecisions: 15000}
	if got := c.EffectiveMaxDecisionsV6(); got != 15000 {
		t.Errorf("EffectiveMaxDecisionsV6() = %d, want fallback 15000", got)
	}
}

func TestEffectiveMaxDecisionsV6Explicit(t *testing.T) {
	c := &Config{MaxDecisions: 15000, MaxDecisionsV6: 3000}
	if got := c.EffectiveMaxDecisionsV6(); got != 3000 {
		t.Errorf("EffectiveMaxDecisionsV6() = %d, want 3000", got)
	}
}

func TestValidateRejectsNegativeMaxDecisionsV6(t *testing.T) {
	c := &Config{
		ListenAddr:      "127.0.0.1:8081",
		UpstreamLAPIURL: "http://x",
		UpstreamLAPIKey: "k",
		MaxDecisions:    100,
		MaxDecisionsV6:  -1,
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate() should reject negative max_decisions_v6")
	}
}
