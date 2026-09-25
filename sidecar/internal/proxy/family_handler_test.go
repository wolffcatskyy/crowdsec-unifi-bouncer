package proxy

import (
	"log/slog"
	"os"
	"testing"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

// Per-family capping: a v6 flood must not evict v4 decisions and vice versa,
// because the device's v4 and v6 ipsets have separate maxelem.
func TestScoreAndCapPerFamily(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.MaxDecisions = 2
	cfg.MaxDecisionsV6 = 1
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h := New(cfg, logger)

	decisions := []lapi.Decision{
		{Value: "1.1.1.1", Origin: "CAPI", Type: "ban", Scenario: "ssh-bf"},
		{Value: "2.2.2.2", Origin: "CAPI", Type: "ban", Scenario: "ssh-bf"},
		{Value: "3.3.3.3", Origin: "CAPI", Type: "ban", Scenario: "http-xss"},
		{Value: "2001:db8::1", Origin: "CAPI", Type: "ban", Scenario: "ssh-bf"},
		{Value: "2001:db8::2", Origin: "CAPI", Type: "ban", Scenario: "ssh-bf"},
		{Value: "2001:db8::3", Origin: "CAPI", Type: "ban", Scenario: "ssh-bf"},
	}

	kept, stats := h.scoreAndCapPerFamily(decisions)

	var keptV4, keptV6 int
	for _, d := range kept {
		if IsV6(d) {
			keptV6++
		} else {
			keptV4++
		}
	}
	if keptV4 != 2 {
		t.Errorf("kept v4 = %d, want 2 (max_decisions)", keptV4)
	}
	if keptV6 != 1 {
		t.Errorf("kept v6 = %d, want 1 (max_decisions_v6)", keptV6)
	}
	if stats.TotalDecisions != 6 || stats.ReturnedDecisions != 3 || stats.DroppedDecisions != 3 {
		t.Errorf("stats = %d/%d/%d, want 6/3/3", stats.TotalDecisions, stats.ReturnedDecisions, stats.DroppedDecisions)
	}
	if len(stats.DroppedIPs) != 3 {
		t.Errorf("DroppedIPs = %d, want 3", len(stats.DroppedIPs))
	}
}

// Without max_decisions_v6 set, the v6 cap falls back to max_decisions.
func TestScoreAndCapPerFamilyV6Fallback(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.MaxDecisions = 2
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h := New(cfg, logger)
	if h.cfg.EffectiveMaxDecisionsV6() != 2 {
		t.Fatalf("EffectiveMaxDecisionsV6 = %d, want fallback 2", h.cfg.EffectiveMaxDecisionsV6())
	}
}
