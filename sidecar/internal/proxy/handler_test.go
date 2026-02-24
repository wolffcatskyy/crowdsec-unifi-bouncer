package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/scorer"
)

func testConfig(lapiURL string) *config.Config {
	return &config.Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamLAPIURL: lapiURL,
		UpstreamLAPIKey: "test-key",
		MaxDecisions:    3,
		CacheTTL:        60 * time.Second,
		UpstreamTimeout: 10 * time.Second,
		LogLevel:        "debug",
		Scoring: config.ScoringConfig{
			Scenarios: map[string]int{
				"ssh-bf":  50,
				"default": 10,
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
		},
		Health: config.HealthConfig{
			Enabled: true,
			Path:    "/health",
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
		},
		Effectiveness: config.EffectivenessConfig{
			TopScenarios: 20,
			FalseNegativeCheck: config.FalseNegativeConfig{
				Enabled:  true,
				Interval: 1 * time.Second,
				Lookback: 15 * time.Minute,
			},
		},
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestHandler_MetricsContainsEffectivenessMetrics(t *testing.T) {
	decisions := []lapi.Decision{
		{ID: 1, Scenario: "ssh-bf", Origin: "crowdsec", Type: "ban", Scope: "ip", Value: "1.1.1.1"},
		{ID: 2, Scenario: "ssh-bf", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "2.2.2.2"},
		{ID: 3, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "3.3.3.3"},
		{ID: 4, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "4.4.4.4"},
		{ID: 5, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "5.5.5.5"},
	}

	// Mock LAPI server
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decisions":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(decisions)
		case "/health":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer lapiServer.Close()

	cfg := testConfig(lapiServer.URL)
	handler := New(cfg, testLogger())

	// First, trigger a decisions fetch to populate cache stats
	req := httptest.NewRequest("GET", "/v1/decisions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("decisions request failed: %d", rr.Code)
	}

	// Now fetch metrics
	req = httptest.NewRequest("GET", "/metrics", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("metrics request failed: %d", rr.Code)
	}

	body := rr.Body.String()

	// Check existing operational metrics
	expectedMetrics := []string{
		"crowdsec_sidecar_requests_total",
		"crowdsec_sidecar_decisions_total",
		"crowdsec_sidecar_decisions_dropped",
	}

	// Check new effectiveness metrics
	effectivenessMetrics := []string{
		"crowdsec_sidecar_decisions_kept{origin=",
		"crowdsec_sidecar_decisions_dropped_by_origin{origin=",
		"crowdsec_sidecar_scenario_kept{scenario=",
		"crowdsec_sidecar_scenario_dropped{scenario=",
		"crowdsec_sidecar_score_cutoff",
		"crowdsec_sidecar_score_max",
		"crowdsec_sidecar_score_median",
		"crowdsec_sidecar_score_bucket{le=",
		"crowdsec_sidecar_recidivism_ips",
		"crowdsec_sidecar_recidivism_boosts",
		"crowdsec_sidecar_false_negatives_total",
		"crowdsec_sidecar_false_negative_check_time",
	}

	for _, metric := range append(expectedMetrics, effectivenessMetrics...) {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}

	// Verify specific values
	// 5 total decisions, max 3 kept, so 2 dropped
	if !strings.Contains(body, "crowdsec_sidecar_decisions_total 5") {
		t.Error("expected decisions_total 5")
	}
	if !strings.Contains(body, "crowdsec_sidecar_decisions_dropped 2") {
		t.Error("expected decisions_dropped 2")
	}

	// crowdsec origin: 1 kept (ssh-bf scores highest), 0 dropped
	if !strings.Contains(body, `crowdsec_sidecar_decisions_kept{origin="crowdsec"} 1`) {
		t.Error("expected crowdsec origin kept=1")
	}

	// false negatives should be 0
	if !strings.Contains(body, "crowdsec_sidecar_false_negatives_total 0") {
		t.Error("expected false_negatives_total 0")
	}
}

func TestHandler_FalseNegativeDetection(t *testing.T) {
	alertsServed := false

	// Mock LAPI: serves decisions and alerts
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decisions":
			decisions := []lapi.Decision{
				{ID: 1, Scenario: "ssh-bf", Origin: "crowdsec", Type: "ban", Scope: "ip", Value: "1.1.1.1"},
				{ID: 2, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "2.2.2.2"},
				{ID: 3, Scenario: "default", Origin: "CAPI", Type: "ban", Scope: "ip", Value: "3.3.3.3"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(decisions)
		case "/v1/alerts":
			alertsServed = true
			// Return an alert for an IP that was dropped (3.3.3.3 will be dropped with max_decisions=2)
			alerts := []lapi.Alert{
				{ID: 100, Scenario: "crowdsecurity/ssh-bf", Source: lapi.AlertSource{IP: "3.3.3.3", Scope: "ip", Value: "3.3.3.3"}},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(alerts)
		case "/health":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer lapiServer.Close()

	cfg := testConfig(lapiServer.URL)
	cfg.MaxDecisions = 2 // Keep only 2 of 3 decisions
	handler := New(cfg, testLogger())

	// Trigger a decisions fetch to populate droppedIPs
	req := httptest.NewRequest("GET", "/v1/decisions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("decisions request failed: %d", rr.Code)
	}

	// Verify droppedIPs is populated
	handler.droppedIPsMu.RLock()
	droppedCount := len(handler.droppedIPs)
	handler.droppedIPsMu.RUnlock()

	if droppedCount == 0 {
		t.Fatal("expected droppedIPs to be populated after decisions fetch")
	}

	// Run false-negative check manually
	handler.runFalseNegativeCheck(context.Background())

	if !alertsServed {
		t.Fatal("expected LAPI alerts endpoint to be queried")
	}

	// Check if false negative was detected
	fnTotal := handler.falseNegativesTotal.Load()
	if fnTotal != 1 {
		t.Errorf("expected 1 false negative, got %d", fnTotal)
	}

	// Check that last check time was updated
	lastCheck := handler.falseNegativeLastCheck.Load()
	if lastCheck == 0 {
		t.Error("expected falseNegativeLastCheck to be updated")
	}
}

func TestHandler_FalseNegativeNoDroppedIPs(t *testing.T) {
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/alerts":
			t.Error("alerts endpoint should not be called when no dropped IPs")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer lapiServer.Close()

	cfg := testConfig(lapiServer.URL)
	handler := New(cfg, testLogger())

	// Run check with no dropped IPs — should skip LAPI query
	handler.runFalseNegativeCheck(context.Background())

	lastCheck := handler.falseNegativeLastCheck.Load()
	if lastCheck == 0 {
		t.Error("expected falseNegativeLastCheck to be updated even with no dropped IPs")
	}
}

func TestHandler_BackgroundChecksLifecycle(t *testing.T) {
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	}))
	defer lapiServer.Close()

	cfg := testConfig(lapiServer.URL)
	cfg.Effectiveness.FalseNegativeCheck.Interval = 100 * time.Millisecond
	handler := New(cfg, testLogger())

	// Start background checks
	handler.StartBackgroundChecks(context.Background())

	// Let it run a couple ticks
	time.Sleep(350 * time.Millisecond)

	// Stop should not hang
	done := make(chan struct{})
	go func() {
		handler.StopBackgroundChecks()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("StopBackgroundChecks timed out")
	}
}

func TestHandler_MetricsTopNAggregation(t *testing.T) {
	// Create a handler with pre-populated cache stats that have many scenarios
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer lapiServer.Close()

	cfg := testConfig(lapiServer.URL)
	cfg.Effectiveness.TopScenarios = 2 // Only show top 2
	handler := New(cfg, testLogger())

	// Manually populate cache stats
	handler.cacheMu.Lock()
	handler.cacheStats = scorer.Stats{
		TotalDecisions:    100,
		ReturnedDecisions: 50,
		DroppedDecisions:  50,
		ScenarioKept: map[string]int{
			"ssh-bf":       20,
			"http-probing": 15,
			"http-sqli":    10,
			"default":      5,
		},
		ScenarioDropped: map[string]int{
			"default":           30,
			"http-bad-ua":       15,
			"http-path-trav":    5,
		},
		OriginKept:    map[string]int{"crowdsec": 20, "CAPI": 30},
		OriginDropped: map[string]int{"CAPI": 50},
		ScoreBuckets:  map[int]int{25: 10, 50: 30, 75: 60, 100: 80, 150: 95, 200: 100},
		DroppedIPs:    make(map[string]struct{}),
	}
	handler.cacheMu.Unlock()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()

	// Top 2 kept scenarios should be ssh-bf (20) and http-probing (15)
	if !strings.Contains(body, `crowdsec_sidecar_scenario_kept{scenario="ssh-bf"} 20`) {
		t.Error("expected ssh-bf in top N kept")
	}
	if !strings.Contains(body, `crowdsec_sidecar_scenario_kept{scenario="http-probing"} 15`) {
		t.Error("expected http-probing in top N kept")
	}
	// Remaining should be aggregated as "other" = 10 + 5 = 15
	if !strings.Contains(body, `crowdsec_sidecar_scenario_kept{scenario="other"} 15`) {
		t.Error("expected 'other' aggregation = 15 for kept scenarios")
	}

	// Top 2 dropped scenarios should be default (30) and http-bad-ua (15)
	if !strings.Contains(body, `crowdsec_sidecar_scenario_dropped{scenario="default"} 30`) {
		t.Error("expected default in top N dropped")
	}
	// "other" for dropped = 5
	if !strings.Contains(body, `crowdsec_sidecar_scenario_dropped{scenario="other"} 5`) {
		t.Error("expected 'other' aggregation = 5 for dropped scenarios")
	}
}
