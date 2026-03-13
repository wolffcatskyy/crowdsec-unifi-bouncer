package abuseipdb

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestReporter_Disabled(t *testing.T) {
	r := New(Config{Enabled: false}, testLogger())
	defer r.Stop()

	if r.IsEnabled() {
		t.Error("reporter should be disabled")
	}

	// Should be safe to call even when disabled.
	r.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "ip",
	})

	metrics := r.GetMetrics()
	if metrics.ReportsTotal != 0 {
		t.Errorf("expected 0 total reports, got %d", metrics.ReportsTotal)
	}
}

func TestReporter_DisabledWithoutAPIKey(t *testing.T) {
	r := New(Config{Enabled: true, APIKey: ""}, testLogger())
	defer r.Stop()

	if r.IsEnabled() {
		t.Error("reporter should be disabled without API key")
	}
}

func TestReporter_SuccessfulReport(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)

		// Verify headers.
		if r.Header.Get("Key") != "test-api-key" {
			t.Errorf("expected Key header 'test-api-key', got %q", r.Header.Get("Key"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header 'application/json', got %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type 'application/x-www-form-urlencoded', got %q", r.Header.Get("Content-Type"))
		}

		// Verify form data.
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}
		if r.FormValue("ip") != "1.2.3.4" {
			t.Errorf("expected ip=1.2.3.4, got %q", r.FormValue("ip"))
		}
		if r.FormValue("categories") != "22,18" {
			t.Errorf("expected categories=22,18 (SSH), got %q", r.FormValue("categories"))
		}

		// Return success.
		resp := reportResponse{}
		resp.Data.IPAddress = "1.2.3.4"
		resp.Data.AbuseConfidenceScore = 100
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "crowdsecurity/ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "ip",
		Duration: "4h",
	})

	// Wait for async processing.
	reporter.Stop()

	if received.Load() != 1 {
		t.Errorf("expected 1 report sent, got %d", received.Load())
	}

	metrics := reporter.GetMetrics()
	if metrics.ReportsTotal != 1 {
		t.Errorf("expected ReportsTotal=1, got %d", metrics.ReportsTotal)
	}
	if metrics.ReportsSuccess != 1 {
		t.Errorf("expected ReportsSuccess=1, got %d", metrics.ReportsSuccess)
	}
}

func TestReporter_SkipsCAPIDecisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not send report for CAPI decisions")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "CAPI",
		Type:     "ban",
		Scope:    "ip",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsSkipped != 1 {
		t.Errorf("expected ReportsSkipped=1, got %d", metrics.ReportsSkipped)
	}
}

func TestReporter_SkipsBlocklistOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not send report for blocklist-import decisions")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	origins := []string{
		"lists:firehol_level1",
		"lists:blocklist_de",
		"blocklist-import",
	}

	for _, origin := range origins {
		reporter.ReportDecision(lapi.Decision{
			Value:    "1.2.3.4",
			Scenario: "ssh-bf",
			Origin:   origin,
			Type:     "ban",
			Scope:    "ip",
		})
	}

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsSkipped != 3 {
		t.Errorf("expected ReportsSkipped=3, got %d", metrics.ReportsSkipped)
	}
}

func TestReporter_SkipsNonBanDecisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not send report for non-ban decisions")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "captcha",
		Scope:    "ip",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsSkipped != 1 {
		t.Errorf("expected ReportsSkipped=1, got %d", metrics.ReportsSkipped)
	}
}

func TestReporter_SkipsCIDRRanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not send report for CIDR ranges")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.0/24",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "range",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsSkipped != 1 {
		t.Errorf("expected ReportsSkipped=1, got %d", metrics.ReportsSkipped)
	}
}

func TestReporter_RateLimit(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		resp := reportResponse{}
		resp.Data.IPAddress = r.FormValue("ip")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 3, // Very low limit for testing.
	}, testLogger())

	// Send 5 reports; only 3 should go through.
	for i := 0; i < 5; i++ {
		reporter.ReportDecision(lapi.Decision{
			Value:    "1.2.3." + string(rune('1'+i)),
			Scenario: "ssh-bf",
			Origin:   "crowdsec",
			Type:     "ban",
			Scope:    "ip",
		})
	}

	reporter.Stop()

	if received.Load() != 3 {
		t.Errorf("expected 3 reports sent (rate limited), got %d", received.Load())
	}

	metrics := reporter.GetMetrics()
	if metrics.ReportsSkipped != 2 {
		t.Errorf("expected ReportsSkipped=2 (rate limited), got %d", metrics.ReportsSkipped)
	}
}

func TestReporter_RateLimitWindowReset(t *testing.T) {
	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-key",
		DailyLimit: 2,
	}, testLogger())

	// Fill up the window.
	reporter.mu.Lock()
	reporter.reportCount = 2
	reporter.windowStart = time.Now().Add(-25 * time.Hour) // 25 hours ago.
	reporter.mu.Unlock()

	// Should succeed because the window has expired.
	got := reporter.acquireRateSlot()
	if !got {
		t.Error("expected rate slot to be available after window expiry")
	}

	reporter.mu.Lock()
	if reporter.reportCount != 1 {
		t.Errorf("expected reportCount=1 after reset, got %d", reporter.reportCount)
	}
	reporter.mu.Unlock()

	reporter.Stop()
}

func TestReporter_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "ip",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsFailed != 1 {
		t.Errorf("expected ReportsFailed=1, got %d", metrics.ReportsFailed)
	}
}

func TestReporter_API429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "ip",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsFailed != 1 {
		t.Errorf("expected ReportsFailed=1 (429), got %d", metrics.ReportsFailed)
	}
}

func TestReporter_APIResponseWithErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":[{"detail":"IP already reported","status":422}]}`))
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		Type:     "ban",
		Scope:    "ip",
	})

	reporter.Stop()

	metrics := reporter.GetMetrics()
	if metrics.ReportsFailed != 1 {
		t.Errorf("expected ReportsFailed=1 (API error), got %d", metrics.ReportsFailed)
	}
}

func TestReporter_ConcurrentReports(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		resp := reportResponse{}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 1000,
	}, testLogger())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			reporter.ReportDecision(lapi.Decision{
				Value:    "10.0.0." + string(rune('0'+n%10)),
				Scenario: "ssh-bf",
				Origin:   "crowdsec",
				Type:     "ban",
				Scope:    "ip",
			})
		}(i)
	}
	wg.Wait()

	reporter.Stop()

	if received.Load() != 20 {
		t.Errorf("expected 20 reports, got %d", received.Load())
	}
}

func TestMapScenarioToCategories(t *testing.T) {
	tests := []struct {
		scenario string
		want     string
	}{
		{"crowdsecurity/ssh-bf", "22,18"},
		{"crowdsecurity/ssh-slow-bf", "22,18"},
		{"ssh-bf", "22,18"},
		{"crowdsecurity/http-probing", "21"},
		{"crowdsecurity/http-sqli", "21"},
		{"http-cve-2024-1234", "21"},
		{"crowdsecurity/smb-bf", "18"},
		{"crowdsecurity/telnet-bf", "23,18"},
		{"ftp-brute", "18"},
		{"unknown-scenario", "14"},
		{"", "14"},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			got := mapScenarioToCategories(tt.scenario)
			if got != tt.want {
				t.Errorf("mapScenarioToCategories(%q) = %q, want %q", tt.scenario, got, tt.want)
			}
		})
	}
}

func TestBuildComment(t *testing.T) {
	tests := []struct {
		name     string
		decision lapi.Decision
		want     string
	}{
		{
			name: "with scenario and duration",
			decision: lapi.Decision{
				Scenario: "crowdsecurity/ssh-bf",
				Duration: "4h",
			},
			want: "CrowdSec ban: crowdsecurity/ssh-bf (duration: 4h)",
		},
		{
			name: "with scenario only",
			decision: lapi.Decision{
				Scenario: "http-probing",
			},
			want: "CrowdSec ban: http-probing",
		},
		{
			name:     "empty decision",
			decision: lapi.Decision{},
			want:     "CrowdSec ban",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildComment(tt.decision)
			if got != tt.want {
				t.Errorf("buildComment() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsBlocklistOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"lists:firehol_level1", true},
		{"lists:blocklist_de", true},
		{"blocklist-import", true},
		{"block_list_custom", true},
		{"CAPI", false},
		{"crowdsec", false},
		{"cscli", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			got := isBlocklistOrigin(tt.origin)
			if got != tt.want {
				t.Errorf("isBlocklistOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestReporter_DefaultConfig(t *testing.T) {
	r := New(Config{
		Enabled: true,
		APIKey:  "test",
	}, testLogger())
	defer r.Stop()

	if r.cfg.APIURL != DefaultAPIURL {
		t.Errorf("expected default API URL %q, got %q", DefaultAPIURL, r.cfg.APIURL)
	}
	if r.cfg.DailyLimit != DefaultDailyLimit {
		t.Errorf("expected default daily limit %d, got %d", DefaultDailyLimit, r.cfg.DailyLimit)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to..."},
	}

	for _, tt := range tests {
		got := truncateString(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestReporter_EmptyTypeAndScopeTreatedAsBanIP(t *testing.T) {
	// Decisions with empty Type or Scope should be treated as ban/ip.
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		resp := reportResponse{}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	reporter := New(Config{
		Enabled:    true,
		APIKey:     "test-api-key",
		APIURL:     server.URL,
		DailyLimit: 100,
	}, testLogger())

	reporter.ReportDecision(lapi.Decision{
		Value:    "1.2.3.4",
		Scenario: "ssh-bf",
		Origin:   "crowdsec",
		// Type and Scope are empty (treated as defaults).
	})

	reporter.Stop()

	if received.Load() != 1 {
		t.Errorf("expected 1 report for empty type/scope, got %d", received.Load())
	}
}
