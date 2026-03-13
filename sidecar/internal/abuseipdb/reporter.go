// Package abuseipdb provides an optional reporter that sends banned IPs
// to the AbuseIPDB report API. Reports are fire-and-forget: failures are
// logged but never affect the main bouncer operation.
package abuseipdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

const (
	// DefaultAPIURL is the AbuseIPDB v2 report endpoint.
	DefaultAPIURL = "https://api.abuseipdb.com/api/v2/report"

	// DefaultDailyLimit is the free-tier rate limit.
	DefaultDailyLimit = 100

	// DefaultTimeout is the HTTP timeout for report requests.
	DefaultTimeout = 10 * time.Second
)

// AbuseIPDB category IDs.
const (
	CategoryPortScan   = 14
	CategoryBruteForce = 18
	CategoryWebAppAtk  = 21
	CategorySSH        = 22
	CategoryTelnet     = 23
)

// Config holds the AbuseIPDB reporter configuration.
type Config struct {
	Enabled    bool   `yaml:"enabled"`
	APIKey     string `yaml:"api_key"`
	APIURL     string `yaml:"api_url"` // override for testing
	DailyLimit int    `yaml:"daily_limit"`
}

// Reporter sends IP reports to AbuseIPDB asynchronously.
// It is safe for concurrent use.
type Reporter struct {
	cfg        Config
	logger     *slog.Logger
	httpClient *http.Client

	// Rate limiting: simple daily counter that resets every 24h.
	mu          sync.Mutex
	reportCount int
	windowStart time.Time

	// Prometheus metrics (atomic for lock-free reads).
	reportsTotal   atomic.Int64
	reportsSuccess atomic.Int64
	reportsFailed  atomic.Int64
	reportsSkipped atomic.Int64 // skipped due to rate limit, blocklist origin, etc.

	// Report queue for async processing.
	queue chan reportRequest
	done  chan struct{}
	wg    sync.WaitGroup
}

// reportRequest holds the data needed to send a single report.
type reportRequest struct {
	IP         string
	Categories string
	Comment    string
}

// Metrics contains reporter statistics for the metrics endpoint.
type Metrics struct {
	ReportsTotal   int64
	ReportsSuccess int64
	ReportsFailed  int64
	ReportsSkipped int64
}

// reportResponse is the AbuseIPDB API response (minimal fields).
type reportResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	} `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"errors"`
}

// New creates a new Reporter. If the config is disabled or has no API key,
// the reporter will be a no-op (all methods are safe to call).
func New(cfg Config, logger *slog.Logger) *Reporter {
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	if cfg.DailyLimit <= 0 {
		cfg.DailyLimit = DefaultDailyLimit
	}

	r := &Reporter{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		windowStart: time.Now(),
		queue:       make(chan reportRequest, 1000),
		done:        make(chan struct{}),
	}

	// Start the background worker if enabled.
	if r.IsEnabled() {
		r.wg.Add(1)
		go r.worker()
		logger.Info("abuseipdb reporter started",
			"daily_limit", cfg.DailyLimit,
		)
	}

	return r
}

// IsEnabled returns true if the reporter is configured and active.
func (r *Reporter) IsEnabled() bool {
	return r.cfg.Enabled && r.cfg.APIKey != ""
}

// ReportDecision queues an AbuseIPDB report for a new ban decision.
// It is non-blocking; reports are processed asynchronously.
//
// Decisions are filtered:
//   - Only "ban" decisions are reported
//   - Only IP-scope decisions are reported (not ranges)
//   - Decisions originating from blocklist-import are skipped (avoid circular reporting)
//   - Decisions from community sources (CAPI) are skipped (already in threat intel)
//   - Rate limits are enforced
func (r *Reporter) ReportDecision(d lapi.Decision) {
	if !r.IsEnabled() {
		return
	}

	// Only report bans (not captchas or throttles).
	if d.Type != "" && d.Type != "ban" {
		r.reportsSkipped.Add(1)
		return
	}

	// Only report individual IPs (not CIDR ranges).
	if d.Scope != "" && d.Scope != "ip" && d.Scope != "Ip" {
		r.reportsSkipped.Add(1)
		return
	}
	if strings.Contains(d.Value, "/") {
		r.reportsSkipped.Add(1)
		return
	}

	// Skip blocklist-import decisions (avoid circular reporting).
	if isBlocklistOrigin(d.Origin) {
		r.reportsSkipped.Add(1)
		r.logger.Debug("abuseipdb: skipping blocklist-origin decision",
			"ip", d.Value,
			"origin", d.Origin,
		)
		return
	}

	// Skip CAPI decisions (already in community threat intel).
	if d.Origin == "CAPI" {
		r.reportsSkipped.Add(1)
		return
	}

	categories := mapScenarioToCategories(d.Scenario)
	comment := buildComment(d)

	req := reportRequest{
		IP:         d.Value,
		Categories: categories,
		Comment:    comment,
	}

	// Non-blocking enqueue.
	select {
	case r.queue <- req:
		r.reportsTotal.Add(1)
	default:
		r.reportsSkipped.Add(1)
		r.logger.Warn("abuseipdb: report queue full, dropping report",
			"ip", d.Value,
		)
	}
}

// Stop shuts down the reporter and waits for pending reports to drain.
func (r *Reporter) Stop() {
	if !r.IsEnabled() {
		return
	}
	close(r.done)
	r.wg.Wait()
	r.logger.Info("abuseipdb reporter stopped",
		"reports_success", r.reportsSuccess.Load(),
		"reports_failed", r.reportsFailed.Load(),
		"reports_skipped", r.reportsSkipped.Load(),
	)
}

// GetMetrics returns the current reporter metrics.
func (r *Reporter) GetMetrics() Metrics {
	return Metrics{
		ReportsTotal:   r.reportsTotal.Load(),
		ReportsSuccess: r.reportsSuccess.Load(),
		ReportsFailed:  r.reportsFailed.Load(),
		ReportsSkipped: r.reportsSkipped.Load(),
	}
}

// worker processes the report queue.
func (r *Reporter) worker() {
	defer r.wg.Done()

	for {
		select {
		case <-r.done:
			// Drain remaining items.
			for {
				select {
				case req := <-r.queue:
					r.sendReport(context.Background(), req)
				default:
					return
				}
			}
		case req := <-r.queue:
			r.sendReport(context.Background(), req)
		}
	}
}

// sendReport sends a single report to AbuseIPDB.
func (r *Reporter) sendReport(ctx context.Context, req reportRequest) {
	// Check rate limit.
	if !r.acquireRateSlot() {
		r.reportsSkipped.Add(1)
		r.logger.Debug("abuseipdb: rate limit reached, skipping report",
			"ip", req.IP,
		)
		return
	}

	form := url.Values{}
	form.Set("ip", req.IP)
	form.Set("categories", req.Categories)
	form.Set("comment", req.Comment)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.APIURL, strings.NewReader(form.Encode()))
	if err != nil {
		r.reportsFailed.Add(1)
		r.logger.Error("abuseipdb: failed to create request",
			"ip", req.IP,
			"error", err,
		)
		return
	}

	httpReq.Header.Set("Key", r.cfg.APIKey)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		r.reportsFailed.Add(1)
		r.logger.Error("abuseipdb: request failed",
			"ip", req.IP,
			"error", err,
		)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		r.reportsFailed.Add(1)
		r.logger.Warn("abuseipdb: rate limited by API (429)",
			"ip", req.IP,
		)
		return
	}

	if resp.StatusCode != http.StatusOK {
		r.reportsFailed.Add(1)
		r.logger.Error("abuseipdb: unexpected status",
			"ip", req.IP,
			"status", resp.StatusCode,
			"body", truncateString(string(body), 200),
		)
		return
	}

	// Parse response for logging.
	var apiResp reportResponse
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if len(apiResp.Errors) > 0 {
			r.reportsFailed.Add(1)
			r.logger.Warn("abuseipdb: API returned errors",
				"ip", req.IP,
				"error", apiResp.Errors[0].Detail,
			)
			return
		}
	}

	r.reportsSuccess.Add(1)
	r.logger.Debug("abuseipdb: reported",
		"ip", req.IP,
		"categories", req.Categories,
	)
}

// acquireRateSlot checks and updates the daily rate limit.
// Returns true if a report slot is available.
func (r *Reporter) acquireRateSlot() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset counter if 24 hours have passed.
	if time.Since(r.windowStart) >= 24*time.Hour {
		r.reportCount = 0
		r.windowStart = time.Now()
	}

	if r.reportCount >= r.cfg.DailyLimit {
		return false
	}

	r.reportCount++
	return true
}

// mapScenarioToCategories maps a CrowdSec scenario name to AbuseIPDB category IDs.
func mapScenarioToCategories(scenario string) string {
	lower := strings.ToLower(scenario)

	// Strip common prefixes.
	for _, prefix := range []string{"crowdsecurity/", "crowdsec/"} {
		lower = strings.TrimPrefix(lower, prefix)
	}

	switch {
	case strings.Contains(lower, "ssh"):
		return fmt.Sprintf("%d,%d", CategorySSH, CategoryBruteForce)
	case strings.Contains(lower, "telnet"):
		return fmt.Sprintf("%d,%d", CategoryTelnet, CategoryBruteForce)
	case strings.Contains(lower, "http"):
		return fmt.Sprintf("%d", CategoryWebAppAtk)
	case strings.Contains(lower, "smb"):
		return fmt.Sprintf("%d", CategoryBruteForce)
	case strings.Contains(lower, "ftp"):
		return fmt.Sprintf("%d", CategoryBruteForce)
	default:
		return fmt.Sprintf("%d", CategoryPortScan)
	}
}

// buildComment creates a human-readable comment for the AbuseIPDB report.
func buildComment(d lapi.Decision) string {
	var b bytes.Buffer
	b.WriteString("CrowdSec ban")

	if d.Scenario != "" {
		b.WriteString(": ")
		b.WriteString(d.Scenario)
	}

	if d.Duration != "" {
		b.WriteString(" (duration: ")
		b.WriteString(d.Duration)
		b.WriteString(")")
	}

	return b.String()
}

// isBlocklistOrigin returns true if the origin indicates a blocklist import
// (to avoid circular reporting of IPs we imported from other threat feeds).
func isBlocklistOrigin(origin string) bool {
	lower := strings.ToLower(origin)
	return strings.HasPrefix(lower, "lists") ||
		strings.Contains(lower, "blocklist") ||
		strings.Contains(lower, "block_list")
}

// truncateString truncates a string to maxLen, appending "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
