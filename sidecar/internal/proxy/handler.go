// Package proxy implements the HTTP proxy handler.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/scorer"
)

// Handler handles HTTP requests and proxies to the upstream LAPI.
type Handler struct {
	cfg       *config.Config
	client    *lapi.Client
	scorer    *scorer.Scorer
	logger    *slog.Logger
	startTime time.Time

	// Cache
	cacheMu     sync.RWMutex
	cache       []lapi.Decision
	cacheTime   time.Time
	cacheStats  scorer.Stats
	cacheHits   int64
	cacheMisses int64

	// Metrics
	metricsMu        sync.RWMutex
	totalRequests    int64
	failedRequests   int64
	upstreamLatency  time.Duration
	lastUpstreamCall time.Time
}

// New creates a new Handler.
func New(cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:       cfg,
		client:    lapi.NewClient(cfg.UpstreamLAPIURL, cfg.UpstreamLAPIKey, cfg.UpstreamTimeout),
		scorer:    scorer.New(&cfg.Scoring),
		logger:    logger,
		startTime: time.Now(),
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metricsMu.Lock()
	h.totalRequests++
	h.metricsMu.Unlock()

	switch r.URL.Path {
	case "/v1/decisions":
		h.handleDecisions(w, r)
	case "/v1/decisions/stream":
		h.handleDecisionsStream(w, r)
	case h.cfg.Health.Path:
		if h.cfg.Health.Enabled {
			h.handleHealth(w, r)
		} else {
			http.NotFound(w, r)
		}
	case h.cfg.Metrics.Path:
		if h.cfg.Metrics.Enabled {
			h.handleMetrics(w, r)
		} else {
			http.NotFound(w, r)
		}
	default:
		// Proxy unknown paths directly to upstream
		h.proxyPassthrough(w, r)
	}
}

// handleDecisions handles GET /v1/decisions
func (h *Handler) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Check cache
	decisions, stats, fromCache := h.getCachedDecisions()
	if !fromCache {
		var err error
		decisions, stats, err = h.fetchAndScoreDecisions(ctx, r.URL.Query())
		if err != nil {
			h.logger.Error("failed to fetch decisions", "error", err)
			h.metricsMu.Lock()
			h.failedRequests++
			h.metricsMu.Unlock()
			http.Error(w, "failed to fetch decisions from upstream", http.StatusBadGateway)
			return
		}

		h.setCachedDecisions(decisions, stats)

		h.logger.Info("fetched decisions from upstream",
			"total", stats.TotalDecisions,
			"returned", stats.ReturnedDecisions,
			"dropped", stats.DroppedDecisions,
			"max_score", stats.MaxScore,
			"min_score", stats.MinScore,
		)
	} else {
		h.logger.Debug("serving cached decisions",
			"count", len(decisions),
			"age", time.Since(h.cacheTime).Round(time.Second),
		)
	}

	w.Header().Set("Content-Type", "application/json")

	// Return null for empty decisions (matching LAPI behavior)
	if len(decisions) == 0 {
		w.Write([]byte("null"))
		return
	}

	if err := json.NewEncoder(w).Encode(decisions); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// handleDecisionsStream handles GET /v1/decisions/stream
func (h *Handler) handleDecisionsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	startup := r.URL.Query().Get("startup") == "true"

	start := time.Now()
	stream, err := h.client.GetDecisionsStream(ctx, startup)
	if err != nil {
		h.logger.Error("failed to fetch decision stream", "error", err)
		h.metricsMu.Lock()
		h.failedRequests++
		h.metricsMu.Unlock()
		http.Error(w, "failed to fetch decisions from upstream", http.StatusBadGateway)
		return
	}

	h.metricsMu.Lock()
	h.upstreamLatency = time.Since(start)
	h.lastUpstreamCall = time.Now()
	h.metricsMu.Unlock()

	// Score and truncate new decisions
	if len(stream.New) > 0 {
		stream.New, _ = h.scorer.ScoreAndTruncateWithStats(stream.New, h.cfg.MaxDecisions)
	}

	h.logger.Info("processed decision stream",
		"new", len(stream.New),
		"deleted", len(stream.Deleted),
		"startup", startup,
	)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stream); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// handleHealth handles the health check endpoint.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check upstream LAPI health
	upstreamHealthy := true
	if err := h.client.Health(ctx); err != nil {
		h.logger.Warn("upstream LAPI health check failed", "error", err)
		upstreamHealthy = false
	}

	health := map[string]interface{}{
		"status":           "healthy",
		"uptime":           time.Since(h.startTime).String(),
		"upstream_healthy": upstreamHealthy,
	}

	if !upstreamHealthy {
		health["status"] = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleMetrics handles the metrics endpoint (Prometheus format).
func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	h.metricsMu.RLock()
	totalReqs := h.totalRequests
	failedReqs := h.failedRequests
	upstreamLat := h.upstreamLatency.Seconds()
	h.metricsMu.RUnlock()

	h.cacheMu.RLock()
	cacheHits := h.cacheHits
	cacheMisses := h.cacheMisses
	cachedDecisions := len(h.cache)
	cacheStats := h.cacheStats
	h.cacheMu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_requests_total Total number of requests\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_requests_total counter\n")
	fmt.Fprintf(w, "crowdsec_sidecar_requests_total %d\n", totalReqs)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_requests_failed_total Total number of failed requests\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_requests_failed_total counter\n")
	fmt.Fprintf(w, "crowdsec_sidecar_requests_failed_total %d\n", failedReqs)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_cache_hits_total Total number of cache hits\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_cache_hits_total counter\n")
	fmt.Fprintf(w, "crowdsec_sidecar_cache_hits_total %d\n", cacheHits)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_cache_misses_total Total number of cache misses\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_cache_misses_total counter\n")
	fmt.Fprintf(w, "crowdsec_sidecar_cache_misses_total %d\n", cacheMisses)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_cached_decisions Current number of cached decisions\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_cached_decisions gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_cached_decisions %d\n", cachedDecisions)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_upstream_latency_seconds Last upstream request latency\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_upstream_latency_seconds gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_upstream_latency_seconds %.3f\n", upstreamLat)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_max_decisions Configured max decisions limit\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_max_decisions gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_max_decisions %d\n", h.cfg.MaxDecisions)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_decisions_total Total decisions from upstream\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_decisions_total gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_decisions_total %d\n", cacheStats.TotalDecisions)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_decisions_dropped Decisions dropped due to limit\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_decisions_dropped gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_decisions_dropped %d\n", cacheStats.DroppedDecisions)

	fmt.Fprintf(w, "# HELP crowdsec_sidecar_uptime_seconds Time since sidecar started\n")
	fmt.Fprintf(w, "# TYPE crowdsec_sidecar_uptime_seconds gauge\n")
	fmt.Fprintf(w, "crowdsec_sidecar_uptime_seconds %.0f\n", time.Since(h.startTime).Seconds())
}

// proxyPassthrough proxies requests directly to upstream without modification.
func (h *Handler) proxyPassthrough(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("proxying request to upstream", "path", r.URL.Path)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, h.cfg.UpstreamLAPIURL+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("X-Api-Key", h.cfg.UpstreamLAPIKey)
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// getCachedDecisions returns cached decisions if still valid.
func (h *Handler) getCachedDecisions() ([]lapi.Decision, scorer.Stats, bool) {
	h.cacheMu.RLock()
	cache := h.cache
	cacheTime := h.cacheTime
	cacheStats := h.cacheStats
	h.cacheMu.RUnlock()

	if cache != nil && time.Since(cacheTime) < h.cfg.CacheTTL {
		h.cacheMu.Lock()
		h.cacheHits++
		h.cacheMu.Unlock()
		return cache, cacheStats, true
	}

	return nil, scorer.Stats{}, false
}

// setCachedDecisions updates the cache.
func (h *Handler) setCachedDecisions(decisions []lapi.Decision, stats scorer.Stats) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	h.cache = decisions
	h.cacheTime = time.Now()
	h.cacheStats = stats
	h.cacheMisses++
}

// fetchAndScoreDecisions fetches from upstream, scores, and truncates.
func (h *Handler) fetchAndScoreDecisions(ctx context.Context, query map[string][]string) ([]lapi.Decision, scorer.Stats, error) {
	start := time.Now()
	decisions, err := h.client.GetDecisions(ctx, query)
	if err != nil {
		return nil, scorer.Stats{}, err
	}

	h.metricsMu.Lock()
	h.upstreamLatency = time.Since(start)
	h.lastUpstreamCall = time.Now()
	h.metricsMu.Unlock()

	result, stats := h.scorer.ScoreAndTruncateWithStats(decisions, h.cfg.MaxDecisions)
	return result, stats, nil
}
