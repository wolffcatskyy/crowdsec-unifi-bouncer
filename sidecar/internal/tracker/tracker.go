// Package tracker implements stream-aware decision capping.
//
// The CrowdSec LAPI streaming endpoint (/v1/decisions/stream) operates in two modes:
//   - startup=true: Full sync — returns all active decisions at once
//   - startup=false: Incremental — returns only new/deleted decisions since last poll
//
// Without stream tracking, the sidecar correctly caps full sync responses to max_decisions,
// but incremental updates bypass the cap because each small batch (often 1 decision) is
// independently smaller than the limit. Over a 2-hour window between full syncs, enough
// incremental CAPI decisions accumulate to push the bouncer's ipset over its maxelem limit.
//
// StreamTracker solves this by maintaining a cumulative count of CAPI decisions passed
// to the bouncer between full syncs. LOCAL decisions (origin: crowdsec, cscli) are always
// passed through regardless of count. Two eviction modes are supported:
//   - "cap": Simply stop adding new CAPI decisions once at the limit
//   - "evict": Replace the oldest tracked CAPI decisions with newer ones when at the limit
package tracker

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

// EvictionMode controls what happens when CAPI decisions exceed the cap.
type EvictionMode string

const (
	// ModeCap stops adding new CAPI decisions once the limit is reached.
	ModeCap EvictionMode = "cap"
	// ModeEvict replaces the oldest CAPI decisions with newer ones when at the limit.
	ModeEvict EvictionMode = "evict"
)

// localOrigins defines decision origins that are always passed through.
var localOrigins = map[string]bool{
	"crowdsec": true,
	"cscli":    true,
}

// IsLocalOrigin returns true if the given origin represents a local decision
// that should always be passed through regardless of CAPI cap.
func IsLocalOrigin(origin string) bool {
	return localOrigins[origin]
}

// trackedDecision stores minimal info about a CAPI decision for eviction ordering.
type trackedDecision struct {
	value     string // IP or CIDR value
	addedAt   time.Time
	createdAt time.Time
}

// StreamTracker tracks cumulative CAPI decision counts between full syncs
// and enforces the configured cap on incremental stream updates.
// Two sets of decisions are tracked separately:
//   - fullSyncSet: CAPI decisions from the authoritative full sync (always passed through)
//   - trackedSet: INCREMENTAL CAPI decisions added since the last full sync
//
// The cap only applies to incremental additions. This fixes the bug where a full sync
// returning more CAPI decisions than maxDecisions (e.g., UDM Pro with 20k active vs 15k max)
// would make capiCount start over the cap, silently dropping all subsequent incrementals.
// Evictions also only ever replace incremental decisions, never baseline ones.
type StreamTracker struct {
	mu           sync.Mutex
	maxDecisions int
	mode         EvictionMode
	logger       *slog.Logger

	// Cumulative count of INCREMENTAL CAPI decisions added since last full sync.
	// Full sync baseline decisions are NOT counted here — the cap only applies to
	// incremental additions (fixes #58).
	capiCount int

	// Ordered list of tracked INCREMENTAL CAPI decisions (oldest first) for eviction mode.
	// Only populated when mode == ModeEvict. Never includes full-sync baseline decisions
	// so eviction can never remove a baseline decision (fixes #57).
	tracked []trackedDecision

	// Set of all currently tracked CAPI decision values for deduplication (baseline + incremental).
	trackedSet map[string]struct{}

	// Set of CAPI decision values from the authoritative full sync.
	// These are not counted in capiCount and are never subject to eviction.
	fullSyncSet map[string]struct{}

	// Metrics (atomic for lock-free reads from metrics endpoint)
	decisionsPassed atomic.Int64
	decisionsDropped atomic.Int64
	evictions        atomic.Int64
	fullSyncs        atomic.Int64
	lastFullSync     atomic.Int64 // unix timestamp
}

// Metrics contains stream tracker statistics for the metrics endpoint.
type Metrics struct {
	DecisionsPassed  int64
	DecisionsDropped int64
	Evictions        int64
	FullSyncs        int64
	LastFullSync     int64
	CAPICount        int // INCREMENTAL CAPI count (additions since last full sync)
	BaseCount        int // Full-sync baseline CAPI decisions (authoritative set)
	MaxDecisions     int
	EvictionMode     string
}

// New creates a new StreamTracker.
func New(maxDecisions int, mode EvictionMode, logger *slog.Logger) *StreamTracker {
	if mode == "" {
		mode = ModeCap
	}
	return &StreamTracker{
		maxDecisions: maxDecisions,
		mode:         mode,
		logger:       logger,
		trackedSet:   make(map[string]struct{}),
		fullSyncSet:  make(map[string]struct{}),
	}
}

// Reset clears all tracking state. Called on full sync (startup=true).
func (t *StreamTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.capiCount = 0
	t.tracked = nil
	t.trackedSet = make(map[string]struct{})
	t.fullSyncSet = make(map[string]struct{})
	t.fullSyncs.Add(1)
	t.lastFullSync.Store(time.Now().Unix())

	t.logger.Info("stream tracker reset (full sync)")
}

// FilterStreamDecisions processes a batch of incremental stream decisions,
// enforcing the CAPI cap while always passing through local decisions.
// It modifies the stream in place and returns the filtered new decisions.
//
// Deleted decisions are also tracked: when a CAPI decision is deleted,
// the cumulative count is decremented, freeing capacity for new decisions.
func (t *StreamTracker) FilterStreamDecisions(stream *lapi.DecisionStream) []lapi.Decision {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Process deletions first — free up capacity
	for _, d := range stream.Deleted {
		if !IsLocalOrigin(d.Origin) {
			t.removeTracked(d.Value)
		}
	}

	// Filter new decisions
	var kept []lapi.Decision
	for _, d := range stream.New {
		if IsLocalOrigin(d.Origin) {
			// Local decisions always pass through
			kept = append(kept, d)
			t.decisionsPassed.Add(1)
			continue
		}

		// CAPI/community decision — check cap
		if t.capiCount < t.maxDecisions {
			// Under cap — pass through
			kept = append(kept, d)
			t.addTracked(d)
			t.decisionsPassed.Add(1)
		} else if t.mode == ModeEvict {
			// At cap in evict mode — replace oldest
			if t.evictOldest() {
				kept = append(kept, d)
				t.addTracked(d)
				t.decisionsPassed.Add(1)
				t.evictions.Add(1)
			} else {
				// Nothing to evict (shouldn't happen if capiCount > 0)
				t.decisionsDropped.Add(1)
				t.logger.Debug("stream cap: dropped CAPI decision (evict failed)",
					"value", d.Value,
					"capi_count", t.capiCount,
					"max", t.maxDecisions,
				)
			}
		} else {
			// At cap in cap mode — drop
			t.decisionsDropped.Add(1)
			t.logger.Debug("stream cap: dropped CAPI decision",
				"value", d.Value,
				"capi_count", t.capiCount,
				"max", t.maxDecisions,
			)
		}
	}

	return kept
}

// addTracked adds a CAPI decision to the tracking state.
func (t *StreamTracker) addTracked(d lapi.Decision) {
	// Don't double-count if we already track this value
	if _, exists := t.trackedSet[d.Value]; exists {
		return
	}

	t.capiCount++
	t.trackedSet[d.Value] = struct{}{}

	if t.mode == ModeEvict {
		t.tracked = append(t.tracked, trackedDecision{
			value:     d.Value,
			addedAt:   time.Now(),
			createdAt: d.ParsedCreated,
		})
	}
}

// removeTracked removes a CAPI decision from tracking (called on deletion).
// If the decision was part of the full-sync baseline, only the dedup set is updated
// (capiCount is not decremented since baseline decisions are not counted).
// If the decision was an incremental addition, capiCount is decremented.
func (t *StreamTracker) removeTracked(value string) {
	if _, exists := t.trackedSet[value]; !exists {
		return
	}

	delete(t.trackedSet, value)

	// Only decrement capiCount if this was an incremental, not a baseline decision
	if _, isBaseline := t.fullSyncSet[value]; isBaseline {
		delete(t.fullSyncSet, value)
	} else {
		t.capiCount--
		if t.capiCount < 0 {
			t.capiCount = 0
		}
	}

	if t.mode == ModeEvict {
		for i, td := range t.tracked {
			if td.value == value {
				t.tracked = append(t.tracked[:i], t.tracked[i+1:]...)
				break
			}
		}
	}
}

// evictOldest removes the oldest tracked CAPI decision to make room for a new one.
// Returns true if a decision was evicted, false if nothing to evict.
func (t *StreamTracker) evictOldest() bool {
	if len(t.tracked) == 0 {
		return false
	}

	oldest := t.tracked[0]
	t.tracked = t.tracked[1:]
	delete(t.trackedSet, oldest.value)
	t.capiCount--

	t.logger.Debug("stream cap: evicted oldest CAPI decision",
		"value", oldest.value,
		"age", time.Since(oldest.addedAt).Round(time.Second),
	)

	return true
}

// SetCapFromFullSync records the CAPI decisions from a full sync response as the
// authoritative baseline. These baseline decisions are always passed through and are
// NOT counted against the cap — the cap only applies to INCREMENTAL CAPI decisions
// added after the full sync. This ensures that when a full sync returns more CAPI
// decisions than maxDecisions (e.g., UDM Pro with 20k active vs 15k max), subsequent
// incremental decisions are not silently dropped (fixes #58).
func (t *StreamTracker) SetCapFromFullSync(capiDecisions []lapi.Decision) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reset incremental tracking state
	t.capiCount = 0
	t.tracked = nil
	t.trackedSet = make(map[string]struct{})
	t.fullSyncSet = make(map[string]struct{})

	// Populate the baseline set from the full sync response
	// These are NOT counted in capiCount — they're authoritative and always passed through
	for _, d := range capiDecisions {
		if !IsLocalOrigin(d.Origin) {
			t.fullSyncSet[d.Value] = struct{}{}
			t.trackedSet[d.Value] = struct{}{}
		}
	}

	t.logger.Info("stream tracker initialized from full sync",
		"base_capi_count", len(t.fullSyncSet),
		"max_incrementals", t.maxDecisions,
	)
}

// GetMetrics returns the current tracker metrics.
func (t *StreamTracker) GetMetrics() Metrics {
	t.mu.Lock()
	capiCount := t.capiCount
	baseCount := len(t.fullSyncSet)
	t.mu.Unlock()

	return Metrics{
		DecisionsPassed:  t.decisionsPassed.Load(),
		DecisionsDropped: t.decisionsDropped.Load(),
		Evictions:        t.evictions.Load(),
		FullSyncs:        t.fullSyncs.Load(),
		LastFullSync:     t.lastFullSync.Load(),
		CAPICount:        capiCount,
		BaseCount:        baseCount,
		MaxDecisions:     t.maxDecisions,
		EvictionMode:     string(t.mode),
	}
}
