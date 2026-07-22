package tracker

import (
	"log/slog"
	"os"
	"testing"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestStreamTracker_LocalDecisionsAlwaysPass(t *testing.T) {
	tr := New(2, ModeCap, testLogger())

	// Fill to cap with CAPI decisions
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}

	// Now at cap — CAPI should be dropped, but local should pass
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
			{ID: 4, Origin: "crowdsec", Value: "4.4.4.4", Scope: "ip"},
			{ID: 5, Origin: "cscli", Value: "5.5.5.5", Scope: "ip"},
		},
	}
	kept = tr.FilterStreamDecisions(stream)

	if len(kept) != 2 {
		t.Fatalf("expected 2 kept (local only), got %d", len(kept))
	}

	// Verify only local decisions were kept
	for _, d := range kept {
		if !IsLocalOrigin(d.Origin) {
			t.Errorf("non-local decision passed: origin=%s value=%s", d.Origin, d.Value)
		}
	}

	metrics := tr.GetMetrics()
	if metrics.DecisionsDropped != 1 {
		t.Errorf("expected 1 dropped, got %d", metrics.DecisionsDropped)
	}
	if metrics.DecisionsPassed != 4 {
		t.Errorf("expected 4 passed, got %d", metrics.DecisionsPassed)
	}
}

func TestStreamTracker_CapMode(t *testing.T) {
	tr := New(3, ModeCap, testLogger())

	// Send 5 CAPI decisions — only 3 should pass
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
			{ID: 4, Origin: "CAPI", Value: "4.4.4.4", Scope: "ip"},
			{ID: 5, Origin: "CAPI", Value: "5.5.5.5", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)

	if len(kept) != 3 {
		t.Fatalf("expected 3 kept, got %d", len(kept))
	}

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3, got %d", metrics.CAPICount)
	}
	if metrics.DecisionsDropped != 2 {
		t.Errorf("expected 2 dropped, got %d", metrics.DecisionsDropped)
	}
}

func TestStreamTracker_EvictMode(t *testing.T) {
	tr := New(3, ModeEvict, testLogger())

	// Fill to cap
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 3 {
		t.Fatalf("expected 3 kept, got %d", len(kept))
	}

	// Send 2 more — should evict oldest
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 4, Origin: "CAPI", Value: "4.4.4.4", Scope: "ip"},
			{ID: 5, Origin: "CAPI", Value: "5.5.5.5", Scope: "ip"},
		},
	}
	kept = tr.FilterStreamDecisions(stream)

	if len(kept) != 2 {
		t.Fatalf("expected 2 kept (evicted), got %d", len(kept))
	}

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3 after eviction, got %d", metrics.CAPICount)
	}
	if metrics.Evictions != 2 {
		t.Errorf("expected 2 evictions, got %d", metrics.Evictions)
	}
	if metrics.DecisionsDropped != 0 {
		t.Errorf("expected 0 dropped in evict mode, got %d", metrics.DecisionsDropped)
	}
}

func TestStreamTracker_DeletionFreesCapacity(t *testing.T) {
	tr := New(2, ModeCap, testLogger())

	// Fill to cap
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	tr.FilterStreamDecisions(stream)

	// Delete one decision, then add a new one
	stream = &lapi.DecisionStream{
		Deleted: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1"},
		},
		New: []lapi.Decision{
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)

	if len(kept) != 1 {
		t.Fatalf("expected 1 kept after deletion freed capacity, got %d", len(kept))
	}
	if kept[0].Value != "3.3.3.3" {
		t.Errorf("expected 3.3.3.3, got %s", kept[0].Value)
	}

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 2 {
		t.Errorf("expected CAPICount=2, got %d", metrics.CAPICount)
	}
}

func TestStreamTracker_ResetOnFullSync(t *testing.T) {
	tr := New(2, ModeCap, testLogger())

	// Fill to cap
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	tr.FilterStreamDecisions(stream)

	// Reset (simulating full sync)
	tr.Reset()

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0 after reset, got %d", metrics.CAPICount)
	}
	if metrics.FullSyncs != 1 {
		t.Errorf("expected 1 full sync, got %d", metrics.FullSyncs)
	}

	// Should be able to add decisions again
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept after reset, got %d", len(kept))
	}
}

func TestStreamTracker_SetCapFromFullSync(t *testing.T) {
	tr := New(5, ModeCap, testLogger())

	// Simulate a full sync that returned 3 CAPI decisions and 1 local
	decisions := []lapi.Decision{
		{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
		{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		{ID: 4, Origin: "crowdsec", Value: "4.4.4.4", Scope: "ip"},
	}
	tr.SetCapFromFullSync(decisions)

	metrics := tr.GetMetrics()
	// capiCount tracks INCREMENTAL additions only (starts at 0 after full sync)
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0 (incrementals), got %d", metrics.CAPICount)
	}
	if metrics.BaseCount != 3 {
		t.Errorf("expected BaseCount=3 (full sync CAPI), got %d", metrics.BaseCount)
	}

	// Should have headroom for up to maxDecisions (5) incremental CAPI decisions
	// All 3 incrementals should pass since capiCount=0 and max=5
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 5, Origin: "CAPI", Value: "5.5.5.5", Scope: "ip"},
			{ID: 6, Origin: "CAPI", Value: "6.6.6.6", Scope: "ip"},
			{ID: 7, Origin: "CAPI", Value: "7.7.7.7", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 3 {
		t.Fatalf("expected 3 kept (cap only applies to incrementals), got %d", len(kept))
	}

	metrics = tr.GetMetrics()
	if metrics.DecisionsDropped != 0 {
		t.Errorf("expected 0 dropped, got %d", metrics.DecisionsDropped)
	}
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3 (3 incrementals added), got %d", metrics.CAPICount)
	}
}

func TestStreamTracker_DuplicateDecisionsNotDoubleCounted(t *testing.T) {
	tr := New(3, ModeCap, testLogger())

	// Send same decision twice
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"}, // duplicate
			{ID: 3, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)

	if len(kept) != 3 {
		t.Fatalf("expected 3 kept (duplicate not double-counted), got %d", len(kept))
	}

	metrics := tr.GetMetrics()
	// Only 2 unique CAPI values tracked
	if metrics.CAPICount != 2 {
		t.Errorf("expected CAPICount=2 (deduped), got %d", metrics.CAPICount)
	}
}

func TestStreamTracker_IncrementalAccumulation(t *testing.T) {
	// Simulates the real-world scenario:
	// Full sync sets 5 CAPI at cap, then incremental adds trickle in one at a time
	tr := New(5, ModeCap, testLogger())

	// Simulate full sync result being used to set cap
	fullSyncDecisions := make([]lapi.Decision, 5)
	for i := range fullSyncDecisions {
		fullSyncDecisions[i] = lapi.Decision{
			ID: i + 1, Origin: "CAPI", Value: makeIP(i + 1), Scope: "ip",
		}
	}
	tr.SetCapFromFullSync(fullSyncDecisions)

	// capiCount starts at 0 after full sync — cap applies only to incrementals
	// With max=5, the first 5 incremental decisions pass, then the rest are dropped
	for i := 0; i < 5; i++ {
		stream := &lapi.DecisionStream{
			New: []lapi.Decision{
				{ID: 100 + i, Origin: "CAPI", Value: makeIP(100 + i), Scope: "ip"},
			},
		}
		kept := tr.FilterStreamDecisions(stream)
		if len(kept) != 1 {
			t.Errorf("incremental %d: expected 1 kept (under cap), got %d", i, len(kept))
		}
	}

	// Now at cap — subsequent incrementals should be dropped
	for i := 5; i < 10; i++ {
		stream := &lapi.DecisionStream{
			New: []lapi.Decision{
				{ID: 100 + i, Origin: "CAPI", Value: makeIP(100 + i), Scope: "ip"},
			},
		}
		kept := tr.FilterStreamDecisions(stream)
		if len(kept) != 0 {
			t.Errorf("incremental %d: expected 0 kept (at cap), got %d", i, len(kept))
		}
	}

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 5 {
		t.Errorf("expected CAPICount=5 (incrementals), got %d", metrics.CAPICount)
	}
	if metrics.BaseCount != 5 {
		t.Errorf("expected BaseCount=5 (baseline), got %d", metrics.BaseCount)
	}
	if metrics.DecisionsDropped != 5 {
		t.Errorf("expected 5 dropped incrementals, got %d", metrics.DecisionsDropped)
	}
}

func TestStreamTracker_FullSyncExceedsMaxDecisions(t *testing.T) {
	// Bug #58 regression test: When full sync returns MORE CAPI decisions than
	// maxDecisions (e.g., UDM Pro with 20k active vs 15k max), the tracker must
	// NOT silently drop subsequent incremental decisions.
	// capiCount starts at 0 after full sync — only incrementals are capped.
	tr := New(3, ModeCap, testLogger())

	// Full sync has 6 CAPI decisions (exceeding maxDecisions=3)
	fullSyncDecisions := make([]lapi.Decision, 6)
	for i := range fullSyncDecisions {
		fullSyncDecisions[i] = lapi.Decision{
			ID: i + 1, Origin: "CAPI", Value: makeIP(i + 1), Scope: "ip",
		}
	}
	tr.SetCapFromFullSync(fullSyncDecisions)

	// Verify baseline is tracked separately from incrementals
	metrics := tr.GetMetrics()
	if metrics.BaseCount != 6 {
		t.Errorf("expected BaseCount=6 (full sync baseline), got %d", metrics.BaseCount)
	}
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0 (no incrementals yet), got %d", metrics.CAPICount)
	}
	if metrics.DecisionsDropped != 0 {
		t.Errorf("expected 0 dropped, got %d", metrics.DecisionsDropped)
	}

	// Incremental decisions should still be addable up to maxDecisions=3
	for i := 0; i < 3; i++ {
		stream := &lapi.DecisionStream{
			New: []lapi.Decision{
				{ID: 100 + i, Origin: "CAPI", Value: makeIP(100 + i), Scope: "ip"},
			},
		}
		kept := tr.FilterStreamDecisions(stream)
		if len(kept) != 1 {
			t.Errorf("incremental %d: expected 1 kept, got %d", i, len(kept))
		}
	}

	// 4th incremental should be dropped (at cap)
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 103, Origin: "CAPI", Value: makeIP(103), Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 0 {
		t.Errorf("expected 0 kept (at incremental cap), got %d", len(kept))
	}

	metrics = tr.GetMetrics()
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3 (incrementals), got %d", metrics.CAPICount)
	}
	if metrics.BaseCount != 6 {
		t.Errorf("expected BaseCount=6 (baseline unchanged), got %d", metrics.BaseCount)
	}
	if metrics.DecisionsDropped != 1 {
		t.Errorf("expected 1 dropped, got %d", metrics.DecisionsDropped)
	}

	// Local decisions should still always pass regardless of cap
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 200, Origin: "crowdsec", Value: "10.0.0.1", Scope: "ip"},
		},
	}
	kept = tr.FilterStreamDecisions(stream)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept (local passes even at cap), got %d", len(kept))
	}
}

func TestStreamTracker_EvictModeBaselineProtected(t *testing.T) {
	// Bug #57 regression test: After SetCapFromFullSync, eviction should only
	// ever replace INCREMENTAL decisions, never baseline decisions from the
	// authoritative full sync.
	tr := New(3, ModeEvict, testLogger())

	// Full sync with 3 baseline CAPI decisions
	fullSyncDecisions := []lapi.Decision{
		{ID: 1, Origin: "CAPI", Value: "10.0.0.1", Scope: "ip"},
		{ID: 2, Origin: "CAPI", Value: "10.0.0.2", Scope: "ip"},
		{ID: 3, Origin: "CAPI", Value: "10.0.0.3", Scope: "ip"},
	}
	tr.SetCapFromFullSync(fullSyncDecisions)

	metrics := tr.GetMetrics()
	if metrics.BaseCount != 3 {
		t.Errorf("expected BaseCount=3, got %d", metrics.BaseCount)
	}
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0 (no incrementals), got %d", metrics.CAPICount)
	}

	// Add 3 incremental CAPI decisions (fills incremental capacity)
	for i := 0; i < 3; i++ {
		stream := &lapi.DecisionStream{
			New: []lapi.Decision{
				{ID: 10 + i, Origin: "CAPI", Value: makeIP(10 + i), Scope: "ip"},
			},
		}
		kept := tr.FilterStreamDecisions(stream)
		if len(kept) != 1 {
			t.Errorf("incremental %d: expected 1 kept, got %d", i, len(kept))
		}
	}

	metrics = tr.GetMetrics()
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3, got %d", metrics.CAPICount)
	}

	// Now at cap — evict should replace an INCREMENTAL, not a baseline decision
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 20, Origin: "CAPI", Value: "10.0.0.100", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept (evicted), got %d", len(kept))
	}

	metrics = tr.GetMetrics()
	if metrics.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", metrics.Evictions)
	}
	// CAPICount should remain at 3 (evict replaces one)
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3 after eviction, got %d", metrics.CAPICount)
	}
	// BaseCount should still be 3 (baseline decisions are NEVER evicted)
	if metrics.BaseCount != 3 {
		t.Errorf("expected BaseCount=3 (baseline protected from eviction), got %d", metrics.BaseCount)
	}

	// Verify the baseline decisions are still tracked in the full sync set
	tr.mu.Lock()
	_, b1Exists := tr.fullSyncSet["10.0.0.1"]
	_, b2Exists := tr.fullSyncSet["10.0.0.2"]
	_, b3Exists := tr.fullSyncSet["10.0.0.3"]
	tr.mu.Unlock()

	if !b1Exists || !b2Exists || !b3Exists {
		t.Errorf("baseline decisions were removed from fullSyncSet after eviction")
	}

	// And the new decision is in trackedSet
	tr.mu.Lock()
	_, newExists := tr.trackedSet["10.0.0.100"]
	tr.mu.Unlock()
	if !newExists {
		t.Errorf("evicted decision not in trackedSet")
	}
}

func TestStreamTracker_EvictModePreservesCount(t *testing.T) {
	// In evict mode, total CAPI count should never exceed maxDecisions
	tr := New(3, ModeEvict, testLogger())

	// Fill with 3
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		},
	}
	tr.FilterStreamDecisions(stream)

	// Add 5 more one at a time (should evict each time)
	for i := 4; i <= 8; i++ {
		stream := &lapi.DecisionStream{
			New: []lapi.Decision{
				{ID: i, Origin: "CAPI", Value: makeIP(i), Scope: "ip"},
			},
		}
		tr.FilterStreamDecisions(stream)

		metrics := tr.GetMetrics()
		if metrics.CAPICount != 3 {
			t.Errorf("after adding decision %d: CAPICount=%d, want 3", i, metrics.CAPICount)
		}
	}

	metrics := tr.GetMetrics()
	if metrics.Evictions != 5 {
		t.Errorf("expected 5 evictions, got %d", metrics.Evictions)
	}
}

func TestStreamTracker_MixedLocalAndCAPI(t *testing.T) {
	tr := New(2, ModeCap, testLogger())

	// Fill CAPI to cap
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	tr.FilterStreamDecisions(stream)

	// Mixed batch: local decisions should pass, CAPI should be dropped
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 3, Origin: "crowdsec", Value: "3.3.3.3", Scope: "ip"},
			{ID: 4, Origin: "CAPI", Value: "4.4.4.4", Scope: "ip"},
			{ID: 5, Origin: "cscli", Value: "5.5.5.5", Scope: "ip"},
			{ID: 6, Origin: "CAPI", Value: "6.6.6.6", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)

	if len(kept) != 2 {
		t.Fatalf("expected 2 kept (only locals), got %d", len(kept))
	}

	origins := map[string]int{}
	for _, d := range kept {
		origins[d.Origin]++
	}
	if origins["crowdsec"] != 1 || origins["cscli"] != 1 {
		t.Errorf("expected 1 crowdsec + 1 cscli, got %v", origins)
	}
}

func TestIsLocalOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"crowdsec", true},
		{"cscli", true},
		{"CAPI", false},
		{"lists:firehol_level1", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsLocalOrigin(tt.origin); got != tt.want {
			t.Errorf("IsLocalOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

func TestStreamTracker_DefaultEvictionMode(t *testing.T) {
	tr := New(10, "", testLogger())
	metrics := tr.GetMetrics()
	if metrics.EvictionMode != string(ModeCap) {
		t.Errorf("expected default mode 'cap', got %q", metrics.EvictionMode)
	}
}

func TestStreamTracker_IncrementalDeletionFreesCapacity(t *testing.T) {
	// Verify that deleting an incremental CAPI decision frees a slot for a new one.
	// This is the same mechanism as TestStreamTracker_DeletionFreesCapacity but
	// explicitly testing the incremental path.
	tr := New(2, ModeCap, testLogger())

	// Add 2 incremental CAPI decisions
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1", Scope: "ip"},
			{ID: 2, Origin: "CAPI", Value: "2.2.2.2", Scope: "ip"},
		},
	}
	tr.FilterStreamDecisions(stream)

	// Delete incremental decision, which decrements capiCount
	stream = &lapi.DecisionStream{
		Deleted: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "1.1.1.1"},
		},
		New: []lapi.Decision{
			{ID: 3, Origin: "CAPI", Value: "3.3.3.3", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept after deletion freed capacity, got %d", len(kept))
	}

	metrics := tr.GetMetrics()
	if metrics.CAPICount != 2 {
		t.Errorf("expected CAPICount=2 (1 remaining + 1 new), got %d", metrics.CAPICount)
	}
	if metrics.BaseCount != 0 {
		t.Errorf("expected BaseCount=0 (no full sync), got %d", metrics.BaseCount)
	}
}

func TestStreamTracker_BaselineDeletionDoesNotAffectIncrementalCount(t *testing.T) {
	// Verify that deleting a baseline (full sync) decision does NOT decrement
	// capiCount since baseline decisions are not counted as incrementals.
	tr := New(5, ModeCap, testLogger())

	// Full sync with 3 baseline CAPI decisions
	fullSyncDecisions := []lapi.Decision{
		{ID: 1, Origin: "CAPI", Value: "10.0.0.1", Scope: "ip"},
		{ID: 2, Origin: "CAPI", Value: "10.0.0.2", Scope: "ip"},
		{ID: 3, Origin: "CAPI", Value: "10.0.0.3", Scope: "ip"},
	}
	tr.SetCapFromFullSync(fullSyncDecisions)

	metrics := tr.GetMetrics()
	if metrics.BaseCount != 3 {
		t.Errorf("expected BaseCount=3, got %d", metrics.BaseCount)
	}
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0, got %d", metrics.CAPICount)
	}

	// Delete one baseline decision
	stream := &lapi.DecisionStream{
		Deleted: []lapi.Decision{
			{ID: 1, Origin: "CAPI", Value: "10.0.0.1"},
		},
	}
	tr.FilterStreamDecisions(stream)

	metrics = tr.GetMetrics()
	// BaseCount should decrease (baseline decision removed)
	if metrics.BaseCount != 2 {
		t.Errorf("expected BaseCount=2 after baseline deletion, got %d", metrics.BaseCount)
	}
	// CAPICount should remain 0 (deleting a baseline doesn't affect incremental count)
	if metrics.CAPICount != 0 {
		t.Errorf("expected CAPICount=0 (baseline deletion doesn't affect incrementals), got %d", metrics.CAPICount)
	}

	// Drop from dedup set — same value can be added again as incremental
	stream = &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 100, Origin: "CAPI", Value: "10.0.0.1", Scope: "ip"},
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept (value can be re-added), got %d", len(kept))
	}

	metrics = tr.GetMetrics()
	if metrics.CAPICount != 1 {
		t.Errorf("expected CAPICount=1 (re-added as incremental), got %d", metrics.CAPICount)
	}
}

// makeIP generates an IP address string from an integer for test data.
func makeIP(n int) string {
	return "10." + itoa(n/65536%256) + "." + itoa(n/256%256) + "." + itoa(n%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
