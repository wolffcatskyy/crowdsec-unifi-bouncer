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
	if metrics.CAPICount != 3 {
		t.Errorf("expected CAPICount=3, got %d", metrics.CAPICount)
	}

	// Should have headroom for 2 more CAPI decisions
	stream := &lapi.DecisionStream{
		New: []lapi.Decision{
			{ID: 5, Origin: "CAPI", Value: "5.5.5.5", Scope: "ip"},
			{ID: 6, Origin: "CAPI", Value: "6.6.6.6", Scope: "ip"},
			{ID: 7, Origin: "CAPI", Value: "7.7.7.7", Scope: "ip"}, // should be dropped
		},
	}
	kept := tr.FilterStreamDecisions(stream)
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}

	metrics = tr.GetMetrics()
	if metrics.DecisionsDropped != 1 {
		t.Errorf("expected 1 dropped, got %d", metrics.DecisionsDropped)
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
	// Simulates the real-world scenario from issue #39:
	// Full sync sets 13000, then incremental adds trickle in one at a time
	tr := New(5, ModeCap, testLogger())

	// Simulate full sync result being used to set cap
	fullSyncDecisions := make([]lapi.Decision, 5)
	for i := range fullSyncDecisions {
		fullSyncDecisions[i] = lapi.Decision{
			ID: i + 1, Origin: "CAPI", Value: makeIP(i + 1), Scope: "ip",
		}
	}
	tr.SetCapFromFullSync(fullSyncDecisions)

	// Now incremental decisions arrive one at a time — all should be capped
	for i := 0; i < 10; i++ {
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
	if metrics.DecisionsDropped != 10 {
		t.Errorf("expected 10 dropped incrementals, got %d", metrics.DecisionsDropped)
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
