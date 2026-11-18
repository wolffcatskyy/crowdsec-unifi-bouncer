package tracker

import (
	"io"
	"log/slog"
	"testing"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

func remoteTotal(id int, value string) lapi.Decision {
	return lapi.Decision{ID: id, Origin: "CAPI", Value: value, Scope: "Ip", Type: "ban"}
}

func TestTotalCapBaselineRefreshDeletionAndTail(t *testing.T) {
	tr := NewWithScope(2, ModeCap, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a, b, c, d := remoteTotal(1, "192.0.2.1"), remoteTotal(2, "192.0.2.2"), remoteTotal(3, "192.0.2.3"), remoteTotal(4, "192.0.2.4")
	tr.SetCapFromFullSync([]lapi.Decision{a, b, a})
	if len(tr.trackedSet) != 2 {
		t.Fatal("baseline must count unique values")
	}
	// c represents a value truncated by the scorer and later reissued.
	kept, _ := tr.FilterStreamDecisions(&lapi.DecisionStream{New: []lapi.Decision{a, c, d}})
	if len(kept) != 1 || kept[0].Value != a.Value {
		t.Fatalf("only loaded refresh should pass: %+v", kept)
	}
	// Unknown/duplicate deletions must not invent free slots.
	tr.FilterStreamDecisions(&lapi.DecisionStream{Deleted: []lapi.Decision{c, c}, New: []lapi.Decision{d}})
	if len(tr.trackedSet) != 2 {
		t.Fatal("unknown deletion changed occupancy")
	}
	kept, _ = tr.FilterStreamDecisions(&lapi.DecisionStream{Deleted: []lapi.Decision{a, a}, New: []lapi.Decision{c, d}})
	if len(kept) != 1 || kept[0].Value != c.Value || len(tr.trackedSet) != 2 {
		t.Fatalf("one expiry must free exactly one slot: %+v", kept)
	}
	// Local values remain outside nonlocal accounting and always pass.
	local := lapi.Decision{ID: 9, Origin: "cscli", Value: "192.0.2.9", Scope: "Ip", Type: "ban"}
	kept, _ = tr.FilterStreamDecisions(&lapi.DecisionStream{New: []lapi.Decision{local}})
	if len(kept) != 1 || len(tr.trackedSet) != 2 {
		t.Fatal("local priority/count changed")
	}
}

func TestTotalCapDefensivelyNeverEvicts(t *testing.T) {
	tr := NewWithScope(1, ModeEvict, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tr.SetCapFromFullSync([]lapi.Decision{remoteTotal(1, "192.0.2.1")})
	kept, evicted := tr.FilterStreamDecisions(&lapi.DecisionStream{New: []lapi.Decision{remoteTotal(2, "192.0.2.2")}})
	if len(kept) != 0 || len(evicted) != 0 {
		t.Fatal("total mode must never synthesize eviction")
	}
}
