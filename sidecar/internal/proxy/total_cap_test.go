package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/lapi"
)

func capDecision(id int, v string) lapi.Decision {
	return lapi.Decision{ID: id, Origin: "CAPI", Value: v, Scope: "Ip", Type: "ban", Duration: "1h"}
}
func capPoll(t *testing.T, h *Handler, start bool) (int, lapi.DecisionStream) {
	t.Helper()
	u := "/v1/decisions/stream"
	if start {
		u += "?startup=true"
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u, nil))
	var s lapi.DecisionStream
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, s
}
func TestTotalCapHandlerGateFamilyAndStartup(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		s := lapi.DecisionStream{}
		if r.URL.Query().Get("startup") == "true" {
			s.New = []lapi.Decision{capDecision(1, "192.0.2.1"), capDecision(2, "192.0.2.2"), capDecision(3, "192.0.2.3"), capDecision(4, "2001:db8::1")}
		} else {
			s.New = []lapi.Decision{capDecision(1, "192.0.2.1"), capDecision(3, "192.0.2.3"), capDecision(5, "2001:db8::2")}
		}
		json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.CapScope = "total"
	cfg.MaxDecisions = 2
	cfg.MaxDecisionsV6 = 2
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 3; i++ {
		if code, _ := capPoll(t, h, false); code != 503 {
			t.Fatalf("pre-sync code=%d", code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("gated delta advanced upstream cursor")
	}
	if code, s := capPoll(t, h, true); code != 200 || len(s.New) != 3 {
		t.Fatalf("startup=%d %+v", code, s)
	}
	code, s := capPoll(t, h, false)
	if code != 200 || len(s.New) != 2 {
		t.Fatalf("want loaded v4 refresh + new v6, got%d %+v", code, s)
	}
	if h.streamTracker.GetMetrics().BaseCount != 2 || h.streamTrackerV6.GetMetrics().CAPICount != 1 {
		t.Fatal("family accounting diverged")
	}
}
func TestTotalCapStartupSerializesDeltas(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var deltaCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("startup") == "true" {
			close(entered)
			<-release
			json.NewEncoder(w).Encode(lapi.DecisionStream{New: []lapi.Decision{capDecision(1, "192.0.2.1")}})
		} else {
			deltaCalls.Add(1)
			json.NewEncoder(w).Encode(lapi.DecisionStream{New: []lapi.Decision{capDecision(2, "192.0.2.2")}})
		}
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.CapScope = "total"
	cfg.MaxDecisions = 1
	h := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); capPoll(t, h, true) }()
	<-entered
	done := make(chan struct{})
	go func() { defer wg.Done(); capPoll(t, h, false); close(done) }()
	// Startup is blocked upstream; delta must not fetch or complete until release.
	select {
	case <-done:
		t.Fatal("delta escaped startup critical section")
	case <-time.After(30 * time.Millisecond):
	}
	if deltaCalls.Load() != 0 {
		t.Fatal("delta fetched upstream during startup")
	}
	close(release)
	wg.Wait()
	if len(h.streamTracker.GetMetrics().EvictionMode) == 0 || h.streamTracker.GetMetrics().BaseCount != 1 || h.streamTracker.GetMetrics().CAPICount != 0 {
		t.Fatal("delta admitted beyond full baseline")
	}
}
func TestDefaultCapDeltaIsNotGated(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(lapi.DecisionStream{})
	}))
	defer server.Close()
	h := New(testConfig(server.URL), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if code, _ := capPoll(t, h, false); code != 200 || calls.Load() != 1 {
		t.Fatal("legacy delta behavior changed")
	}
}
