package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
)

func TestHealthURLFromConfig(t *testing.T) {
	tests := []struct {
		listen, path, want string
	}{
		{"0.0.0.0:8084", "/health", "http://127.0.0.1:8084/health"},
		{":8084", "", "http://127.0.0.1:8084/health"},
		{"127.0.0.1:8081", "/healthz", "http://127.0.0.1:8081/healthz"},
		{"[::]:8084", "/health", "http://127.0.0.1:8084/health"},
		{"not-an-addr", "/health", defaultHealthURL},
	}
	for _, tt := range tests {
		cfg := &config.Config{ListenAddr: tt.listen}
		cfg.Health.Path = tt.path
		if got := healthURLFromConfig(cfg); got != tt.want {
			t.Errorf("healthURLFromConfig(%q, %q) = %q, want %q", tt.listen, tt.path, got, tt.want)
		}
	}
}

func TestRunHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()

	*healthcheckURL = srv.URL + "/health"
	defer func() { *healthcheckURL = "" }()

	if code := runHealthcheck("/nonexistent"); code != 0 {
		t.Errorf("healthy endpoint: exit %d, want 0", code)
	}
	status = http.StatusServiceUnavailable
	if code := runHealthcheck("/nonexistent"); code != 1 {
		t.Errorf("degraded endpoint: exit %d, want 1", code)
	}
	srv.Close()
	if code := runHealthcheck("/nonexistent"); code != 1 {
		t.Errorf("unreachable endpoint: exit %d, want 1", code)
	}
}
