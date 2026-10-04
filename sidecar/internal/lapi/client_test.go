package lapi

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestClient_GetAlerts(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		statusCode int
		wantCount  int
		wantErr    bool
	}{
		{
			name: "successful alert fetch",
			response: `[
				{"id":1,"scenario":"crowdsecurity/ssh-bf","source":{"ip":"1.2.3.4","scope":"ip","value":"1.2.3.4"}},
				{"id":2,"scenario":"crowdsecurity/http-probing","source":{"ip":"5.6.7.8","scope":"ip","value":"5.6.7.8"}}
			]`,
			statusCode: http.StatusOK,
			wantCount:  2,
		},
		{
			name:       "null response",
			response:   "null",
			statusCode: http.StatusOK,
			wantCount:  0,
		},
		{
			name:       "empty array response",
			response:   "[]",
			statusCode: http.StatusOK,
			wantCount:  0,
		},
		{
			name:       "LAPI error",
			response:   "internal server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/alerts" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Header.Get("X-Api-Key") != "test-key" {
					t.Errorf("missing or wrong API key")
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-key", 0)
			alerts, err := client.GetAlerts(context.Background(), nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetAlerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(alerts) != tt.wantCount {
				t.Errorf("GetAlerts() returned %d alerts, want %d", len(alerts), tt.wantCount)
			}
		})
	}
}

func TestClient_GetAlerts_WithParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since := r.URL.Query().Get("since")
		if since != "15m0s" {
			t.Errorf("expected since=15m0s, got %s", since)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":1,"scenario":"ssh-bf","source":{"ip":"1.2.3.4","scope":"ip","value":"1.2.3.4"}}]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", 0)
	params := url.Values{}
	params.Set("since", "15m0s")

	alerts, err := client.GetAlerts(context.Background(), params)
	if err != nil {
		t.Fatalf("GetAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Source.IP != "1.2.3.4" {
		t.Errorf("expected source IP 1.2.3.4, got %s", alerts[0].Source.IP)
	}
}

func TestClient_GetAlerts_ParsesFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{
			"id": 42,
			"scenario": "crowdsecurity/ssh-bf",
			"source": {
				"ip": "10.0.0.1",
				"scope": "ip",
				"value": "10.0.0.1"
			}
		}]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", 0)
	alerts, err := client.GetAlerts(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetAlerts() error = %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.ID != 42 {
		t.Errorf("ID = %d, want 42", alert.ID)
	}
	if alert.Scenario != "crowdsecurity/ssh-bf" {
		t.Errorf("Scenario = %s, want crowdsecurity/ssh-bf", alert.Scenario)
	}
	if alert.Source.IP != "10.0.0.1" {
		t.Errorf("Source.IP = %s, want 10.0.0.1", alert.Source.IP)
	}
	if alert.Source.Scope != "ip" {
		t.Errorf("Source.Scope = %s, want ip", alert.Source.Scope)
	}
}

func TestClient_TLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	// Default client must reject the self-signed server cert.
	if _, err := NewClient(srv.URL, "k", 0).GetDecisions(context.Background(), nil); err == nil {
		t.Fatal("expected certificate error with default TLS")
	}

	// With the server CA configured it succeeds.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := BuildTLSConfig(TLSOptions{CACertPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientWithTLS(srv.URL, "k", 0, cfg).GetDecisions(context.Background(), nil); err != nil {
		t.Fatalf("CA-configured client failed: %v", err)
	}

	// insecure_skip_verify also works.
	cfg, _ = BuildTLSConfig(TLSOptions{InsecureSkipVerify: true})
	if _, err := NewClientWithTLS(srv.URL, "k", 0, cfg).GetDecisions(context.Background(), nil); err != nil {
		t.Fatalf("insecure client failed: %v", err)
	}
}

func TestBuildTLSConfig_Errors(t *testing.T) {
	if cfg, err := BuildTLSConfig(TLSOptions{}); cfg != nil || err != nil {
		t.Fatal("zero options should return nil config")
	}
	if _, err := BuildTLSConfig(TLSOptions{CACertPath: "/nonexistent"}); err == nil {
		t.Fatal("expected error for missing CA")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := BuildTLSConfig(TLSOptions{CACertPath: bad}); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if _, err := BuildTLSConfig(TLSOptions{ClientCertPath: "c.pem"}); err == nil {
		t.Fatal("expected error when key missing")
	}
}
