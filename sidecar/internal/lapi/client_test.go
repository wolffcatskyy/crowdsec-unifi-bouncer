package lapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
