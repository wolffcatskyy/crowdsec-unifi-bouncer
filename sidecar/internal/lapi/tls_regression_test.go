package lapi

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSOptionsRequireBothClientFiles(t *testing.T) {
	for _, opts := range []TLSOptions{{ClientCertPath: "cert.pem"}, {ClientKeyPath: "key.pem"}} {
		if _, err := BuildTLSConfig(opts); err == nil {
			t.Fatal("unpaired client credentials must fail")
		}
	}
}

func TestConfiguredTLSMinimumAndVerification(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d", cfg.MinVersion)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" {
			t.Error("API key missing")
		}
		if r.URL.Path == "/v1/decisions/stream" {
			w.Write([]byte(`{"new":[],"deleted":[]}`))
		} else {
			w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = BuildTLSConfig(TLSOptions{CACertPath: ca})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("custom CA must not turn off verification")
	}
	client := NewClientWithTLS(srv.URL, "test-key", 0, cfg)
	if _, err := client.GetAlerts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetDecisionsStream(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}
