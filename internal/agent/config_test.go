package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchRemoteConfigIncludesNodeIDAndToken(t *testing.T) {
	t.Parallel()

	const expectedToken = "agent-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("node_id"); got != "node-123" {
			t.Fatalf("expected node_id query parameter, got %q", got)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != expectedToken {
			t.Fatalf("expected agent token header, got %q", got)
		}
		_, _ = w.Write([]byte(`{"alias":"edge-a","group":"cn","agent_token":"node-token-001","tests":[{"name":"probe","type":"tcp","host":"example.com","port":443}],"test_interval_sec":12,"update":{"version":"1.2.3","download_url":"https://example.com/agent","checksum_url":"https://example.com/checksums.txt"}}`))
	}))
	defer server.Close()

	cfg, err := fetchRemoteConfig(context.Background(), server.Client(), server.URL+"/config", "node-123", expectedToken)
	if err != nil {
		t.Fatalf("fetch remote config: %v", err)
	}
	if cfg.Alias != "edge-a" || cfg.Group != "cn" || cfg.TestIntervalSec != 12 {
		t.Fatalf("unexpected remote config payload: %+v", cfg)
	}
	if len(cfg.Tests) != 1 || cfg.Tests[0].Host != "example.com" || cfg.Tests[0].Port != 443 {
		t.Fatalf("unexpected tests payload: %+v", cfg.Tests)
	}
	if cfg.Update == nil || cfg.Update.Version != "1.2.3" {
		t.Fatalf("expected remote update payload, got %+v", cfg.Update)
	}
	if cfg.AgentToken != "node-token-001" {
		t.Fatalf("expected node-specific agent token, got %q", cfg.AgentToken)
	}
}

func TestFetchRemoteConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alias":"edge-a","extra":"unexpected"}`))
	}))
	defer server.Close()

	_, err := fetchRemoteConfig(context.Background(), server.Client(), server.URL, "node-123", "")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestFetchRemoteConfigRejectsTrailingData(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alias":"edge-a"}{}`))
	}))
	defer server.Close()

	_, err := fetchRemoteConfig(context.Background(), server.Client(), server.URL, "node-123", "")
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected trailing data error, got %v", err)
	}
}

func TestFetchRemoteConfigSurfacesStatusBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing profile", http.StatusNotFound)
	}))
	defer server.Close()

	_, err := fetchRemoteConfig(context.Background(), server.Client(), server.URL, "node-123", "")
	if err == nil || !strings.Contains(err.Error(), "config status 404") || !strings.Contains(err.Error(), "missing profile") {
		t.Fatalf("expected surfaced status body, got %v", err)
	}
}
