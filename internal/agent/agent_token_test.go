package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistedDedicatedTokenPreferredOverBootstrapToken(t *testing.T) {
	originalDialTimeout := grpcDialTimeout
	originalCallTimeout := grpcCallTimeout
	originalReadyTimeout := grpcReadyTimeout
	grpcDialTimeout = 25 * time.Millisecond
	grpcCallTimeout = 25 * time.Millisecond
	grpcReadyTimeout = 10 * time.Millisecond
	defer func() {
		grpcDialTimeout = originalDialTimeout
		grpcCallTimeout = originalCallTimeout
		grpcReadyTimeout = originalReadyTimeout
	}()

	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	mustWriteFile(t, tokenFile, " dedicated-token \n")

	var registerHits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/register":
			registerHits.Add(1)
			t.Fatalf("unexpected register call when dedicated token already exists")
		case "/api/v1/agent/config":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected persisted dedicated token for config request, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alias":             "",
				"group":             "",
				"test_interval_sec": 5,
				"tests":             []any{},
			})
		case "/api/v1/ingest":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected persisted dedicated token for ingest request, got %q", got)
			}
			cancel()
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := Run(ctx, Config{
		ServerURL:  server.URL,
		Interval:   time.Hour,
		NodeID:     "node-1",
		NodeName:   "node-1",
		AgentToken: "bootstrap-token",
		TokenFile:  tokenFile,
		HostRoot:   t.TempDir(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want %v", err, context.Canceled)
	}
	if got := registerHits.Load(); got != 0 {
		t.Fatalf("register hits = %d, want 0", got)
	}
}

func TestBootstrapDedicatedTokenPersistsAcrossRestarts(t *testing.T) {
	originalDialTimeout := grpcDialTimeout
	originalCallTimeout := grpcCallTimeout
	originalReadyTimeout := grpcReadyTimeout
	grpcDialTimeout = 25 * time.Millisecond
	grpcCallTimeout = 25 * time.Millisecond
	grpcReadyTimeout = 10 * time.Millisecond
	defer func() {
		grpcDialTimeout = originalDialTimeout
		grpcCallTimeout = originalCallTimeout
		grpcReadyTimeout = originalReadyTimeout
	}()

	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	cfg := Config{
		Interval:   time.Hour,
		NodeID:     "node-1",
		NodeName:   "node-1",
		AgentToken: "bootstrap-token",
		TokenFile:  tokenFile,
		HostRoot:   t.TempDir(),
	}

	var firstRegisterHits atomic.Int32
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/register":
			firstRegisterHits.Add(1)
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "bootstrap-token" {
				t.Fatalf("expected bootstrap token for register request, got %q", got)
			}
			_, _ = w.Write([]byte(`{"node_id":"node-1","agent_token":"dedicated-token"}`))
		case "/api/v1/agent/config":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected dedicated token after register for config request, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alias":             "",
				"group":             "",
				"test_interval_sec": 5,
				"tests":             []any{},
			})
		case "/api/v1/ingest":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected dedicated token after register for ingest request, got %q", got)
			}
			cancel1()
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer firstServer.Close()

	cfg.ServerURL = firstServer.URL
	err := Run(ctx1, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("first Run() error = %v, want %v", err, context.Canceled)
	}
	if got := firstRegisterHits.Load(); got != 1 {
		t.Fatalf("first register hits = %d, want 1", got)
	}
	if got := strings.TrimSpace(mustReadTrimmedFile(t, tokenFile)); got != "dedicated-token" {
		t.Fatalf("persisted token after bootstrap = %q, want %q", got, "dedicated-token")
	}

	var secondRegisterHits atomic.Int32
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/register":
			secondRegisterHits.Add(1)
			t.Fatalf("unexpected register call after dedicated token was persisted")
		case "/api/v1/agent/config":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected persisted dedicated token after restart for config request, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alias":             "",
				"group":             "",
				"test_interval_sec": 5,
				"tests":             []any{},
			})
		case "/api/v1/ingest":
			if got := r.Header.Get("X-AGENT-TOKEN"); got != "dedicated-token" {
				t.Fatalf("expected persisted dedicated token after restart for ingest request, got %q", got)
			}
			cancel2()
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer secondServer.Close()

	cfg.ServerURL = secondServer.URL
	err = Run(ctx2, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("second Run() error = %v, want %v", err, context.Canceled)
	}
	if got := secondRegisterHits.Load(); got != 0 {
		t.Fatalf("second register hits = %d, want 0", got)
	}
}
