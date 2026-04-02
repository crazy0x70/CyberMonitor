package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveOrCreateNodeIDPrefersExplicitValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "node-id")
	got, err := resolveOrCreateNodeID("custom-node", filePath, func() string {
		return "generated-node"
	})
	if err != nil {
		t.Fatalf("resolve explicit node id: %v", err)
	}
	if got != "custom-node" {
		t.Fatalf("expected explicit node id, got %q", got)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("expected explicit node id to skip persistence, stat err=%v", err)
	}
}

func TestResolveOrCreateNodeIDLoadsPersistedValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "node-id")
	if err := os.WriteFile(filePath, []byte("persisted-node\n"), 0o600); err != nil {
		t.Fatalf("write persisted node id: %v", err)
	}
	got, err := resolveOrCreateNodeID("", filePath, func() string {
		return "generated-node"
	})
	if err != nil {
		t.Fatalf("resolve persisted node id: %v", err)
	}
	if got != "persisted-node" {
		t.Fatalf("expected persisted node id, got %q", got)
	}
}

func TestResolveOrCreateNodeIDGeneratesAndPersistsRandomValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "node-id")
	got, err := resolveOrCreateNodeID("", filePath, func() string {
		return "node-random-001"
	})
	if err != nil {
		t.Fatalf("resolve generated node id: %v", err)
	}
	if got != "node-random-001" {
		t.Fatalf("expected generated node id, got %q", got)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read generated node id file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "node-random-001" {
		t.Fatalf("expected generated node id to persist, got %q", string(data))
	}
}

func TestRegisterNodeTokenUsesBootstrapToken(t *testing.T) {
	t.Parallel()

	const (
		bootstrap = "bootstrap-token"
		nodeID    = "node-random-001"
		nodeToken = "node-token-001"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != bootstrap {
			t.Fatalf("expected bootstrap token header, got %q", got)
		}
		if got := r.URL.Query().Get("node_id"); got != nodeID {
			t.Fatalf("expected node_id query parameter, got %q", got)
		}
		_, _ = w.Write([]byte(`{"node_id":"` + nodeID + `","agent_token":"` + nodeToken + `"}`))
	}))
	defer server.Close()

	got, err := registerNodeToken(context.Background(), server.Client(), server.URL+"/register", nodeID, bootstrap)
	if err != nil {
		t.Fatalf("register node token: %v", err)
	}
	if got != nodeToken {
		t.Fatalf("expected node token %q, got %q", nodeToken, got)
	}
}

func TestPersistAgentTokenWritesTrimmedValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "agent-token")
	if err := persistAgentToken(filePath, " node-token-001 \n"); err != nil {
		t.Fatalf("persist agent token: %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read persisted agent token: %v", err)
	}
	if strings.TrimSpace(string(data)) != "node-token-001" {
		t.Fatalf("expected trimmed token, got %q", string(data))
	}
}
