package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaybeApplyRemoteUpdateHonorsDisableUpdate(t *testing.T) {
	t.Parallel()

	var reports []map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode update report: %v", err)
		}
		reports = append(reports, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		NodeID:        "node-1",
		AgentToken:    "agent-token",
		AgentVersion:  "1.0.0",
		DisableUpdate: true,
	}

	err := maybeApplyRemoteUpdate(context.Background(), server.Client(), server.URL, cfg, &RemoteUpdateInstruction{
		Version:     "1.1.0",
		DownloadURL: "https://example.com/cyber-monitor-agent",
	})
	if err != nil {
		t.Fatalf("maybe apply remote update: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected exactly one update report, got %d", len(reports))
	}
	if reports[0]["state"] != "failed" {
		t.Fatalf("expected failed report state, got %q", reports[0]["state"])
	}
	if reports[0]["version"] != "1.1.0" {
		t.Fatalf("expected target version 1.1.0, got %q", reports[0]["version"])
	}
	if reports[0]["message"] != "当前 Agent 已禁用远程更新" {
		t.Fatalf("unexpected disable update message: %q", reports[0]["message"])
	}
}
