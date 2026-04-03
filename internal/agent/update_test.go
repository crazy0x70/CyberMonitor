package agent

import (
	"context"
	"testing"

	"cyber_monitor/internal/metrics"
)

type stubControlPlane struct {
	reports []map[string]string
}

func (s *stubControlPlane) RegisterNodeToken(context.Context, string, string) (string, error) {
	return "", nil
}

func (s *stubControlPlane) FetchConfig(context.Context, string, string) (RemoteConfig, error) {
	return RemoteConfig{}, nil
}

func (s *stubControlPlane) ReportStats(context.Context, metrics.NodeStats, string) error {
	return nil
}

func (s *stubControlPlane) ReportUpdate(_ context.Context, nodeID, token, state, version, message string) error {
	s.reports = append(s.reports, map[string]string{
		"node_id": nodeID,
		"token":   token,
		"state":   state,
		"version": version,
		"message": message,
	})
	return nil
}

func (s *stubControlPlane) Close() error {
	return nil
}

func TestMaybeApplyRemoteUpdateHonorsDisableUpdate(t *testing.T) {
	t.Parallel()

	transport := &stubControlPlane{}

	cfg := Config{
		NodeID:        "node-1",
		AgentToken:    "agent-token",
		AgentVersion:  "1.0.0",
		DisableUpdate: true,
	}

	err := maybeApplyRemoteUpdate(context.Background(), transport, cfg, &RemoteUpdateInstruction{
		Version:     "1.1.0",
		DownloadURL: "https://example.com/cyber-monitor-agent",
	})
	if err != nil {
		t.Fatalf("maybe apply remote update: %v", err)
	}
	if len(transport.reports) != 1 {
		t.Fatalf("expected exactly one update report, got %d", len(transport.reports))
	}
	if transport.reports[0]["state"] != "failed" {
		t.Fatalf("expected failed report state, got %q", transport.reports[0]["state"])
	}
	if transport.reports[0]["version"] != "1.1.0" {
		t.Fatalf("expected target version 1.1.0, got %q", transport.reports[0]["version"])
	}
	if transport.reports[0]["message"] != "当前 Agent 已禁用远程更新" {
		t.Fatalf("unexpected disable update message: %q", transport.reports[0]["message"])
	}
}
