package server

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestAgentGRPCRegisterIssuesDedicatedNodeToken(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	client := newTestAgentRPCClient(t, baseURL)
	resp, err := client.Register(context.Background(), &agentrpc.RegisterRequest{
		NodeID:         "node-123",
		BootstrapToken: "bootstrap-token",
	})
	if err != nil {
		t.Fatalf("grpc register node: %v", err)
	}
	if resp.NodeID != "node-123" {
		t.Fatalf("expected node_id node-123, got %q", resp.NodeID)
	}
	if resp.AgentToken == "" || resp.AgentToken == "bootstrap-token" {
		t.Fatalf("expected dedicated node token, got %q", resp.AgentToken)
	}
}

func TestAgentGRPCConfigAcceptsBootstrapTokenForLegacyAgentAndReturnsDedicatedToken(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	client := newTestAgentRPCClient(t, baseURL)
	resp, err := client.GetConfig(context.Background(), &agentrpc.ConfigRequest{
		NodeID:     "node-123",
		AgentToken: "bootstrap-token",
	})
	if err != nil {
		t.Fatalf("grpc get config with bootstrap token: %v", err)
	}
	if resp.AgentToken == "" || resp.AgentToken == "bootstrap-token" {
		t.Fatalf("expected config to return dedicated node token, got %q", resp.AgentToken)
	}

	resp, err = client.GetConfig(context.Background(), &agentrpc.ConfigRequest{
		NodeID:     "node-123",
		AgentToken: resp.AgentToken,
	})
	if err != nil {
		t.Fatalf("grpc get config with node token: %v", err)
	}
	if resp.TestIntervalSec == 0 {
		t.Fatalf("expected test interval to be populated")
	}
}

func TestAgentGRPCReportStatsPreservesPublicHistoryPath(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	store := &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        initSettings(Config{AdminPath: "/cm-admin", AgentToken: "bootstrap-token"}),
		dataPath:        filepath.Join(dataDir, "state.json"),
		historyPath:     filepath.Join(dataDir, "test_history.json"),
		persistInterval: time.Hour,
		alerted:         make(map[string]alertState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		loginAttempts:   make(map[string]*loginAttempt),
	}
	api := newAgentAPI(store, &Hub{clients: make(map[*websocket.Conn]*hubClient)}, &Config{
		AgentToken: "bootstrap-token",
	})
	server := &agentRPCServer{api: api}

	latency := 24.5
	_, err := server.ReportStats(context.Background(), &agentrpc.ReportStatsRequest{
		AgentToken: "bootstrap-token",
		Stats: metrics.NodeStats{
			NodeID:    "grpc-node-1",
			NodeName:  "grpc-node-1",
			Hostname:  "grpc-host",
			OS:        "linux",
			Arch:      "amd64",
			Timestamp: time.Now().Unix(),
			CPU:       metrics.CPUInfo{UsagePercent: 1.5},
			Memory:    metrics.MemInfo{Total: 1024, Used: 512, Free: 512, UsedPercent: 50},
			Disk:      []metrics.DiskPartition{},
			DiskIO:    metrics.DiskIO{},
			Network:   metrics.NetworkIO{},
			NetworkTests: []metrics.NetworkTestResult{
				{
					Name:       "edge-hk",
					Type:       "tcp",
					Host:       "1.1.1.1",
					Port:       443,
					LatencyMs:  &latency,
					PacketLoss: 0,
					Status:     "online",
					CheckedAt:  time.Now().Unix(),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("grpc report stats: %v", err)
	}

	history := store.snapshotTestHistory()
	if len(history["grpc-node-1"]) == 0 {
		t.Fatalf("expected grpc stats to update shared test history path")
	}
}

func TestAgentGRPCReportStatsRejectsDedicatedNodeMismatch(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	store := &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        initSettings(Config{AdminPath: "/cm-admin", AgentToken: "bootstrap-token"}),
		dataPath:        filepath.Join(dataDir, "state.json"),
		historyPath:     filepath.Join(dataDir, "test_history.json"),
		persistInterval: time.Hour,
		alerted:         make(map[string]alertState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		loginAttempts:   make(map[string]*loginAttempt),
	}
	token := store.ensureAgentAuthToken("node-123")
	api := newAgentAPI(store, &Hub{clients: make(map[*websocket.Conn]*hubClient)}, &Config{
		AgentToken: "bootstrap-token",
	})
	server := &agentRPCServer{api: api}

	_, err := server.ReportStats(context.Background(), &agentrpc.ReportStatsRequest{
		AgentToken: token,
		Stats: metrics.NodeStats{
			NodeID:    "other-node",
			NodeName:  "other-node",
			Hostname:  "other-node",
			OS:        "linux",
			Arch:      "amd64",
			Timestamp: time.Now().Unix(),
			CPU:       metrics.CPUInfo{},
			Memory:    metrics.MemInfo{},
			Disk:      []metrics.DiskPartition{},
			DiskIO:    metrics.DiskIO{},
			Network:   metrics.NetworkIO{},
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated mismatch error, got %v", err)
	}
}

func TestAgentGRPCReportUpdateClearsPendingTaskOnSuccess(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	store := &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        initSettings(Config{AdminPath: "/cm-admin", AgentToken: "bootstrap-token"}),
		dataPath:        filepath.Join(dataDir, "state.json"),
		historyPath:     filepath.Join(dataDir, "test_history.json"),
		persistInterval: time.Hour,
		alerted:         make(map[string]alertState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		loginAttempts:   make(map[string]*loginAttempt),
	}
	nodeToken := store.ensureAgentAuthToken("node-123")
	store.QueueAgentUpdate("node-123", AgentUpdateInstruction{
		Version:     "1.1.0",
		DownloadURL: "https://example.com/agent",
	})
	api := newAgentAPI(store, &Hub{clients: make(map[*websocket.Conn]*hubClient)}, &Config{
		AgentToken: "bootstrap-token",
	})
	server := &agentRPCServer{api: api}

	resp, err := server.ReportUpdate(context.Background(), &agentrpc.ReportUpdateRequest{
		NodeID:     "node-123",
		AgentToken: nodeToken,
		State:      "succeeded",
		Version:    "1.1.0",
		Message:    "done",
	})
	if err != nil {
		t.Fatalf("grpc report update: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected report update status ok, got %q", resp.Status)
	}

	config := store.AgentConfig("node-123")
	if config.Update != nil {
		t.Fatalf("expected pending update to be cleared after success report")
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	if got := store.profiles["node-123"].AgentUpdateState; got != "succeeded" {
		t.Fatalf("expected update state succeeded, got %q", got)
	}
}

func newTestAgentRPCClient(t *testing.T, baseURL string) agentrpc.AgentServiceClient {
	t.Helper()

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		parsed.Host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(agentrpc.GobCodec{})),
	)
	if err != nil {
		t.Fatalf("dial grpc server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return agentrpc.NewAgentServiceClient(conn)
}
