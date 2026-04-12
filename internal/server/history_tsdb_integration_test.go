package server

import (
	"path/filepath"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"
)

func TestDeleteNodeRemovesOnlyMatchingTSDBHistory(t *testing.T) {
	t.Parallel()

	store := newHistoryIntegratedStore(t)
	now := time.Unix(1_840_000_000, 0).UTC()

	seedHistoryStore(t, store, "node-a", "1.1.1.1", "a", now, 15)
	seedHistoryStore(t, store, "node-b", "8.8.8.8", "b", now, 25)
	seedOfflineHistoryStore(t, store, "node-a", now, 12*time.Minute)
	seedOfflineHistoryStore(t, store, "node-b", now, 20*time.Minute)
	store.nodes["node-a"] = NodeState{Stats: metrics.NodeStats{NodeID: "node-a"}}
	store.nodes["node-b"] = NodeState{Stats: metrics.NodeStats{NodeID: "node-b"}}
	store.profiles["node-a"] = &NodeProfile{}
	store.profiles["node-b"] = &NodeProfile{}

	if !store.DeleteNode("node-a") {
		t.Fatal("expected node-a deletion to report existing node")
	}

	nodeAHistory, err := store.historyManager.NetworkStore().QueryRange("node-a", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-a history: %v", err)
	}
	if len(nodeAHistory) != 0 {
		t.Fatalf("expected node-a TSDB history to be deleted, got %d series", len(nodeAHistory))
	}

	nodeBHistory, err := store.historyManager.NetworkStore().QueryRange("node-b", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-b history: %v", err)
	}
	if len(nodeBHistory) != 1 {
		t.Fatalf("expected node-b TSDB history to remain, got %d series", len(nodeBHistory))
	}

	nodeAOffline, err := store.historyManager.OfflineStore().QuerySummary("node-a", now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-a offline history: %v", err)
	}
	if nodeAOffline.TotalCount != 0 {
		t.Fatalf("expected node-a offline TSDB history to be deleted, got %d events", nodeAOffline.TotalCount)
	}

	nodeBOffline, err := store.historyManager.OfflineStore().QuerySummary("node-b", now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-b offline history: %v", err)
	}
	if nodeBOffline.TotalCount != 1 {
		t.Fatalf("expected node-b offline TSDB history to remain, got %d events", nodeBOffline.TotalCount)
	}
}

func TestClearNodesAlsoClearsTSDBHistory(t *testing.T) {
	t.Parallel()

	store := newHistoryIntegratedStore(t)
	now := time.Unix(1_850_000_000, 0).UTC()

	seedHistoryStore(t, store, "node-a", "1.1.1.1", "a", now, 15)
	seedHistoryStore(t, store, "node-b", "8.8.8.8", "b", now, 25)
	seedOfflineHistoryStore(t, store, "node-a", now, 12*time.Minute)
	seedOfflineHistoryStore(t, store, "node-b", now, 20*time.Minute)
	store.nodes["node-a"] = NodeState{Stats: metrics.NodeStats{NodeID: "node-a"}}
	store.nodes["node-b"] = NodeState{Stats: metrics.NodeStats{NodeID: "node-b"}}
	store.profiles["node-a"] = &NodeProfile{}
	store.profiles["node-b"] = &NodeProfile{}

	store.ClearNodes()

	nodeAHistory, err := store.historyManager.NetworkStore().QueryRange("node-a", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-a history: %v", err)
	}
	nodeBHistory, err := store.historyManager.NetworkStore().QueryRange("node-b", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-b history: %v", err)
	}
	if len(nodeAHistory) != 0 || len(nodeBHistory) != 0 {
		t.Fatalf("expected TSDB history to be cleared for all nodes, got node-a=%d node-b=%d", len(nodeAHistory), len(nodeBHistory))
	}

	nodeAOffline, err := store.historyManager.OfflineStore().QuerySummary("node-a", now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-a offline history: %v", err)
	}
	nodeBOffline, err := store.historyManager.OfflineStore().QuerySummary("node-b", now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-b offline history: %v", err)
	}
	if nodeAOffline.TotalCount != 0 || nodeBOffline.TotalCount != 0 {
		t.Fatalf("expected offline TSDB history to be cleared for all nodes, got node-a=%d node-b=%d", nodeAOffline.TotalCount, nodeBOffline.TotalCount)
	}
}

func newHistoryIntegratedStore(t *testing.T) *Store {
	t.Helper()

	dataDir := t.TempDir()
	manager, err := history.OpenManager(dataDir)
	if err != nil {
		t.Fatalf("open history manager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close history manager: %v", err)
		}
	})

	return &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        initSettings(Config{AdminPath: "/cm-admin"}),
		dataPath:        filepath.Join(dataDir, "state.json"),
		historyPath:     filepath.Join(dataDir, testHistoryFileName),
		persistInterval: time.Hour,
		alerted:         make(map[string]alertState),
		offlineSessions: make(map[string]OfflineSessionState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		historyManager:  manager,
		loginAttempts:   make(map[string]*loginAttempt),
	}
}

func seedHistoryStore(
	t *testing.T,
	store *Store,
	nodeID string,
	host string,
	name string,
	now time.Time,
	latency float64,
) {
	t.Helper()

	if err := store.historyManager.AppendNetworkBatch(nodeID, []metrics.NetworkTestResult{{
		Type:       "icmp",
		Host:       host,
		Name:       name,
		CheckedAt:  now.Unix(),
		LatencyMs:  &latency,
		PacketLoss: 0,
		Status:     "online",
	}}, now); err != nil {
		t.Fatalf("append network history for %s: %v", nodeID, err)
	}
}

func seedOfflineHistoryStore(t *testing.T, store *Store, nodeID string, recoveredAt time.Time, duration time.Duration) {
	t.Helper()

	if err := store.historyManager.OfflineStore().AppendEvent(nodeID, recoveredAt, duration); err != nil {
		t.Fatalf("append offline history for %s: %v", nodeID, err)
	}
}
