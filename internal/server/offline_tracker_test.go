package server

import (
	"path/filepath"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"
)

func TestOfflineTrackerWritesEventOnRecovery(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)
	offlineStart := time.Unix(1_930_000_000, 0).UTC()
	thresholdReachedAt := offlineStart.Add(5 * time.Minute)
	recoveryAt := offlineStart.Add(8 * time.Minute)

	store.nodes["node-1"] = NodeState{
		LastSeen:  offlineStart,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}

	store.ReconcileOfflineTracker(thresholdReachedAt)

	if state, ok := store.offlineSessions["node-1"]; !ok || state.StartedAt != offlineStart.Unix() {
		t.Fatalf("expected offline session to start at %d, got %+v present=%v", offlineStart.Unix(), state, ok)
	}

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), recoveryAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query offline summary before recovery: %v", err)
	}
	if summary.TotalCount != 0 {
		t.Fatalf("expected no offline events before recovery, got %d", summary.TotalCount)
	}

	store.nodes["node-1"] = NodeState{
		LastSeen:  recoveryAt,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}

	store.ReconcileOfflineTracker(recoveryAt)

	if _, ok := store.offlineSessions["node-1"]; ok {
		t.Fatal("expected offline session to be cleared after recovery")
	}

	summary, err = store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), recoveryAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query offline summary after recovery: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected one offline event after recovery, got %d", summary.TotalCount)
	}
	if summary.LongestDurationSec != 480 {
		t.Fatalf("expected offline duration 480 seconds, got %v", summary.LongestDurationSec)
	}
	if !summary.LastOfflineRecoveredAt.Equal(recoveryAt) {
		t.Fatalf("expected recovered at %s, got %s", recoveryAt, summary.LastOfflineRecoveredAt)
	}
}

func TestOfflineTrackerRecoveryAfterRestartUsesPersistedSession(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	dataPath := filepath.Join(dataDir, "state.json")
	historyPath := filepath.Join(dataDir, testHistoryFileName)
	offlineStart := time.Unix(1_940_000_000, 0).UTC()
	recoveryAt := offlineStart.Add(11 * time.Minute)

	settings := initSettings(Config{AdminPath: "/cm-admin"})
	settings.AlertOfflineSec = 300
	if err := savePersistedData(dataPath, PersistedData{
		Settings: settings,
		Profiles: map[string]*NodeProfile{},
		Nodes: map[string]NodeState{
			"node-1": {
				LastSeen:  offlineStart,
				FirstSeen: offlineStart.Add(-time.Hour),
				Stats:     metrics.NodeStats{NodeID: "node-1"},
			},
		},
		OfflineSessions: map[string]OfflineSessionState{
			"node-1": {StartedAt: offlineStart.Unix()},
		},
	}); err != nil {
		t.Fatalf("save persisted data: %v", err)
	}

	loaded, ok, err := loadPersistedData(dataPath)
	if err != nil {
		t.Fatalf("load persisted data: %v", err)
	}
	if !ok {
		t.Fatal("expected persisted data to load after restart")
	}
	if state, exists := loaded.OfflineSessions["node-1"]; !exists || state.StartedAt != offlineStart.Unix() {
		t.Fatalf("expected persisted offline session to survive restart, got %+v present=%v", state, exists)
	}

	manager, err := history.OpenManager(dataDir)
	if err != nil {
		t.Fatalf("open history manager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close history manager: %v", err)
		}
	})

	store := &Store{
		nodes:           loaded.Nodes,
		profiles:        loaded.Profiles,
		settings:        loaded.Settings,
		dataPath:        dataPath,
		historyPath:     historyPath,
		persistInterval: time.Hour,
		alerted:         make(map[string]alertState),
		offlineSessions: loaded.OfflineSessions,
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		historyManager:  manager,
		loginAttempts:   make(map[string]*loginAttempt),
	}

	store.nodes["node-1"] = NodeState{
		LastSeen:  recoveryAt,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}

	store.ReconcileOfflineTracker(recoveryAt)

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), recoveryAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query offline summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected one offline event after restart recovery, got %d", summary.TotalCount)
	}
	if summary.LongestDurationSec != 660 {
		t.Fatalf("expected offline duration 660 seconds, got %v", summary.LongestDurationSec)
	}
}

func TestOfflineTrackerStillWorksWhenAlertNotificationsDisabled(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)
	offlineStart := time.Unix(1_950_000_000, 0).UTC()
	recoveryAt := offlineStart.Add(9 * time.Minute)
	disabled := false
	store.profiles["node-1"] = &NodeProfile{AlertEnabled: &disabled}

	store.nodes["node-1"] = NodeState{
		LastSeen:  offlineStart,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}

	store.ReconcileOfflineTracker(offlineStart.Add(5 * time.Minute))

	store.nodes["node-1"] = NodeState{
		LastSeen:  recoveryAt,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}

	store.ReconcileOfflineTracker(recoveryAt)

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), recoveryAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query offline summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected offline tracker to write history even with alerts disabled, got %d", summary.TotalCount)
	}
	if summary.LongestDurationSec != 540 {
		t.Fatalf("expected offline duration 540 seconds, got %v", summary.LongestDurationSec)
	}
}

func TestOfflineTrackerRecoveryIsFinalizedByUpdateWithoutWaitingForTicker(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)
	offlineStart := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)

	store.nodes["node-1"] = NodeState{
		LastSeen:  offlineStart,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}
	store.offlineSessions["node-1"] = OfflineSessionState{StartedAt: offlineStart.Unix()}

	beforeUpdate := time.Now().UTC().Add(-time.Second)
	store.Update(metrics.NodeStats{NodeID: "node-1"})
	afterUpdate := time.Now().UTC().Add(time.Second)

	if _, ok := store.offlineSessions["node-1"]; ok {
		t.Fatal("expected Update to clear offline session immediately on recovery")
	}

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), afterUpdate)
	if err != nil {
		t.Fatalf("query offline summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected one offline event to be written by Update, got %d", summary.TotalCount)
	}
	if summary.LastOfflineRecoveredAt.Before(beforeUpdate) || summary.LastOfflineRecoveredAt.After(afterUpdate) {
		t.Fatalf("expected recovery timestamp between %s and %s, got %s", beforeUpdate, afterUpdate, summary.LastOfflineRecoveredAt)
	}
}

func TestOfflineTrackerUpdateSkipsExistingRecoveryForSameSessionAndClearsStaleSession(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)
	offlineStart := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)
	recordedRecoveryAt := offlineStart.Add(9 * time.Minute)
	queryEnd := time.Now().UTC().Add(time.Second)

	if err := store.historyManager.OfflineStore().AppendEvent("node-1", recordedRecoveryAt, recordedRecoveryAt.Sub(offlineStart)); err != nil {
		t.Fatalf("seed offline history: %v", err)
	}

	store.nodes["node-1"] = NodeState{
		LastSeen:  offlineStart,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}
	store.offlineSessions["node-1"] = OfflineSessionState{StartedAt: offlineStart.Unix()}

	store.Update(metrics.NodeStats{NodeID: "node-1"})

	if _, ok := store.offlineSessions["node-1"]; ok {
		t.Fatal("expected Update dedupe path to clear stale offline session")
	}

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), queryEnd)
	if err != nil {
		t.Fatalf("query offline summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected existing recovery event for same session to prevent duplicate append, got %d events", summary.TotalCount)
	}
	if !summary.LastOfflineRecoveredAt.Equal(recordedRecoveryAt) {
		t.Fatalf("expected dedupe to keep original recovered at %s, got %s", recordedRecoveryAt, summary.LastOfflineRecoveredAt)
	}
}

func TestStoreUpdatePreservesRawNetworkTotalsWhenAgentCountersDrop(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)

	store.Update(metrics.NodeStats{
		NodeID:    "node-1",
		NodeName:  "node-1",
		Timestamp: 1_960_000_100,
		Network: metrics.NetworkIO{
			BytesSent:     100 * 1024 * 1024,
			BytesRecv:     200 * 1024 * 1024,
			TxBytesPerSec: 4 * 1024,
			RxBytesPerSec: 8 * 1024,
		},
	})

	store.Update(metrics.NodeStats{
		NodeID:    "node-1",
		NodeName:  "node-1",
		Timestamp: 1_960_000_101,
		Network: metrics.NetworkIO{
			BytesSent:     95 * 1024 * 1024,
			BytesRecv:     190 * 1024 * 1024,
			TxBytesPerSec: 2 * 1024,
			RxBytesPerSec: 3 * 1024,
		},
	})

	snapshot := store.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("expected one node in snapshot, got %d", len(snapshot))
	}

	network := snapshot[0].Stats.Network
	if network.BytesSent != 95*1024*1024 {
		t.Fatalf("expected latest raw sent bytes to be preserved, got %d", network.BytesSent)
	}
	if network.BytesRecv != 190*1024*1024 {
		t.Fatalf("expected latest raw recv bytes to be preserved, got %d", network.BytesRecv)
	}
	if network.TxBytesPerSec != 2*1024 {
		t.Fatalf("expected latest tx rate to be preserved, got %v", network.TxBytesPerSec)
	}
	if network.RxBytesPerSec != 3*1024 {
		t.Fatalf("expected latest rx rate to be preserved, got %v", network.RxBytesPerSec)
	}
}

func TestOfflineTrackerReconcileSkipsDuplicateRecoveryEventAndClearsSession(t *testing.T) {
	t.Parallel()

	store := newOfflineTrackerTestStore(t)
	offlineStart := time.Unix(1_960_000_000, 0).UTC()
	recoveryAt := offlineStart.Add(12 * time.Minute)

	store.nodes["node-1"] = NodeState{
		LastSeen:  recoveryAt,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{NodeID: "node-1"},
	}
	store.offlineSessions["node-1"] = OfflineSessionState{StartedAt: offlineStart.Unix()}

	if err := store.historyManager.OfflineStore().AppendEvent("node-1", recoveryAt, recoveryAt.Sub(offlineStart)); err != nil {
		t.Fatalf("seed offline history: %v", err)
	}

	store.ReconcileOfflineTracker(recoveryAt.Add(time.Second))

	if _, ok := store.offlineSessions["node-1"]; ok {
		t.Fatal("expected duplicate recovery reconciliation to clear stale offline session")
	}

	summary, err := store.historyManager.OfflineStore().QuerySummary("node-1", offlineStart.Add(-time.Hour), recoveryAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query offline summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected dedupe path to keep exactly one recovery event, got %d", summary.TotalCount)
	}
	if !summary.LastOfflineRecoveredAt.Equal(recoveryAt) {
		t.Fatalf("expected recovered at %s, got %s", recoveryAt, summary.LastOfflineRecoveredAt)
	}
}

func newOfflineTrackerTestStore(t *testing.T) *Store {
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

	settings := initSettings(Config{AdminPath: "/cm-admin"})
	settings.AlertOfflineSec = 300

	return &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        settings,
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
