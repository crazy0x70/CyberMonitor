package server

import (
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func newAlertDurationTestStore(thresholdSec int64) *Store {
	settings := initSettings(Config{
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "admin123",
	})
	settings.AlertOfflineSec = thresholdSec
	settings.AlertWebhook = "https://example.com/webhook"

	return &Store{
		nodes:    map[string]NodeState{},
		profiles: map[string]*NodeProfile{},
		settings: settings,
		alerted:  map[string]alertState{},
	}
}

func TestCollectAlertEventsRecoveryUsesTotalDowntime(t *testing.T) {
	t.Parallel()

	store := newAlertDurationTestStore(300)

	offlineStart := time.Unix(1_700_000_000, 0)
	firstCheck := offlineStart.Add(5 * time.Minute)
	recoveryAt := offlineStart.Add(8 * time.Minute)

	store.nodes["node-1"] = NodeState{
		LastSeen:  offlineStart,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{},
	}

	_, offlineEvents, recoveredEvents := store.CollectAlertEvents(firstCheck)
	if len(offlineEvents) != 1 {
		t.Fatalf("expected one offline alert, got %d", len(offlineEvents))
	}
	if len(recoveredEvents) != 0 {
		t.Fatalf("expected no recovery alert on first check, got %d", len(recoveredEvents))
	}
	if offlineEvents[0].OfflineSec != int64(5*time.Minute/time.Second) {
		t.Fatalf("expected initial offline duration 300 seconds, got %d", offlineEvents[0].OfflineSec)
	}

	store.nodes["node-1"] = NodeState{
		LastSeen:  recoveryAt,
		FirstSeen: offlineStart.Add(-time.Hour),
		Stats:     metrics.NodeStats{},
	}

	_, offlineEvents, recoveredEvents = store.CollectAlertEvents(recoveryAt)
	if len(offlineEvents) != 0 {
		t.Fatalf("expected no new offline alert after recovery, got %d", len(offlineEvents))
	}
	if len(recoveredEvents) != 1 {
		t.Fatalf("expected one recovery alert, got %d", len(recoveredEvents))
	}

	got := recoveredEvents[0].OfflineSec
	want := int64(8 * time.Minute / time.Second)
	if got != want {
		t.Fatalf("expected recovery downtime %d seconds, got %d", want, got)
	}
}
