package history

import (
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestNetworkHistoryRetentionKeepsRolling366DayWindow(t *testing.T) {
	t.Parallel()

	store := newTestNetworkStore(t)
	start := time.Unix(1_700_000_000, 0).UTC()

	for i := 0; i < 367; i++ {
		day := start.Add(time.Duration(i) * 24 * time.Hour)
		latency := 12.3 + float64(i)/10
		err := store.AppendBatch("node-a", []metrics.NetworkTestResult{{
			Type:       "tcp",
			Host:       "example.com",
			Port:       443,
			Name:       "https",
			CheckedAt:  day.Unix(),
			LatencyMs:  &latency,
			PacketLoss: 0,
			Status:     "online",
		}}, day)
		if err != nil {
			t.Fatalf("append day %d: %v", i, err)
		}
	}

	got, err := store.QueryRange("node-a", start, start.Add(367*24*time.Hour))
	if err != nil {
		t.Fatalf("query range: %v", err)
	}
	entry := got["tcp|example.com|443|https"]
	if entry == nil {
		t.Fatalf("expected tcp series to exist, got keys=%v", mapKeys(got))
	}
	if len(entry.Times) != 366 {
		t.Fatalf("expected 366 retained points, got %d", len(entry.Times))
	}
	wantFirst := start.Add(24 * time.Hour).Unix()
	if entry.Times[0] != wantFirst {
		t.Fatalf("expected first retained timestamp %d, got %d", wantFirst, entry.Times[0])
	}
	wantLast := start.Add(366 * 24 * time.Hour).Unix()
	if entry.LastAt != wantLast {
		t.Fatalf("expected last_at %d, got %d", wantLast, entry.LastAt)
	}
	if len(entry.Availability) != 366 {
		t.Fatalf("expected availability series to align with retained points, got %d", len(entry.Availability))
	}
}

func TestNetworkStoreDeleteNodeRemovesOnlyMatchingNodeSeries(t *testing.T) {
	t.Parallel()

	store := newTestNetworkStore(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	latencyA := 23.4
	latencyB := 45.6

	if err := store.AppendBatch("node-a", []metrics.NetworkTestResult{{
		Type:       "icmp",
		Host:       "1.1.1.1",
		Name:       "cloudflare",
		CheckedAt:  base.Unix(),
		LatencyMs:  &latencyA,
		PacketLoss: 0,
		Status:     "online",
	}}, base); err != nil {
		t.Fatalf("append node-a: %v", err)
	}
	if err := store.AppendBatch("node-b", []metrics.NetworkTestResult{{
		Type:       "icmp",
		Host:       "8.8.8.8",
		Name:       "google",
		CheckedAt:  base.Unix(),
		LatencyMs:  &latencyB,
		PacketLoss: 0,
		Status:     "online",
	}}, base); err != nil {
		t.Fatalf("append node-b: %v", err)
	}

	before, err := store.QueryRange("node-a", base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("query before delete: %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("expected one series for node-a before delete, got %d", len(before))
	}

	if err := store.DeleteNode("node-a"); err != nil {
		t.Fatalf("delete node-a: %v", err)
	}

	after, err := store.QueryRange("node-a", base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("query after delete: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("expected node-a history to be deleted, got %d series", len(after))
	}

	other, err := store.QueryRange("node-b", base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("query node-b: %v", err)
	}
	if len(other) != 1 {
		t.Fatalf("expected node-b history to remain, got %d series", len(other))
	}
}

func newTestNetworkStore(t *testing.T) *NetworkStore {
	t.Helper()

	store, err := OpenNetworkStore(t.TempDir())
	if err != nil {
		t.Fatalf("open network store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close network store: %v", err)
		}
	})
	return store
}

func mapKeys[M ~map[string]V, V any](input M) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	return keys
}
