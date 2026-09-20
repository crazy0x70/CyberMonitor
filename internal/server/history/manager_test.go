package history

import (
	"context"
	"reflect"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

// Uses real TSDB directories and WAL replay, rather than replacing store APIs.
func TestManagerLifecycle(t *testing.T) {
	dir := t.TempDir()
	var m *Manager
	open := func(t *testing.T) {
		t.Helper()
		var err error
		m, err = OpenManager(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	closeManager := func(t *testing.T) {
		t.Helper()
		if m != nil {
			err := m.Close()
			m = nil
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		if m != nil {
			if err := m.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	open(t)
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	sample := metrics.NetworkTestResult{Type: "icmp", Host: "example.test", Name: "probe", CheckedAt: now.Unix(), LatencyMs: NormalizeFloat(12), PacketLoss: 0, Status: "online"}
	key := BuildNetworkTestKey(sample)
	appendNode := func(t *testing.T, node string, at time.Time) {
		t.Helper()
		s := sample
		s.CheckedAt = at.Unix()
		if err := m.AppendNetworkBatch(node, []metrics.NetworkTestResult{s}, now); err != nil {
			t.Fatal(err)
		}
		if err := m.AppendOfflineEvent(node, at, 10*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	assertNode := func(t *testing.T, node string, times []int64, offlineCount int) {
		t.Helper()
		got, err := m.NetworkStore().QueryRangeRaw(context.Background(), node, now.Add(-time.Hour), now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if len(times) == 0 {
			if len(got) != 0 {
				t.Fatalf("%s network remains: %+v", node, got)
			}
		} else {
			e := got[key]
			if len(got) != 1 || e == nil {
				t.Fatalf("%s network: %+v", node, got)
			}
			if !reflect.DeepEqual(e.Times, times) || e.LastAt != times[len(times)-1] {
				t.Fatalf("%s times: %+v", node, e)
			}
			for i := range times {
				if e.Latency[i] == nil || *e.Latency[i] != 12 || e.Loss[i] == nil || *e.Loss[i] != 0 || e.Availability[i] == nil || *e.Availability[i] != 1 {
					t.Fatalf("%s values: %+v", node, e)
				}
			}
		}
		insight, err := m.OfflineStore().QueryInsights(context.Background(), node, now.Add(time.Minute), 10)
		if err != nil {
			t.Fatal(err)
		}
		if insight.TotalCount != offlineCount || insight.Last30dCount != offlineCount || len(insight.RecentSessions) != offlineCount {
			t.Fatalf("%s offline: %+v", node, insight)
		}
		if offlineCount > 0 && (insight.AvgDurationSec != 10 || insight.LongestDurationSec != 10) {
			t.Fatalf("%s durations: %+v", node, insight)
		}
		has, err := m.HasNodeHistory(node)
		if err != nil || has != (len(times) > 0 || offlineCount > 0) {
			t.Fatalf("%s has=%v err=%v", node, has, err)
		}
	}
	for _, node := range []string{"node|a%7C", "node-b"} {
		appendNode(t, node, now)
		assertNode(t, node, []int64{now.Unix()}, 1)
	}
	t.Run("public_query_and_missing_session", func(t *testing.T) {
		got, err := m.NetworkStore().QueryPublicRange(context.Background(), "node-b", now.Add(-time.Second), now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		e := got[key]
		if len(got) != 1 || e == nil || !reflect.DeepEqual(e.Times, []int64{now.Unix()}) || e.Latency[0] == nil || *e.Latency[0] != 12 || e.Availability[0] != nil {
			t.Fatalf("public query: %+v", got)
		}
		got, err = m.NetworkStore().QueryPublicRange(context.Background(), "node-b", now.Add(time.Second), now.Add(-time.Second))
		if err != nil || len(got) != 0 {
			t.Fatalf("reversed range: %+v err=%v", got, err)
		}
		found, err := m.HasOfflineEventForSession("node-b", now.Add(-20*time.Second))
		if err != nil || found {
			t.Fatalf("unexpected session=%v err=%v", found, err)
		}
	})

	t.Run("duplicate_and_restart", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			appendNode(t, "node|a%7C", now)
			conflicting := sample
			conflicting.LatencyMs = NormalizeFloat(999)
			if err := m.AppendNetworkBatch("node|a%7C", []metrics.NetworkTestResult{conflicting}, now); err != nil {
				t.Fatal(err)
			}
			assertNode(t, "node|a%7C", []int64{now.Unix()}, 1)
			found, err := m.HasOfflineEventForSession("node|a%7C", now.Add(-10*time.Second))
			if err != nil || !found {
				t.Fatalf("session=%v err=%v", found, err)
			}
			closeManager(t)
			open(t)
		}
	})
	t.Run("delete_isolated_and_persistent", func(t *testing.T) {
		if err := m.DeleteNode("node|a%7C"); err != nil {
			t.Fatal(err)
		}
		assertNode(t, "node|a%7C", nil, 0)
		assertNode(t, "node-b", []int64{now.Unix()}, 1)
		closeManager(t)
		open(t)
		assertNode(t, "node|a%7C", nil, 0)
		assertNode(t, "node-b", []int64{now.Unix()}, 1)
		appendNode(t, "node|a%7C", now.Add(time.Second))
		assertNode(t, "node|a%7C", []int64{now.Add(time.Second).Unix()}, 1)
	})
	t.Run("clear_persistent_and_reusable", func(t *testing.T) {
		if err := m.ClearNodes(); err != nil {
			t.Fatal(err)
		}
		for _, node := range []string{"node|a%7C", "node-b"} {
			assertNode(t, node, nil, 0)
		}
		closeManager(t)
		open(t)
		for _, node := range []string{"node|a%7C", "node-b"} {
			assertNode(t, node, nil, 0)
		}
		appendNode(t, "node-b", now.Add(2*time.Second))
		assertNode(t, "node-b", []int64{now.Add(2 * time.Second).Unix()}, 1)
	})
}
