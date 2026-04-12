package server

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestBuildAISnapshotIncludesOperationalContextAndNetworkTrendSummary(t *testing.T) {
	t.Parallel()

	now := time.Now()
	currentLatency := 23.4
	historyLatencyA := 18.0
	historyLatencyB := 24.0
	historyLatencyC := 30.0
	historyLossA := 0.0
	historyLossB := 0.0
	historyLossC := 1.0
	testCheckedAt := now.Add(-15 * time.Second).Unix()
	historyTimes := []int64{
		now.Add(-3 * time.Minute).Unix(),
		now.Add(-2 * time.Minute).Unix(),
		now.Add(-1 * time.Minute).Unix(),
	}
	testResult := metrics.NetworkTestResult{
		Name:       "tcp-443",
		Type:       "tcp",
		Host:       "1.1.1.1",
		Port:       443,
		LatencyMs:  &currentLatency,
		PacketLoss: 0,
		Status:     "ok",
		CheckedAt:  testCheckedAt,
	}

	store := &Store{
		nodes: map[string]NodeState{
			"node-1": {
				Stats: metrics.NodeStats{
					NodeID:       "node-1",
					NodeName:     "hk-edge-1",
					Hostname:     "hk-edge-1.local",
					OS:           "linux",
					Arch:         "arm64",
					AgentVersion: "1.2.3",
					UptimeSec:    7200,
					NetSpeedMbps: 950,
					CPU: metrics.CPUInfo{
						UsagePercent: 82.5,
					},
					Memory: metrics.MemInfo{
						UsedPercent: 66.6,
					},
					Disk: []metrics.DiskPartition{
						{Mountpoint: "/", UsedPercent: 71.2},
						{Mountpoint: "/data", UsedPercent: 63.4},
					},
					Network: metrics.NetworkIO{
						BytesRecv:     1024,
						BytesSent:     2048,
						RxBytesPerSec: 128.5,
						TxBytesPerSec: 256.5,
					},
					ProcessCount: 123,
					TCPConns:     45,
					UDPConns:     12,
					NetworkTests: []metrics.NetworkTestResult{testResult},
				},
				LastSeen:  now,
				FirstSeen: now.Add(-2 * time.Hour),
			},
		},
		profiles: map[string]*NodeProfile{
			"node-1": {
				ServerID:         "srv-hk-001",
				Alias:            "香港边缘节点",
				Group:            "asia/hk",
				Tags:             []string{"prod"},
				Region:           "HK",
				DiskType:         "SSD",
				NetSpeedMbps:     1000,
				ExpireAt:         now.Add(24 * time.Hour).Unix(),
				RenewIntervalSec: 86400,
				AlertEnabled:     boolPointer(true),
			},
		},
		testHistory: map[string]map[string]*TestHistoryEntry{
			"node-1": {
				buildTestHistoryKey(testResult): {
					Latency:        []*float64{&historyLatencyA, &historyLatencyB, &historyLatencyC},
					Loss:           []*float64{&historyLossA, &historyLossB, &historyLossC},
					Times:          historyTimes,
					LastAt:         historyTimes[len(historyTimes)-1],
					MinIntervalSec: 60,
					AvgIntervalSec: 60,
				},
			},
		},
	}

	snapshot := buildAISnapshot(store)
	if snapshot.GeneratedAt == "" {
		t.Fatal("expected generated_at to be populated")
	}
	if len(snapshot.Servers) != 1 {
		t.Fatalf("expected one server summary, got %d", len(snapshot.Servers))
	}

	server := snapshot.Servers[0]
	if server.AgentVersion != "1.2.3" {
		t.Fatalf("expected agent version 1.2.3, got %q", server.AgentVersion)
	}
	if server.ProcessCount != 123 || server.TCPConns != 45 || server.UDPConns != 12 {
		t.Fatalf("unexpected connection stats: process=%d tcp=%d udp=%d", server.ProcessCount, server.TCPConns, server.UDPConns)
	}
	if server.Region != "HK" {
		t.Fatalf("expected region HK, got %q", server.Region)
	}
	if server.ExpireAt == 0 || server.RenewIntervalSec != 86400 {
		t.Fatalf("unexpected lifecycle fields: expire_at=%d renew_interval=%d", server.ExpireAt, server.RenewIntervalSec)
	}
	if server.DiskType != "SSD" {
		t.Fatalf("expected disk type SSD, got %q", server.DiskType)
	}
	if server.NetSpeedMbps != 1000 {
		t.Fatalf("expected net speed override 1000 Mbps, got %v", server.NetSpeedMbps)
	}

	if len(server.NetworkTests) != 1 {
		t.Fatalf("expected one current network test summary, got %d", len(server.NetworkTests))
	}
	current := server.NetworkTests[0]
	if current.Name != "tcp-443" || current.Type != "tcp" || current.Host != "1.1.1.1" || current.Port != 443 {
		t.Fatalf("unexpected current network test summary: %+v", current)
	}
	assertFloatPointerClose(t, "current latency", current.LatencyMs, currentLatency)
	if current.CheckedAt != testCheckedAt {
		t.Fatalf("expected current checked_at %d, got %d", testCheckedAt, current.CheckedAt)
	}

	if len(server.NetworkTestTrends) != 1 {
		t.Fatalf("expected one network trend summary, got %d", len(server.NetworkTestTrends))
	}
	trend := server.NetworkTestTrends[0]
	if trend.Name != "tcp-443" || trend.Type != "tcp" || trend.Host != "1.1.1.1" || trend.Port != 443 {
		t.Fatalf("unexpected trend identity: %+v", trend)
	}
	if trend.Samples != 3 {
		t.Fatalf("expected 3 trend samples, got %d", trend.Samples)
	}
	if trend.WindowStart != historyTimes[0] || trend.WindowEnd != historyTimes[len(historyTimes)-1] {
		t.Fatalf("unexpected trend window: start=%d end=%d", trend.WindowStart, trend.WindowEnd)
	}
	if trend.LatestCheckedAt != testCheckedAt {
		t.Fatalf("expected latest checked_at %d, got %d", testCheckedAt, trend.LatestCheckedAt)
	}
	assertFloatPointerClose(t, "latest latency", trend.LatestLatencyMs, currentLatency)
	assertFloatPointerClose(t, "latest loss", trend.LatestLoss, 0)
	assertFloatPointerClose(t, "avg latency", trend.AvgLatencyMs, 24)
	assertFloatPointerClose(t, "max latency", trend.MaxLatencyMs, 30)
	assertFloatPointerClose(t, "avg loss", trend.AvgLoss, 1.0/3.0)
	if trend.MinIntervalSec != 60 {
		t.Fatalf("expected min interval 60, got %d", trend.MinIntervalSec)
	}
	if trend.AvgIntervalSec != 60 {
		t.Fatalf("expected avg interval 60, got %v", trend.AvgIntervalSec)
	}
	if trend.StatusHint != "ok" {
		t.Fatalf("expected status hint ok, got %q", trend.StatusHint)
	}
}

func TestBuildAISnapshotIncludesHistoryTrendWhenCurrentProbeMissing(t *testing.T) {
	t.Parallel()

	now := time.Now()
	loss := 100.0
	historyKey := buildTestHistoryKey(metrics.NetworkTestResult{
		Name: "icmp-core",
		Type: "icmp",
		Host: "8.8.8.8",
	})
	store := &Store{
		nodes: map[string]NodeState{
			"node-2": {
				Stats: metrics.NodeStats{
					NodeID:   "node-2",
					NodeName: "jp-core-1",
					Hostname: "jp-core-1.local",
				},
				LastSeen:  now,
				FirstSeen: now.Add(-time.Hour),
			},
		},
		profiles: map[string]*NodeProfile{
			"node-2": {
				ServerID:     "srv-jp-001",
				AlertEnabled: boolPointer(true),
			},
		},
		testHistory: map[string]map[string]*TestHistoryEntry{
			"node-2": {
				historyKey: {
					Latency:        []*float64{nil, nil},
					Loss:           []*float64{&loss, &loss},
					Times:          []int64{now.Add(-2 * time.Minute).Unix(), now.Add(-1 * time.Minute).Unix()},
					LastAt:         now.Add(-1 * time.Minute).Unix(),
					MinIntervalSec: 60,
					AvgIntervalSec: 60,
				},
			},
		},
	}

	snapshot := buildAISnapshot(store)
	if len(snapshot.Servers) != 1 {
		t.Fatalf("expected one server summary, got %d", len(snapshot.Servers))
	}
	server := snapshot.Servers[0]
	if len(server.NetworkTests) != 0 {
		t.Fatalf("expected no current network test summaries, got %d", len(server.NetworkTests))
	}
	if len(server.NetworkTestTrends) != 1 {
		t.Fatalf("expected one historical network trend summary, got %d", len(server.NetworkTestTrends))
	}
	trend := server.NetworkTestTrends[0]
	if trend.Type != "icmp" || trend.Host != "8.8.8.8" || trend.Name != "icmp-core" {
		t.Fatalf("unexpected parsed history key fields: %+v", trend)
	}
	if trend.Samples != 2 {
		t.Fatalf("expected 2 historical samples, got %d", trend.Samples)
	}
	if trend.LatestLatencyMs != nil {
		t.Fatalf("expected latest latency to be nil when history has no latency values, got %v", *trend.LatestLatencyMs)
	}
	assertFloatPointerClose(t, "latest loss", trend.LatestLoss, 100)
	if trend.StatusHint != "unreachable" {
		t.Fatalf("expected unreachable status hint, got %q", trend.StatusHint)
	}
}

func TestBuildAISnapshotIncludesOfflineSummaryFromHistoryStore(t *testing.T) {
	t.Parallel()

	store := newHistoryIntegratedStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	store.nodes["node-1"] = NodeState{
		Stats: metrics.NodeStats{
			NodeID:   "node-1",
			NodeName: "sg-edge-1",
			Hostname: "sg-edge-1.local",
		},
		LastSeen:  now,
		FirstSeen: now.Add(-90 * 24 * time.Hour),
	}
	store.profiles["node-1"] = &NodeProfile{
		ServerID:     "srv-sg-001",
		Alias:        "新加坡边缘",
		AlertEnabled: boolPointer(true),
	}
	seedOfflineHistoryStore(t, store, "node-1", now.Add(-40*24*time.Hour), 6*time.Minute)
	seedOfflineHistoryStore(t, store, "node-1", now.Add(-3*24*time.Hour), 11*time.Minute)

	snapshot := buildAISnapshot(store)
	if len(snapshot.Servers) != 1 {
		t.Fatalf("expected one server summary, got %d", len(snapshot.Servers))
	}

	server := snapshot.Servers[0]
	if server.OfflineSummary == nil {
		t.Fatal("expected offline summary to be included in AI snapshot")
	}
	if server.OfflineSummary.TotalCount != 2 {
		t.Fatalf("expected total_count 2, got %d", server.OfflineSummary.TotalCount)
	}
	if server.OfflineSummary.Last30dCount != 1 {
		t.Fatalf("expected last_30d_count 1, got %d", server.OfflineSummary.Last30dCount)
	}
	if server.OfflineSummary.LongestDurationSec != 660 {
		t.Fatalf("expected longest_duration_sec 660, got %v", server.OfflineSummary.LongestDurationSec)
	}
	if len(server.OfflineSummary.RecentSessions) != 2 {
		t.Fatalf("expected 2 recent sessions, got %d", len(server.OfflineSummary.RecentSessions))
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"offline_summary"`)) {
		t.Fatalf("expected marshaled snapshot JSON to include offline_summary, got %s", payload)
	}
}

func assertFloatPointerClose(t *testing.T, label string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: expected %v, got nil", label, want)
	}
	if math.Abs(*got-want) > 0.0001 {
		t.Fatalf("%s: expected %v, got %v", label, want, *got)
	}
}
