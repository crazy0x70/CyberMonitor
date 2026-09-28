package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func benchStore(nodeCount int) *Store {
	latency := func(v float64) *float64 { return &v }
	nodes := make(map[string]NodeState, nodeCount)
	profiles := make(map[string]*NodeProfile, nodeCount)
	now := time.Now()
	for i := 0; i < nodeCount; i++ {
		id := fmt.Sprintf("bench-%04d", i)
		alias := true
		nodes[id] = NodeState{
			LastSeen:  now,
			FirstSeen: now.Add(-72 * time.Hour),
			Stats: metrics.NodeStats{
				NodeID:       id,
				NodeName:     fmt.Sprintf("bench-node-%04d", i),
				Hostname:     fmt.Sprintf("bench-%04d.example.internal", i),
				PublicIPv4:   "203.0.113.10",
				OS:           "Ubuntu 24.04.3 LTS",
				Arch:         "amd64",
				StaticInfo:   true,
				DeployMode:   "binary",
				AgentVersion: "0.6.9",
				UptimeSec:    7 * 24 * 3600,
				Timestamp:    now.Unix(),
				CPU: metrics.CPUInfo{
					UsagePercent: 37.5, Load1: 1.2, Load5: 1.1, Load15: 0.9,
					Model: "AMD EPYC 7B13 64-Core Processor", Cores: 64,
				},
				Memory: metrics.MemInfo{
					Total: 137438953472, Used: 68719476736, Free: 68719476736, UsedPercent: 50,
				},
				Disk: []metrics.DiskPartition{
					{Device: "/dev/nvme0n1p1", Mountpoint: "/", Fstype: "ext4", Total: 512110190592, Used: 204884076544, Free: 307226114048, UsedPercent: 40},
					{Device: "/dev/nvme0n1p2", Mountpoint: "/var/lib/docker", Fstype: "ext4", Total: 1099511627776, Used: 824633720832, Free: 274877906944, UsedPercent: 75},
				},
				DiskType: "NVMe",
				DiskIO:   metrics.DiskIO{ReadBytes: 1 << 40, WriteBytes: 1 << 39, ReadBytesPerSec: 524288, WriteBytesPerSec: 262144},
				Network:  metrics.NetworkIO{BytesSent: 1 << 38, BytesRecv: 1 << 39, TxBytesPerSec: 1048576, RxBytesPerSec: 2097152},
				GPU: []metrics.GPUInfo{
					{Index: 0, Name: "NVIDIA RTX 4090", Vendor: "NVIDIA", DriverVersion: "560.35.03", UtilizationPercent: 12, MemoryTotal: 25769803776, MemoryUsed: 4294967296, MemoryFree: 21474836480, MemoryUsedPercent: 16.7, TemperatureC: 48, PowerW: 92},
				},
				GPUCollected: true,
				ProcessCount: 312,
				TCPConns:     148,
				UDPConns:     36,
				NetworkTests: []metrics.NetworkTestResult{
					{Name: "Cloudflare", Type: "tcp", Host: "1.1.1.1", Port: 443, LatencyMs: latency(18.4), Status: "ok", CheckedAt: now.Unix()},
					{Name: "Google DNS", Type: "icmp", Host: "8.8.8.8", LatencyMs: latency(24.1), Status: "ok", CheckedAt: now.Unix()},
				},
			},
		}
		profiles[id] = &NodeProfile{ServerID: id, Alias: fmt.Sprintf("NODE-%04d", i), Group: "默认", AlertEnabled: &alias, TestIntervalSec: 60}
	}
	return &Store{
		nodes:           nodes,
		profiles:        profiles,
		settings:        Settings{SiteTitle: "CyberMonitor", HomeTitle: "CyberMonitor", HomeSubtitle: "主机监控", Locale: "zh-CN"},
		alerted:         map[string]AlertedState{},
		offlineSessions: map[string]OfflineSessionState{},
		loginAttempts:   map[string]*loginAttempt{},
		configRefresh:   map[string]struct{}{},
		agentIngestRate: map[string]agentRateWindow{},
		deltaDigests:    map[string]uint64{},
	}
}

func BenchmarkTickSnapshot(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("nodes=%d/public", count), func(b *testing.B) {
			s := benchStore(count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				payload, err := json.Marshal(storeSnapshot(s))
				if err != nil {
					b.Fatal(err)
				}
				_ = snapshotPayloadDigest(payload)
			}
		})
		b.Run(fmt.Sprintf("nodes=%d/admin", count), func(b *testing.B) {
			s := benchStore(count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				payload, err := json.Marshal(adminStoreSnapshot(s))
				if err != nil {
					b.Fatal(err)
				}
				_ = snapshotPayloadDigest(payload)
			}
		})
	}
}
