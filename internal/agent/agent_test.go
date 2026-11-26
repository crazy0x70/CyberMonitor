package agent

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

type fakeControlPlane struct {
	mu            sync.Mutex
	reportedStats []metrics.NodeStats
	updateReports []fakeUpdateReport
}

type fakeUpdateReport struct {
	nodeID, token, updateID, state, version, message string
}

func (f *fakeControlPlane) RegisterNodeToken(context.Context, string, string) (string, error) {
	return "", nil
}

func (f *fakeControlPlane) FetchConfig(context.Context, string, string) (RemoteConfig, error) {
	return RemoteConfig{}, nil
}

func (f *fakeControlPlane) ReportStats(_ context.Context, stats metrics.NodeStats, _ string) (bool, error) {
	f.mu.Lock()
	f.reportedStats = append(f.reportedStats, stats)
	f.mu.Unlock()
	return false, nil
}

func (f *fakeControlPlane) ReportUpdate(_ context.Context, nodeID, token, updateID, state, version, message string) error {
	f.mu.Lock()
	f.updateReports = append(f.updateReports, fakeUpdateReport{
		nodeID: nodeID, token: token, updateID: updateID, state: state, version: version, message: message,
	})
	f.mu.Unlock()
	return nil
}

func (f *fakeControlPlane) Close() error { return nil }

func TestParsePingOutputPartialLossAndTimeoutHostname(t *testing.T) {
	t.Run("macOS partial loss with Request timeout line", func(t *testing.T) {
		output := `PING 1.1.1.1 (1.1.1.1): 56 data bytes
Request timeout for icmp_seq 0
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.0 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.0 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 10.0/12.0/14.0/2.0 ms`
		lat, loss, status, _ := parsePingOutput(output)
		if status != "ok" {
			t.Fatalf("expected status=ok for partial loss, got %q (loss=%.1f)", status, loss)
		}
		if math.Abs(loss-33.3) > 0.1 {
			t.Fatalf("expected loss≈33.3, got %.2f", loss)
		}
		if lat == nil || math.Abs(*lat-12.0) > 0.01 {
			t.Fatalf("expected latency=12.0, got %v", lat)
		}
	})

	t.Run("hostname containing timeout with 0% loss", func(t *testing.T) {
		output := `PING timeout-check.example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=15.0 ms

--- timeout-check.example.com ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 14.0/15.0/16.0/1.0 ms`
		lat, loss, status, _ := parsePingOutput(output)
		if status != "ok" || loss != 0 || lat == nil {
			t.Fatalf("expected ok/0%% loss for timeout hostname, got status=%q loss=%.1f lat=%v", status, loss, lat)
		}
	})

	t.Run("full 100% packet loss", func(t *testing.T) {
		output := `3 packets transmitted, 0 packets received, 100.0% packet loss`
		_, loss, status, _ := parsePingOutput(output)
		if status != "timeout" || loss != 100 {
			t.Fatalf("expected timeout/100, got status=%q loss=%.1f", status, loss)
		}
	})

	t.Run("unparsed timeout text without stats", func(t *testing.T) {
		_, loss, status, _ := parsePingOutput("Request timed out.\nRequest timed out.")
		if status != "timeout" || loss != 100 {
			t.Fatalf("expected timeout/100, got status=%q loss=%.1f", status, loss)
		}
	})
}

func TestCollectAndReportDoesNotBlockOnSlowProbe(t *testing.T) {
	origTestTCP := testTCP
	defer func() { testTCP = origTestTCP }()

	probeStarted := make(chan struct{}, 1)
	releaseProbe := make(chan struct{})
	testTCP = func(ctx context.Context, host string, port int) (*float64, string, string) {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		select {
		case <-releaseProbe:
			v := 8.5
			return &v, "ok", ""
		case <-ctx.Done():
			return nil, "timeout", ctx.Err().Error()
		}
	}

	transport := &fakeControlPlane{}
	cfg := Config{
		ServerURL: "https://monitor.example.com",
		NodeID:    "node-1",
		NodeName:  "node-1",
		NetTests: []metrics.NetworkTestConfig{
			{Name: "SlowTCP", Type: "tcp", Host: "1.1.1.1", Port: 443, IntervalSec: 5},
		},
	}
	runner := newAgentRunner(cfg, transport, metrics.NewCollector("node-1", "node-1", "", nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First tick triggers async probe and must return immediately without waiting for releaseProbe.
	start := time.Now()
	runner.collectAndReport(ctx)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("collectAndReport unexpectedly blocked on slow probe: %v", elapsed)
	}

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected background probe sweep to start")
	}

	// Release probe and wait for sweep completion.
	close(releaseProbe)
	runner.probeWG.Wait()

	// Next tick attaches the completed probe snapshot.
	runner.collectAndReport(ctx)
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.reportedStats) < 2 {
		t.Fatalf("expected at least 2 reported stats, got %d", len(transport.reportedStats))
	}
	second := transport.reportedStats[len(transport.reportedStats)-1]
	if !second.NetworkTestsChanged || len(second.NetworkTests) != 1 || second.NetworkTests[0].Status != "ok" {
		t.Fatalf("expected completed probe results delivered on next tick, got changed=%v tests=%+v", second.NetworkTestsChanged, second.NetworkTests)
	}
}

func TestApplyRemoteConfigReportsFailedWhenTokenNotDurable(t *testing.T) {
	transport := &fakeControlPlane{}
	cfg := Config{
		ServerURL:    "https://monitor.example.com",
		NodeID:       "node-1",
		AgentVersion: "v0.8.6",
		TokenFile:    "/nonexistent/token",
	}
	runner := newAgentRunner(cfg, transport, metrics.NewCollector("node-1", "node-1", "", nil))
	runner.agentTokenDurable = false

	remote := RemoteConfig{
		Update: &RemoteUpdateInstruction{
			ID:      "upd-1",
			Version: "v0.8.7",
		},
	}
	runner.applyRemoteConfig(context.Background(), remote)
	// Second identical call should be deduplicated by skipDuplicateReport.
	runner.applyRemoteConfig(context.Background(), remote)

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.updateReports) != 1 {
		t.Fatalf("expected exactly 1 failed update report, got %d", len(transport.updateReports))
	}
	if got := transport.updateReports[0]; got.state != "failed" || got.updateID != "upd-1" || got.message == "" {
		t.Fatalf("unexpected failed update report: %+v", got)
	}
}
