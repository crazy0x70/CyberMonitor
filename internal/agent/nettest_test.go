package agent

import (
	"math"
	"testing"

	"cyber_monitor/internal/metrics"
)

func TestParseNetTestsSupportsNamedTargetsAndDefaultPorts(t *testing.T) {
	t.Parallel()

	configs := ParseNetTests("Google @ icmp:8.8.8.8, web@tcp:example.com:443, bare.example.com:8080, [2001:db8::1], tcp:example.net")
	if len(configs) != 5 {
		t.Fatalf("expected 5 configs, got %d", len(configs))
	}

	assertNetTestConfig(t, configs[0], "Google", "icmp", "8.8.8.8", 0)
	assertNetTestConfig(t, configs[1], "web", "tcp", "example.com", 443)
	assertNetTestConfig(t, configs[2], "bare.example.com", "tcp", "bare.example.com", 8080)
	assertNetTestConfig(t, configs[3], "2001:db8::1", "icmp", "2001:db8::1", 0)
	assertNetTestConfig(t, configs[4], "example.net", "tcp", "example.net", defaultTCPPort)
}

func TestParsePingOutputParsesUnixSummary(t *testing.T) {
	t.Parallel()

	output := `PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=11.001 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=11.334 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=11.367 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.001/11.234/11.367/0.164 ms`

	latency, loss, status, errText := parsePingOutput(output)
	if errText != "" {
		t.Fatalf("expected empty parse error, got %q", errText)
	}
	if status != "ok" {
		t.Fatalf("expected ok status, got %q", status)
	}
	if loss != 0 {
		t.Fatalf("expected zero packet loss, got %v", loss)
	}
	if latency == nil {
		t.Fatal("expected latency value")
	}
	if math.Abs(*latency-11.234) > 0.001 {
		t.Fatalf("expected avg latency 11.234, got %v", *latency)
	}
}

func TestParsePingOutputMarksTimeouts(t *testing.T) {
	t.Parallel()

	output := `PING 203.0.113.1 (203.0.113.1): 56 data bytes

--- 203.0.113.1 ping statistics ---
3 packets transmitted, 0 packets received, 100.0% packet loss`

	latency, loss, status, errText := parsePingOutput(output)
	if errText != "" {
		t.Fatalf("expected empty parse error, got %q", errText)
	}
	if latency != nil {
		t.Fatalf("expected no latency for timeout, got %v", *latency)
	}
	if status != "timeout" {
		t.Fatalf("expected timeout status, got %q", status)
	}
	if loss != 100 {
		t.Fatalf("expected 100 packet loss, got %v", loss)
	}
}

func assertNetTestConfig(t *testing.T, got metrics.NetworkTestConfig, name, kind, host string, port int) {
	t.Helper()

	if got.Name != name || got.Type != kind || got.Host != host || got.Port != port {
		t.Fatalf("unexpected config: got %+v want name=%q type=%q host=%q port=%d", got, name, kind, host, port)
	}
}
