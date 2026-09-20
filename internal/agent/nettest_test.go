package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

// r66：probeTCPCandidates 全败聚合 + 候选共享单项总预算的回归锚。
// 经注入 probe 直测，零网络依赖。
func TestProbeTCPCandidatesAggregatesFailures(t *testing.T) {
	failProbe := func(_ context.Context, host string, _ int) (*float64, string, string) {
		return nil, "error", "dial " + host + " failed"
	}
	cases := []struct {
		name    string
		hosts   []string
		wantIn  string
		wantOut string // 必须不含
	}{
		{"single failure keeps bare error", []string{"a.test"}, "dial a.test failed", "a.test: "},
		{"two failures joined", []string{"a.test", "b.test"}, "a.test: dial a.test failed; b.test: dial b.test failed", "另有"},
		{"exactly three without overflow suffix", []string{"a.test", "b.test", "c.test"}, "c.test: dial c.test failed", "另有"},
		{"four failures with overflow count", []string{"a.test", "b.test", "c.test", "d.test"}, "另有 1 个地址失败", "d.test:"},
		{"five failures with overflow count", []string{"a.test", "b.test", "c.test", "d.test", "e.test"}, "另有 2 个地址失败", "e.test:"},
	}
	for _, tc := range cases {
		latency, status, errText := probeTCPCandidates(context.Background(), tc.hosts, 443, failProbe)
		if status != "error" || latency != nil {
			t.Errorf("%s: status=%q latency=%v", tc.name, status, latency)
			continue
		}
		if !strings.Contains(errText, tc.wantIn) {
			t.Errorf("%s: errText=%q missing %q", tc.name, errText, tc.wantIn)
		}
		if tc.wantOut != "" && strings.Contains(errText, tc.wantOut) {
			t.Errorf("%s: errText=%q must not contain %q", tc.name, errText, tc.wantOut)
		}
	}
}

func TestProbeTCPCandidatesReturnsFirstSuccess(t *testing.T) {
	calls := 0
	probe := func(_ context.Context, host string, _ int) (*float64, string, string) {
		calls++
		if host == "b.test" {
			v := 5.5
			return &v, "ok", ""
		}
		return nil, "error", "dial " + host + " failed"
	}
	latency, status, errText := probeTCPCandidates(context.Background(), []string{"a.test", "b.test", "c.test"}, 443, probe)
	if status != "ok" || errText != "" || latency == nil || *latency != 5.5 || calls != 2 {
		t.Fatalf("status=%q err=%q latency=%v calls=%d", status, errText, latency, calls)
	}
}

// 候选共享同一个总预算 deadline（与 probeICMPCandidates 同构）：多候选
// 逐一尝试的最坏耗时不超过单地址路径。
func TestProbeTCPCandidatesSharesSingleBudget(t *testing.T) {
	var deadlines []time.Time
	probe := func(ctx context.Context, _ string, _ int) (*float64, string, string) {
		if d, ok := ctx.Deadline(); ok {
			deadlines = append(deadlines, d)
		}
		return nil, "timeout", "dial tcp: i/o timeout"
	}
	_, status, errText := probeTCPCandidates(context.Background(), []string{"a.test", "b.test", "c.test"}, 443, probe)
	if status != "timeout" || !strings.Contains(errText, "i/o timeout") {
		t.Fatalf("status=%q err=%q", status, errText)
	}
	if len(deadlines) != 3 {
		t.Fatalf("expected 3 probes, got %d", len(deadlines))
	}
	if !deadlines[0].Equal(deadlines[1]) || !deadlines[1].Equal(deadlines[2]) {
		t.Fatal("candidates must share one total budget deadline")
	}
	if remain := time.Until(deadlines[0]); remain <= 0 || remain > tcpTimeout {
		t.Fatalf("shared budget deadline out of range: %v", remain)
	}
}

func TestProbeTCPCandidatesEmptyHosts(t *testing.T) {
	probe := func(context.Context, string, int) (*float64, string, string) {
		t.Fatal("probe must not be called for empty hosts")
		return nil, "", ""
	}
	latency, status, errText := probeTCPCandidates(context.Background(), nil, 443, probe)
	if latency != nil || status != "" || errText != "" {
		t.Fatalf("empty hosts: latency=%v status=%q err=%q", latency, status, errText)
	}
}

// r68：调度必须按真实完成时刻（单调时钟）而非上报墙钟——旧实现把
// lastRun 存为 time.Unix(CheckedAt)，时钟回拨后 findDueTests 的 Sub 为负，
// 全部缓存探测停摆到墙钟追回为止。
func TestFindDueTestsSchedulesByRealElapsedNotWallClock(t *testing.T) {
	configs := []metrics.NetworkTestConfig{{Type: "tcp", Host: "a.test", Port: 443}}
	keys := []string{"k"}
	cache := map[string]cachedTest{}
	// CheckedAt 墙钟偏到 1 小时之后（模拟回拨前写入的陈旧墙钟）：
	// 刚完成的探测不得立即到期，且真实 interval 流逝后必须到期。
	updateCacheWithResults(cache, keys, []metrics.NetworkTestResult{{CheckedAt: time.Now().Add(time.Hour).Unix(), Status: "ok"}})
	if due, _, _ := findDueTests(configs, keys, cache, time.Now(), 50*time.Millisecond); len(due) != 0 {
		t.Fatal("just-completed test must not be immediately due")
	}
	// 2.4× 裕度：极端过载 CI 上 not-due 断言与 due 断言都不受调度延迟影响。
	time.Sleep(120 * time.Millisecond)
	if due, _, _ := findDueTests(configs, keys, cache, time.Now(), 50*time.Millisecond); len(due) != 1 {
		t.Fatal("test must become due after the real interval despite wall-clock skew")
	}
}
