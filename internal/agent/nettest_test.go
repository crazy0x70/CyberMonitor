package agent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

// r66：probeTCPCandidates 全败聚合的回归锚。
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

// 新契约：轮总预算（TCP 6s = 两个完整 3s 切片）+ 每候选切片。首候选耗尽
// 整个名义预算后，次候选应得 min(3s, 轮剩余≈3s) ≈ 3s——单候选超时不饿死
// 后续候选。断言 ≥90% 防抖动。
func TestProbeTCPCandidatesPerCandidateBudget(t *testing.T) {
	var remaining []time.Duration
	probe := func(ctx context.Context, host string, _ int) (*float64, string, string) {
		if d, ok := ctx.Deadline(); ok {
			remaining = append(remaining, time.Until(d))
		}
		if host == "a.test" {
			<-ctx.Done() // 模拟 v4 候选耗尽自己的整个名义预算
		}
		return nil, "timeout", "dial tcp: i/o timeout"
	}
	_, status, errText := probeTCPCandidates(context.Background(), []string{"a.test", "b.test"}, 443, probe)
	if status != "timeout" || !strings.Contains(errText, "i/o timeout") {
		t.Fatalf("status=%q err=%q", status, errText)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(remaining))
	}
	for i, r := range remaining {
		if r < tcpTimeout*90/100 || r > tcpTimeout*110/100 {
			t.Fatalf("candidate %d budget = %v, want ≈%v", i, r, tcpTimeout)
		}
	}
}

// R06：轮总预算限制整轮时长。缩小 tcpRoundTimeout 注入，首候选耗尽轮预算后，
// 次候选生来即过期——旧实现（每候选独立预算）会给它全新的 3s。
func TestProbeTCPCandidatesRoundBudgetCapsTotal(t *testing.T) {
	orig := tcpRoundTimeout
	defer func() { tcpRoundTimeout = orig }()
	tcpRoundTimeout = 600 * time.Millisecond

	var entryRemaining []time.Duration
	var bornExpired []bool
	probe := func(ctx context.Context, _ string, _ int) (*float64, string, string) {
		if d, ok := ctx.Deadline(); ok {
			entryRemaining = append(entryRemaining, time.Until(d))
		}
		bornExpired = append(bornExpired, ctx.Err() != nil)
		<-ctx.Done() // 耗尽自己拿到的切片
		return nil, "timeout", "dial tcp: i/o timeout"
	}
	_, status, _ := probeTCPCandidates(context.Background(), []string{"a.test", "b.test"}, 443, probe)
	if status != "timeout" {
		t.Fatalf("status=%q", status)
	}
	if len(entryRemaining) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(entryRemaining))
	}
	if entryRemaining[0] > tcpRoundTimeout+100*time.Millisecond || entryRemaining[0] < tcpRoundTimeout/2 {
		t.Fatalf("first slice = %v, want ≈%v (被轮预算封顶，而非名义 3s)", entryRemaining[0], tcpRoundTimeout)
	}
	if !bornExpired[1] {
		t.Fatal("轮预算耗尽后，次候选必须生来即过期")
	}
}

// R06（ICMP 同构）：缩小 icmpRoundTimeout 注入，轮预算耗尽后剩余候选快速失败。
func TestProbeICMPCandidatesRoundBudgetCapsTotal(t *testing.T) {
	orig := icmpRoundTimeout
	defer func() { icmpRoundTimeout = orig }()
	icmpRoundTimeout = 300 * time.Millisecond

	var bornExpired []bool
	probe := func(ctx context.Context, _ string) (*float64, float64, string, string) {
		bornExpired = append(bornExpired, ctx.Err() != nil)
		<-ctx.Done()
		return nil, 100, "timeout", "ping timeout"
	}
	_, _, status, _ := probeICMPCandidates(context.Background(), []string{"a.test", "b.test"}, probe)
	if status != "timeout" {
		t.Fatalf("status=%q", status)
	}
	if len(bornExpired) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(bornExpired))
	}
	if bornExpired[0] {
		t.Fatal("首候选不应生来过期（轮预算刚开始）")
	}
	if !bornExpired[1] {
		t.Fatal("轮预算耗尽后，次候选必须生来即过期")
	}
}

// 多候选回退（行为级）：轮预算 TCP 6s = 两个完整 3s 切片，首候选耗尽
// 自己的整个名义预算后，次候选仍拿得到完整预算、被真正探测并胜出
// ——v4 超时后 v6 仍有剩余可用。
func TestProbeTCPCandidatesFallsBackAfterFullTimeout(t *testing.T) {
	probe := func(ctx context.Context, host string, _ int) (*float64, string, string) {
		if host == "a.test" {
			<-ctx.Done() // 模拟 v4 候选耗尽自己的整个预算
			return nil, "timeout", "dial tcp: i/o timeout"
		}
		v := 5.5
		return &v, "ok", ""
	}
	latency, status, errText := probeTCPCandidates(context.Background(), []string{"a.test", "b.test"}, 443, probe)
	if status != "ok" || errText != "" || latency == nil || *latency != 5.5 {
		t.Fatalf("status=%q err=%q latency=%v", status, errText, latency)
	}
}

// probeICMPCandidates 与 TCP 同构（轮总预算 10s）：首候选消耗 500ms 后，
// 次候选切片 = min(8s, 轮剩余≈9.5s) = 8s，以接近完整的名义预算胜出。
// 断言 ≥90% 防抖动。
func TestProbeICMPCandidatesPerCandidateBudget(t *testing.T) {
	var remaining []time.Duration
	probe := func(ctx context.Context, host string) (*float64, float64, string, string) {
		if d, ok := ctx.Deadline(); ok {
			remaining = append(remaining, time.Until(d))
		}
		if host == "a.test" {
			time.Sleep(500 * time.Millisecond)
			return nil, 100, "timeout", "ping timeout"
		}
		v := 7.25
		return &v, 0, "ok", ""
	}
	latency, loss, status, errText := probeICMPCandidates(context.Background(), []string{"a.test", "b.test"}, probe)
	if status != "ok" || errText != "" || latency == nil || *latency != 7.25 || loss != 0 {
		t.Fatalf("status=%q err=%q latency=%v loss=%v", status, errText, latency, loss)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(remaining))
	}
	if remaining[1] < icmpTimeout*90/100 {
		t.Fatalf("second candidate must start with a fresh budget, remaining=%v", remaining[1])
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

// R01：探测函数 panic 不得击穿进程（旧实现 recover() 不在 deferred 函数内，
// panic 直接带崩 Agent）。panic 条目返回 error 状态（PacketLoss=100），
// 其余条目正常，结果按配置顺序返回。
func TestRunNetworkTestsRecoversProbePanic(t *testing.T) {
	origTCP, origICMP := testTCP, pingHost
	defer func() { testTCP, pingHost = origTCP, origICMP }()
	testTCP = func(_ context.Context, host string, _ int) (*float64, string, string) {
		if host == "panic.test" {
			panic("tcp probe exploded")
		}
		v := 1.5
		return &v, "ok", ""
	}
	pingHost = func(_ context.Context, host string) (*float64, float64, string, string) {
		if host == "panic6.test" {
			panic("icmp probe exploded")
		}
		v := 2.5
		return &v, 0, "ok", ""
	}
	configs := []metrics.NetworkTestConfig{
		{Name: "bad-tcp", Type: "tcp", Host: "panic.test", Port: 443},
		{Name: "good-tcp", Type: "tcp", Host: "ok.test", Port: 443},
		{Name: "bad-icmp", Type: "icmp", Host: "panic6.test"},
		{Name: "good-icmp", Type: "icmp", Host: "ok6.test"},
	}
	results := RunNetworkTests(context.Background(), configs)
	if len(results) != len(configs) {
		t.Fatalf("results len = %d, want %d", len(results), len(configs))
	}
	for i, result := range results {
		if result.Name != configs[i].Name {
			t.Fatalf("results[%d].Name = %q, want %q", i, result.Name, configs[i].Name)
		}
		wantPanic, isPanic := map[string]string{
			"bad-tcp":  "tcp probe exploded",
			"bad-icmp": "icmp probe exploded",
		}[result.Name]
		if isPanic {
			if result.Status != "error" || result.PacketLoss != 100 {
				t.Errorf("%s: status=%q loss=%v, want error/100", result.Name, result.Status, result.PacketLoss)
			}
			if !strings.Contains(result.Error, "panic: "+wantPanic) {
				t.Errorf("%s: error=%q, want panic %q", result.Name, result.Error, wantPanic)
			}
			if result.CheckedAt == 0 {
				t.Errorf("%s: CheckedAt must be set", result.Name)
			}
			continue
		}
		if result.Status != "ok" || result.PacketLoss != 0 {
			t.Errorf("%s: status=%q loss=%v, want ok/0", result.Name, result.Status, result.PacketLoss)
		}
	}
}

// RunNetworkTests 的并发写模式回归锚（供 -race 实际覆盖）：
// 每 goroutine 写 results 各自下标，wg.Wait 后主协程才读。
func TestRunNetworkTestsConcurrentResultsUnderRace(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local tcp unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	configs := make([]metrics.NetworkTestConfig, 8)
	for i := range configs {
		configs[i] = metrics.NetworkTestConfig{Name: fmt.Sprintf("t%d", i), Type: "tcp", Host: "127.0.0.1", Port: port}
	}
	results := RunNetworkTests(context.Background(), configs)
	if len(results) != len(configs) {
		t.Fatalf("results len = %d, want %d", len(results), len(configs))
	}
	for i, result := range results {
		if result.Name != configs[i].Name || result.Status != "ok" || result.LatencyMs == nil {
			t.Errorf("results[%d] = %+v", i, result)
		}
	}
}
