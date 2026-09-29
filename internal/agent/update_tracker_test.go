package agent

import (
	"testing"
	"time"
)

// r45 挂账回归锚：更新失败重投从平坦 2min 改为连续失败指数退避
// （2min→1h 封顶）；首败窗口与旧行为一致（容忍单次网络抖动）。
func TestUpdateFailureBackoff(t *testing.T) {
	cases := []struct {
		consecutive int
		want        time.Duration
	}{
		{0, 2 * time.Minute},
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{3, 8 * time.Minute},
		{5, 32 * time.Minute},
		{6, time.Hour}, // 2*2^5=64min → 封顶 1h
		{100, time.Hour},
	}
	for _, tc := range cases {
		if got := updateFailureBackoff(tc.consecutive); got != tc.want {
			t.Errorf("updateFailureBackoff(%d) = %v, want %v", tc.consecutive, got, tc.want)
		}
	}
}

func TestTrackerFailureBackoffSequence(t *testing.T) {
	var tr remoteUpdateTracker
	base := time.Now()
	const sig = "sig"

	// 首次指令放行；第一次失败后仍是 2min 窗（与旧行为一致）。
	if !tr.beginApply(sig, base) {
		t.Fatal("first instruction must be applied")
	}
	tr.endApply(sig, base, true)
	if tr.beginApply(sig, base.Add(90*time.Second)) {
		t.Fatal("must stay suppressed inside first failure window")
	}
	t1 := base.Add(2*time.Minute + time.Second)
	if !tr.beginApply(sig, t1) {
		t.Fatal("must re-apply after first failure window")
	}

	// 第二次连续失败：4min 窗。
	tr.endApply(sig, t1, true)
	if tr.beginApply(sig, t1.Add(3*time.Minute)) {
		t.Fatal("must stay suppressed inside second failure window (4min)")
	}
	t2 := t1.Add(4*time.Minute + time.Second)
	if !tr.beginApply(sig, t2) {
		t.Fatal("must re-apply after second failure window")
	}

	// 成功复位：回到平坦 2min 窗。
	tr.endApply(sig, t2, false)
	if tr.beginApply(sig, t2.Add(90*time.Second)) {
		t.Fatal("must stay suppressed inside flat window after success")
	}
	if !tr.beginApply(sig, t2.Add(2*time.Minute+time.Second)) {
		t.Fatal("must re-apply after flat window")
	}

	// 新签名不受旧退避约束。
	tr.endApply(sig, t2, true)
	if !tr.beginApply("other-sig", t2.Add(time.Second)) {
		t.Fatal("different signature must not inherit failure backoff")
	}
}

func TestTrackerResetPreservesFailureWindow(t *testing.T) {
	var tr remoteUpdateTracker
	base := time.Now()
	const sig = "sig"
	if !tr.beginApply(sig, base) {
		t.Fatal("first instruction must be applied")
	}
	tr.endApply(sig, base, true)
	tr.endApply(sig, base, true) // 经两次失败：窗 4min（签名/时间戳由外部维持）

	// 抑制窗活跃时 reset 不清退避：窗口内的重推仍被拦截。
	tr.reset(base.Add(time.Minute))
	if tr.beginApply(sig, base.Add(3*time.Minute)) {
		t.Fatal("reset inside failure window must preserve backoff")
	}

	// 窗口过期后 reset 清理：重推按新指令处理（含失败计数复位）。
	tr.reset(base.Add(5 * time.Minute))
	if !tr.beginApply(sig, base.Add(5*time.Minute+time.Second)) {
		t.Fatal("reset after window expiry must clear backoff state")
	}
}
