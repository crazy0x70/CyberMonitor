package server

import (
	"path/filepath"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

// r70 SUGGESTION-2：告警状态机首个单测锚——退避函数表测 + 恢复重试
// 计数跨「发射→删除→重建」周期的继承链（r70 修复的回归锚：旧缺陷零值
// 重建使恢复重投退化为 2s 恒定循环）。
func TestAlertRetryBackoff(t *testing.T) {
	cases := []struct {
		retryCount int
		want       time.Duration
	}{
		{0, 2 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{7, 128 * time.Second},
		{8, 256 * time.Second},
		{9, maxAlertRetryBackoff},
		{100, maxAlertRetryBackoff},
	}
	for _, tc := range cases {
		if got := alertRetryBackoff(tc.retryCount); got != tc.want {
			t.Errorf("alertRetryBackoff(%d) = %v, want %v", tc.retryCount, got, tc.want)
		}
	}
}

func newAlertTestStore(t *testing.T, online bool, alerted AlertedState) *Store {
	t.Helper()
	lastSeen := time.Now().Add(-10 * time.Minute)
	if online {
		lastSeen = time.Now()
	}
	return &Store{
		nodes: map[string]NodeState{
			"node-a": {LastSeen: lastSeen, Stats: metrics.NodeStats{NodeName: "node-a"}},
		},
		profiles: make(map[string]*NodeProfile),
		settings: Settings{AlertOfflineSec: 300},
		alerted:  map[string]AlertedState{"node-a": alerted},
		dataPath: filepath.Join(t.TempDir(), "state.json"),
	}
}

func TestRecoveryRetryCountInheritedAcrossRebuild(t *testing.T) {
	store := newAlertTestStore(t, true, AlertedState{
		OfflineSince: time.Now().Add(-10 * time.Minute),
		RetryCount:   3,
	})

	// 在线节点首次发射恢复事件：携带累计计数后删除条目。
	_, _, recovered := store.CollectAlertEvents(time.Now())
	if len(recovered) != 1 || recovered[0].RetryCount != 3 {
		t.Fatalf("recovered events: %+v", recovered)
	}

	// 模拟投递失败：重臂重建以事件计数为基递增，退避 = backoff(4)=16s。
	store.RearmAlertDelivery(recovered, false)
	store.mu.Lock()
	state, ok := store.alerted["node-a"]
	store.mu.Unlock()
	if !ok || state.RetryCount != 4 {
		t.Fatalf("rebuilt state: %+v ok=%v", state, ok)
	}
	// 无墙钟依赖的精确锚：Rearm 内 OfflineSince 与 NextRetryAt 同源于同一
	// now，差值恒等于 OfflineSec + backoff(4)=16s（慢 CI/磁盘停顿不引入 flake）。
	if got := state.NextRetryAt.Sub(state.OfflineSince); got != time.Duration(recovered[0].OfflineSec)*time.Second+16*time.Second {
		t.Fatalf("NextRetryAt-OfflineSince = %v, want OfflineSec+16s", got)
	}

	// 退避未到期不重发；到期后重发且计数继续携带（4）。
	if _, _, again := store.CollectAlertEvents(time.Now()); len(again) != 0 {
		t.Fatalf("must wait for backoff, got %+v", again)
	}
	if _, _, again := store.CollectAlertEvents(state.NextRetryAt.Add(time.Second)); len(again) != 1 || again[0].RetryCount != 4 {
		t.Fatalf("re-emit after backoff: %+v", again)
	}
}
