package history

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

// r41 CRITICAL 回归锚：未来时间戳只钳上限（>now+5min→now），过老样本
// 原样保留（迁移历史语义依赖真实时间戳）。
func TestResolveTimestampMillisClampsFuture(t *testing.T) {
	now := time.Unix(1700000060, 0).UTC()
	nowMillis := now.UnixMilli()
	within := now.Add(4 * time.Minute)
	old := now.Add(-24 * time.Hour)
	cases := []struct {
		name      string
		checkedAt int64
		want      int64
	}{
		{"zero", 0, nowMillis},
		{"negative", -5, nowMillis},
		{"overflow guard", math.MaxInt64, nowMillis},
		{"far future", now.Add(time.Hour).Unix(), nowMillis},
		{"within skew", within.Unix(), within.UnixMilli()},
		{"past preserved", old.Unix(), old.UnixMilli()},
	}
	for _, tc := range cases {
		if got := resolveTimestampMillis(tc.checkedAt, now); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

// r41 CRITICAL 行为面：单节点远未来样本若未被钳制，会把 head maxt 抬
// 到未来，此后其它节点的实时样本全部命中 too-old 被静默丢弃（全网
// history 瘫痪）。钳制生效时两节点样本都落在 now。
func TestAppendFutureTimestampClampedForAllNodes(t *testing.T) {
	dir := t.TempDir()
	m, err := OpenManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	base := metrics.NetworkTestResult{Type: "icmp", Name: "probe", LatencyMs: NormalizeFloat(12), PacketLoss: 0, Status: "online"}

	future := base
	future.Host = "future.test"
	future.CheckedAt = now.Add(365 * 24 * time.Hour).Unix()
	if err := m.AppendNetworkBatch("node-future", []metrics.NetworkTestResult{future}, now); err != nil {
		t.Fatal(err)
	}
	normal := base
	normal.Host = "normal.test"
	normal.CheckedAt = now.Unix()
	if err := m.AppendNetworkBatch("node-normal", []metrics.NetworkTestResult{normal}, now); err != nil {
		t.Fatal(err)
	}

	assertSingleTs := func(node, host string) {
		t.Helper()
		got, err := m.NetworkStore().QueryRangeRaw(context.Background(), node, now.Add(-time.Hour), now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		entry := got[BuildNetworkTestKey(metrics.NetworkTestResult{Type: "icmp", Host: host, Name: "probe"})]
		if len(got) != 1 || entry == nil || len(entry.Times) != 1 || entry.Times[0] != now.Unix() {
			t.Fatalf("%s/%s: %+v", node, host, got)
		}
	}
	assertSingleTs("node-future", "future.test")
	assertSingleTs("node-normal", "normal.test")
}

// r41 MAJOR-1 回归锚：legacy 迁移必须全局升序单事务——2 节点 × 2 序列
// × 3 天跨度（>24h OOO 窗口）交错时全部合法样本存活；未来/零值时间戳
// 精确跳过；备份字节等于源文件；重复迁移幂等。
func TestMigrateLegacyMultiNodeSpansAndInvalidTimestamps(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNetworkStore(filepath.Join(dir, "network"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Unix(1700000060, 0).UTC()
	d3, d2h12, d2, d1 := now.Add(-72*time.Hour).Unix(), now.Add(-60*time.Hour).Unix(), now.Add(-48*time.Hour).Unix(), now.Add(-24*time.Hour).Unix()
	m10, m5, m3, fut := now.Add(-10*time.Minute).Unix(), now.Add(-5*time.Minute).Unix(), now.Add(-3*time.Minute).Unix(), now.Add(time.Hour).Unix()

	payload := []byte(fmt.Sprintf(
		`{"version":1,"nodes":{"node-a":{"icmp|a.test|0|n1":{"times":[%d,%d,%d],"latency":[10,11,12],"loss":[0,0,0]},"tcp|b.test|443|n2":{"times":[%d,%d],"latency":[20,21],"loss":[0,0]}},"node-b":{"icmp|c.test|0|n3":{"times":[%d,%d],"latency":[30,31],"loss":[0,0]},"tcp|d.test|443|n4":{"times":[0,%d],"latency":[40,41],"loss":[0,0]}}}}`,
		d3, d1, fut, d2, m10, d2h12, m5, m3))
	path := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateLegacyJSONIfNeeded(path, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.LegacyFound {
		t.Fatal("legacy missing")
	}

	expect := map[string]map[string][]int64{
		"node-a": {"icmp|a.test|0|n1": {d3, d1}, "tcp|b.test|443|n2": {d2, m10}},
		"node-b": {"icmp|c.test|0|n3": {d2h12, m5}, "tcp|d.test|443|n4": {m3}},
	}
	queryAll := func() map[string]map[string][]int64 {
		t.Helper()
		out := map[string]map[string][]int64{}
		for node := range expect {
			got, err := store.QueryRangeRaw(context.Background(), node, now.Add(-96*time.Hour), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			out[node] = map[string][]int64{}
			for key, entry := range got {
				out[node][key] = entry.Times
			}
		}
		return out
	}
	if got := queryAll(); !reflect.DeepEqual(expect, got) {
		t.Fatalf("migrated times: want %+v got %+v", expect, got)
	}

	if _, err := MigrateLegacyJSONIfNeeded(path, store, now); err != nil {
		t.Fatal(err)
	}
	if got := queryAll(); !reflect.DeepEqual(expect, got) {
		t.Fatalf("replay changed data: %+v", got)
	}

	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != string(payload) {
		t.Fatal("backup changed")
	}
}

// r48 MAJOR 回归锚：查询侧序列基数 cap——501 个不同序列的查询只物化
// maxSeriesPerQuery 个（失控基数的内存/响应体敞口在消费端封顶）。
func TestQuerySeriesCapLimitsMaterialization(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNetworkStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	samples := make([]metrics.NetworkTestResult, 0, maxSeriesPerQuery+1)
	for i := 0; i <= maxSeriesPerQuery; i++ {
		samples = append(samples, metrics.NetworkTestResult{
			Type: "icmp", Host: fmt.Sprintf("h%03d.test", i), Name: "probe",
			CheckedAt: now.Unix(), LatencyMs: NormalizeFloat(12), PacketLoss: 0, Status: "online",
		})
	}
	if err := store.AppendBatch("cap-node", samples, now); err != nil {
		t.Fatal(err)
	}
	got, err := store.QueryPublicRange(context.Background(), "cap-node", now.Add(-time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxSeriesPerQuery {
		t.Fatalf("got %d series, want cap %d", len(got), maxSeriesPerQuery)
	}
}

func TestDownsampleBucketMillis(t *testing.T) {
	cases := []struct {
		mint, maxt int64
		want       int64
	}{
		{0, 0, 0},
		{1_000_000, 2_000_000, 0}, // 1000s 窗口 → 桶 1000ms ≤1s → raw
		{0, 1_001_000, 2000},      // 1001s → 桶 1001ms → 整秒对齐 2000
		{0, 3_600_000, 4000},      // 1h → 3600ms → 4000
		{0, 604_800_000, 605_000}, // 7d → 604800ms → 605000
	}
	for _, tc := range cases {
		if got := downsampleBucketMillis(tc.mint, tc.maxt); got != tc.want {
			t.Errorf("window [%d,%d]: got %d, want %d", tc.mint, tc.maxt, got, tc.want)
		}
	}
}

// bucketed 主路径（此前整体零覆盖）：同桶多样本收敛为桶起点均值，
// 跨桶样本独立成点；raw 查询保留原始采样。
func TestBucketedPublicQueryAggregates(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNetworkStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	base := time.Unix(1_700_000_000, 0).UTC() // % 4 == 0
	sampleAt := func(ts int64, latency float64) metrics.NetworkTestResult {
		return metrics.NetworkTestResult{
			Type: "icmp", Host: "bucket.test", Name: "probe",
			CheckedAt: ts, LatencyMs: NormalizeFloat(latency), PacketLoss: 0, Status: "online",
		}
	}
	samples := []metrics.NetworkTestResult{
		sampleAt(base.Unix(), 10),
		sampleAt(base.Add(1*time.Second).Unix(), 20),
		sampleAt(base.Add(2*time.Second).Unix(), 30),
		sampleAt(base.Add(6*time.Second).Unix(), 40),
	}
	if err := store.AppendBatch("bucket-node", samples, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	// ±30min 窗口 → 3600s → 4s 桶：ts 0/1/2 落桶 base，ts 6 落桶 base+4。
	bucketed, err := store.QueryPublicRange(context.Background(), "bucket-node", base.Add(-30*time.Minute), base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	key := BuildNetworkTestKey(samples[0])
	entry := bucketed[key]
	if len(bucketed) != 1 || entry == nil {
		t.Fatalf("bucketed: %+v", bucketed)
	}
	wantTimes := []int64{base.Unix(), base.Add(4 * time.Second).Unix()}
	if !reflect.DeepEqual(entry.Times, wantTimes) {
		t.Fatalf("bucket times: %+v want %+v", entry.Times, wantTimes)
	}
	if entry.Latency[0] == nil || *entry.Latency[0] != 20 || entry.Latency[1] == nil || *entry.Latency[1] != 40 {
		t.Fatalf("bucket means: %+v", entry.Latency)
	}
	if entry.Loss[0] == nil || *entry.Loss[0] != 0 {
		t.Fatalf("bucket loss: %+v", entry.Loss)
	}
	for _, v := range entry.Availability {
		if v != nil {
			t.Fatalf("public bucketed query must exclude availability: %+v", entry.Availability)
		}
	}

	raw, err := store.QueryRangeRaw(context.Background(), "bucket-node", base.Add(-time.Minute), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rawEntry := raw[key]
	wantRaw := []int64{base.Unix(), base.Add(1 * time.Second).Unix(), base.Add(2 * time.Second).Unix(), base.Add(6 * time.Second).Unix()}
	if rawEntry == nil || !reflect.DeepEqual(rawEntry.Times, wantRaw) {
		t.Fatalf("raw times: %+v want %+v", rawEntry, wantRaw)
	}
}

// r41 MAJOR-2 回归锚：latestSeriesTime 去重基线有界——超限先剪陈旧
// 条目，仍超限拒收新键，既有键始终可更新（失控序列基数不耗尽内存）。
func TestRecordLatestSeriesTimeCapPrunesAndRejects(t *testing.T) {
	store, err := OpenNetworkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now()
	stale := now.Add(-100 * time.Hour).UnixMilli() // 远早于 2×乱序窗口 cutoff
	fresh := now.Add(-time.Hour).UnixMilli()

	// 场景 1：满表 + 陈旧条目 → 剪枝后新键可入。
	store.latestSeriesTime = make(map[string]int64, maxLatestSeriesTimeEntries)
	for i := 0; i < maxLatestSeriesTimeEntries; i++ {
		ts := fresh
		if i%2 == 0 {
			ts = stale
		}
		store.latestSeriesTime[fmt.Sprintf("k-%d", i)] = ts
	}
	store.recordLatestSeriesTime(map[string]int64{"new-key": fresh})
	if _, ok := store.latestSeriesTime["new-key"]; !ok {
		t.Fatal("new key must be recorded after pruning stale entries")
	}
	if got := len(store.latestSeriesTime); got != maxLatestSeriesTimeEntries/2+1 {
		t.Fatalf("pruned map size = %d, want exactly fresh half + new key", got)
	}

	// 场景 2：满表全新鲜 → 拒收新键，既有键仍更新。
	store.latestSeriesTime = make(map[string]int64, maxLatestSeriesTimeEntries)
	for i := 0; i < maxLatestSeriesTimeEntries; i++ {
		store.latestSeriesTime[fmt.Sprintf("k-%d", i)] = fresh
	}
	store.recordLatestSeriesTime(map[string]int64{"rejected": fresh})
	if _, ok := store.latestSeriesTime["rejected"]; ok {
		t.Fatal("new key must be rejected when cap holds after pruning")
	}
	newer := fresh + 60000
	store.recordLatestSeriesTime(map[string]int64{"k-0": newer})
	if got := store.latestSeriesTime["k-0"]; got != newer {
		t.Fatalf("existing key update: got %d want %d", got, newer)
	}
}
