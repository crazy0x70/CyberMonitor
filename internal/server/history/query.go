package history

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

const (
	networkLatencyMetric      = "cm_network_test_latency_ms"
	networkLossMetric         = "cm_network_test_packet_loss"
	networkAvailabilityMetric = "cm_network_test_availability"

	// 站长要求图表可回看 1 年（前端已提供 range=1y）。长范围查询由服务端
	// 按窗口降采样（见 downsampleBucketMillis），单次查询的内存与 payload
	// 始终有界（每序列 ≤ ~1000 点），因此 366 天保留本身不构成风险。
	networkRetentionDays    = 366
	networkRetention        = networkRetentionDays * 24 * time.Hour
	networkOutOfOrderWindow = 24 * time.Hour

	// TSDB 磁盘容量上限：超出后按保留策略删除最旧块，为页缓存设界。
	// 该值是病态增长的保护上限，按中等规模节点群 ~1 年的体量估算。
	networkMaxBytes = 2 << 30
	offlineMaxBytes = 256 << 20
)

// 每条序列在单次查询中最多物化的点数目标。桶大小由此推导：
// bucketMillis = ceil(窗口 / maxPointsPerSeries)。
const maxPointsPerSeries = 1000

// downsampleBucketMillis 计算某个 [mint, maxt] 查询窗口（Unix 毫秒）使用的
// 聚合桶大小。返回 0 表示保留原始采样（短窗口走原有 raw 路径）。
//
// 目标：每序列最多输出 ~1000 个点。1 年窗口在 5s 采集间隔下约 630 万个
// 原始样本/序列——不降采样就是内存炸弹与不可传输的 payload。向上取整
// 保证桶数永远不超过 ~1000；桶再对齐到整秒（序列键以 Unix 秒存储，
// 桶起点需满足 ts - ts%bucketSeconds 的对齐语义）。
func downsampleBucketMillis(mint, maxt int64) int64 {
	windowMillis := maxt - mint
	if windowMillis <= 0 {
		return 0
	}
	bucketMillis := (windowMillis + maxPointsPerSeries - 1) / maxPointsPerSeries
	if bucketMillis <= 1000 {
		// 桶 ≤ 1s 时没有可聚合的余量，直接走 raw 路径。
		return 0
	}
	return ((bucketMillis + 999) / 1000) * 1000
}

type NetworkHistoryEntry struct {
	Latency        []*float64 `json:"latency"`
	Loss           []*float64 `json:"loss"`
	Availability   []*float64 `json:"availability"`
	Times          []int64    `json:"times"`
	LastAt         int64      `json:"last_at"`
	MinIntervalSec int64      `json:"min_interval_sec,omitempty"`
	AvgIntervalSec float64    `json:"avg_interval_sec,omitempty"`
}

type networkTestIdentity struct {
	Type string
	Host string
	Port int
	Name string
}

// seriesAccumulator 聚合单个网络测试身份在一次查询窗口内的全部采样。
//
// bucketMillis > 0 时，原始采样被折进固定时长的桶（输出均值），长窗口
// （如 1 年 @5s 间隔 ≈ 630 万样本/序列）坍缩为每序列 ≤ ~1000 个点，
// 避免内存炸弹与不可传输的 payload；bucketMillis == 0 时保留原始采样
// （短窗口行为与降采样改造前完全一致）。
type seriesAccumulator struct {
	identity     networkTestIdentity
	bucketMillis int64
	latency      *metricSeries
	loss         *metricSeries
	availability *metricSeries
}

// metricSeries 承载序列中的一个指标（latency/loss/availability）。
//
//   - raw 模式（bucketSeconds == 0）：键为采样秒（Unix 秒，毫秒截断），
//     同秒多采样后者覆盖前者，非有限值存为 nil 指针（时间点保留、无值），
//     与降采样改造前的行为一致。
//   - 桶模式（bucketSeconds > 0）：键为桶起点秒（ts - ts%bucketSeconds），
//     桶内维护 sum+count，输出 sum/count（均值）。三个指标独立聚合成
//     各自的桶表；条目的 Times 取桶键的有序并集（与改造前取原始键并集
//     的对齐语义相同），某指标在某桶缺采样则该点为 nil 指针（同改造前）。
type metricSeries struct {
	bucketSeconds int64
	raw           map[int64]*float64
	buckets       map[int64]*bucketAggregate
}

type bucketAggregate struct {
	sum   float64
	count int64
}

func newMetricSeries(bucketMillis int64) *metricSeries {
	var bucketSeconds int64
	if bucketMillis > 0 {
		bucketSeconds = bucketMillis / 1000
	}
	return &metricSeries{
		bucketSeconds: bucketSeconds,
		raw:           make(map[int64]*float64),
		buckets:       make(map[int64]*bucketAggregate),
	}
}

// observe 折入一个原始采样。tsSeconds 为 Unix 秒；value 可能为非有限值。
//
// 桶模式下均值语义：latency/loss 是采样均值；availability（每次测试
// 0/1）的均值即该桶的在线率（uptime ratio）。非有限采样无法贡献均值，
// 直接跳过。
func (m *metricSeries) observe(tsSeconds int64, value float64) {
	if m.bucketSeconds <= 0 {
		m.raw[tsSeconds] = NormalizeFloat(value)
		return
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	key := tsSeconds - tsSeconds%m.bucketSeconds
	agg := m.buckets[key]
	if agg == nil {
		agg = &bucketAggregate{}
		m.buckets[key] = agg
	}
	agg.sum += value
	agg.count++
}

// valueAt 返回键 ts（raw 秒或桶起点秒）上的输出值；该指标在 ts 无采样
// 时返回 nil。
func (m *metricSeries) valueAt(ts int64) *float64 {
	if m.bucketSeconds <= 0 {
		return CloneFloatPtr(m.raw[ts])
	}
	agg := m.buckets[ts]
	if agg == nil || agg.count == 0 {
		return nil
	}
	return NormalizeFloat(agg.sum / float64(agg.count))
}

func (m *metricSeries) eachTime(visit func(int64)) {
	if m.bucketSeconds <= 0 {
		for ts := range m.raw {
			visit(ts)
		}
		return
	}
	for ts := range m.buckets {
		visit(ts)
	}
}

func BuildNetworkTestKey(test metrics.NetworkTestResult) string {
	return buildNetworkSeriesKey(networkTestIdentity{
		Type: test.Type,
		Host: test.Host,
		Port: test.Port,
		Name: test.Name,
	})
}

func buildNetworkSeriesKey(identity networkTestIdentity) string {
	_, key := normalizeNetworkSeriesKey(identity)
	return key
}

func parseNetworkSeriesKey(key string) (networkTestIdentity, error) {
	parts := strings.Split(key, "|")
	if len(parts) != 4 {
		return networkTestIdentity{}, fmt.Errorf("invalid network history key %q", key)
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return networkTestIdentity{}, fmt.Errorf("invalid network history port in key %q: %w", key, err)
	}
	return networkTestIdentity{
		Type: strings.TrimSpace(parts[0]),
		Host: strings.TrimSpace(parts[1]),
		Port: port,
		Name: strings.TrimSpace(parts[3]),
	}, nil
}

func normalizeNetworkIdentity(identity networkTestIdentity) networkTestIdentity {
	identity.Type = normalizeIdentityValue(identity.Type, "icmp")
	identity.Host = strings.ToLower(strings.TrimSpace(identity.Host))
	identity.Name = strings.ToLower(strings.TrimSpace(identity.Name))
	return identity
}

func normalizeNetworkSeriesKey(identity networkTestIdentity) (networkTestIdentity, string) {
	identity = normalizeNetworkIdentity(identity)
	if identity.Host == "" && identity.Name == "" {
		return identity, ""
	}
	return identity, fmt.Sprintf("%s|%s|%d|%s", identity.Type, identity.Host, identity.Port, identity.Name)
}

func ensureSeriesAccumulator(
	result map[string]*seriesAccumulator,
	identity networkTestIdentity,
	bucketMillis int64,
) *seriesAccumulator {
	identity, key := normalizeNetworkSeriesKey(identity)
	if key == "" {
		return nil
	}
	existing := result[key]
	if existing != nil {
		return existing
	}
	entry := &seriesAccumulator{
		identity:     identity,
		bucketMillis: bucketMillis,
		latency:      newMetricSeries(bucketMillis),
		loss:         newMetricSeries(bucketMillis),
		availability: newMetricSeries(bucketMillis),
	}
	result[key] = entry
	return entry
}

// CloneFloatPtr returns a copy of value, or nil when value is nil or not
// finite (NaN/Inf).
func CloneFloatPtr(value *float64) *float64 {
	if value == nil {
		return nil
	}
	v := *value
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	copyValue := v
	return &copyValue
}

// NormalizeFloat returns a pointer to value, or nil when value is not finite
// (NaN/Inf).
func NormalizeFloat(value float64) *float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil
	}
	copyValue := value
	return &copyValue
}

func availabilityForTest(test metrics.NetworkTestResult) float64 {
	if strings.EqualFold(strings.TrimSpace(test.Status), "online") {
		return 1
	}
	if test.LatencyMs != nil {
		return 1
	}
	return 0
}

func buildNetworkHistoryEntryWithCutoff(acc *seriesAccumulator, cutoffSeconds int64) *NetworkHistoryEntry {
	if acc == nil {
		return nil
	}
	times := collectNetworkHistoryTimes(acc, cutoffSeconds)
	if len(times) == 0 {
		return nil
	}

	entry := &NetworkHistoryEntry{
		Latency:      cloneHistorySeriesValues(acc.latency, times),
		Loss:         cloneHistorySeriesValues(acc.loss, times),
		Availability: cloneHistorySeriesValues(acc.availability, times),
		Times:        times,
		LastAt:       times[len(times)-1],
	}
	entry.MinIntervalSec, entry.AvgIntervalSec = HistoryIntervalStats(times)
	return entry
}

func cloneHistorySeriesValues(series *metricSeries, times []int64) []*float64 {
	values := make([]*float64, len(times))
	for idx, ts := range times {
		values[idx] = series.valueAt(ts)
	}
	return values
}

func collectNetworkHistoryTimes(acc *seriesAccumulator, cutoffSeconds int64) []int64 {
	timeSet := make(map[int64]struct{}, len(acc.latency.raw)+len(acc.loss.raw)+len(acc.availability.raw))
	for _, series := range [...]*metricSeries{acc.availability, acc.latency, acc.loss} {
		series.eachTime(func(ts int64) {
			if cutoffSeconds > 0 && ts < cutoffSeconds {
				return
			}
			timeSet[ts] = struct{}{}
		})
	}
	if len(timeSet) == 0 {
		return nil
	}

	times := make([]int64, 0, len(timeSet))
	for ts := range timeSet {
		times = append(times, ts)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times
}

func HistoryIntervalStats(times []int64) (int64, float64) {
	if len(times) < 2 {
		return 0, 0
	}
	var (
		minValue int64
		total    int64
		count    int64
	)
	for idx := 1; idx < len(times); idx++ {
		interval := times[idx] - times[idx-1]
		if interval <= 0 {
			continue
		}
		if minValue == 0 || interval < minValue {
			minValue = interval
		}
		total += interval
		count++
	}
	if count == 0 {
		return 0, 0
	}
	return minValue, float64(total) / float64(count)
}
