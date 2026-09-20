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

	networkRetentionDays    = 7
	networkRetention        = networkRetentionDays * 24 * time.Hour
	networkOutOfOrderWindow = 24 * time.Hour

	networkMaxBytes = 2 << 30
	offlineMaxBytes = 256 << 20
)

const maxPointsPerSeries = 1000

func downsampleBucketMillis(mint, maxt int64) int64 {
	windowMillis := maxt - mint
	if windowMillis <= 0 {
		return 0
	}
	bucketMillis := (windowMillis + maxPointsPerSeries - 1) / maxPointsPerSeries
	if bucketMillis <= 1000 {
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

type seriesAccumulator struct {
	identity     networkTestIdentity
	latency      *metricSeries
	loss         *metricSeries
	availability *metricSeries
}

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
	if bucketMillis > 0 {
		return &metricSeries{bucketSeconds: bucketMillis / 1000, buckets: make(map[int64]*bucketAggregate)}
	}
	return &metricSeries{raw: make(map[int64]*float64)}
}

func (m *metricSeries) sizeHint() int {
	return len(m.raw) + len(m.buckets)
}

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

func ParseNetworkSeriesKey(key string) (networkTestIdentity, error) {
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

const maxSeriesPerQuery = 500

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
	if len(result) >= maxSeriesPerQuery {
		return nil
	}
	entry := &seriesAccumulator{
		identity:     identity,
		latency:      newMetricSeries(bucketMillis),
		loss:         newMetricSeries(bucketMillis),
		availability: newMetricSeries(bucketMillis),
	}
	result[key] = entry
	return entry
}

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
	timeSet := make(map[int64]struct{}, acc.latency.sizeHint()+acc.loss.sizeHint()+acc.availability.sizeHint())
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
