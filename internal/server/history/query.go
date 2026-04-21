package history

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"cyber_monitor/internal/metrics"
)

const (
	networkLatencyMetric      = "cm_network_test_latency_ms"
	networkLossMetric         = "cm_network_test_packet_loss"
	networkAvailabilityMetric = "cm_network_test_availability"

	networkRetentionDays = 366
)

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
	latency      map[int64]*float64
	loss         map[int64]*float64
	availability map[int64]*float64
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
		latency:      make(map[int64]*float64),
		loss:         make(map[int64]*float64),
		availability: make(map[int64]*float64),
	}
	result[key] = entry
	return entry
}

func cloneFloatPointer(value *float64) *float64 {
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

func normalizeFloatValue(value float64) *float64 {
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

func cloneHistorySeriesValues(series map[int64]*float64, times []int64) []*float64 {
	values := make([]*float64, len(times))
	for idx, ts := range times {
		values[idx] = cloneFloatPointer(series[ts])
	}
	return values
}

func collectNetworkHistoryTimes(acc *seriesAccumulator, cutoffSeconds int64) []int64 {
	timeSet := make(map[int64]struct{}, len(acc.availability)+len(acc.latency)+len(acc.loss))
	for _, series := range [...]map[int64]*float64{acc.availability, acc.latency, acc.loss} {
		for ts := range series {
			if cutoffSeconds > 0 && ts < cutoffSeconds {
				continue
			}
			timeSet[ts] = struct{}{}
		}
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
