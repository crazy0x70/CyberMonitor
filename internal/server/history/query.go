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

func buildNetworkTestKey(test metrics.NetworkTestResult) string {
	return buildNetworkSeriesKey(networkTestIdentity{
		Type: strings.TrimSpace(test.Type),
		Host: strings.TrimSpace(test.Host),
		Port: test.Port,
		Name: strings.TrimSpace(test.Name),
	})
}

func canonicalNetworkSeriesKey(identity networkTestIdentity) (string, bool) {
	kind := strings.ToLower(strings.TrimSpace(identity.Type))
	if kind == "" {
		kind = "icmp"
	}
	host := strings.ToLower(strings.TrimSpace(identity.Host))
	name := strings.ToLower(strings.TrimSpace(identity.Name))
	if host == "" && name == "" {
		return "", false
	}
	return fmt.Sprintf("%s|%s|%d|%s", kind, host, identity.Port, name), true
}

func buildNetworkSeriesKey(identity networkTestIdentity) string {
	key, ok := canonicalNetworkSeriesKey(identity)
	if !ok {
		return ""
	}
	return key
}

func splitNetworkSeriesKey(key string) (kind, host, portRaw, name string, ok bool) {
	kind, rest, found := strings.Cut(key, "|")
	if !found {
		return "", "", "", "", false
	}
	host, rest, found = strings.Cut(rest, "|")
	if !found {
		return "", "", "", "", false
	}
	portRaw, name, found = strings.Cut(rest, "|")
	if !found || strings.Contains(name, "|") {
		return "", "", "", "", false
	}
	return kind, host, portRaw, name, true
}

func parseNetworkSeriesKey(key string) (networkTestIdentity, error) {
	kind, host, portRaw, name, ok := splitNetworkSeriesKey(key)
	if !ok {
		return networkTestIdentity{}, fmt.Errorf("invalid network history key %q", key)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return networkTestIdentity{}, fmt.Errorf("invalid network history port in key %q: %w", key, err)
	}
	return networkTestIdentity{
		Type: strings.TrimSpace(kind),
		Host: strings.TrimSpace(host),
		Port: port,
		Name: strings.TrimSpace(name),
	}, nil
}

func ensureSeriesAccumulator(
	result map[string]*seriesAccumulator,
	identity networkTestIdentity,
) *seriesAccumulator {
	key := buildNetworkSeriesKey(identity)
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

func buildHistoryEntry(acc *seriesAccumulator) *NetworkHistoryEntry {
	return buildNetworkHistoryEntryWithCutoff(acc, 0)
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
		Latency:      make([]*float64, len(times)),
		Loss:         make([]*float64, len(times)),
		Availability: make([]*float64, len(times)),
		Times:        times,
		LastAt:       times[len(times)-1],
	}
	for index, ts := range times {
		entry.Latency[index] = cloneFloatPointer(acc.latency[ts])
		entry.Loss[index] = cloneFloatPointer(acc.loss[ts])
		entry.Availability[index] = cloneFloatPointer(acc.availability[ts])
	}
	entry.MinIntervalSec, entry.AvgIntervalSec = intervalStats(times)
	return entry
}

func collectNetworkHistoryTimes(acc *seriesAccumulator, cutoffSeconds int64) []int64 {
	timeSet := make(map[int64]struct{}, len(acc.availability)+len(acc.latency)+len(acc.loss))
	addVisibleTimestamp := func(ts int64) {
		if cutoffSeconds > 0 && ts < cutoffSeconds {
			return
		}
		timeSet[ts] = struct{}{}
	}
	for ts := range acc.availability {
		addVisibleTimestamp(ts)
	}
	for ts := range acc.latency {
		addVisibleTimestamp(ts)
	}
	for ts := range acc.loss {
		addVisibleTimestamp(ts)
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

func intervalStats(times []int64) (int64, float64) {
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
