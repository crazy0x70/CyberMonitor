package history

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

var errNilNetworkStore = errors.New("network history store is nil")

type NetworkStore struct {
	db               *tsdb.DB
	dir              string
	appendMu         sync.Mutex
	latestSeriesTime map[string]int64
}

func OpenNetworkStore(dir string) (*NetworkStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("network history dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = int64((networkRetentionDays * 24 * time.Hour) / time.Millisecond)

	db, err := tsdb.Open(dir, nil, nil, opts, nil)
	if err != nil {
		return nil, err
	}
	return &NetworkStore{
		db:               db,
		dir:              dir,
		latestSeriesTime: make(map[string]int64),
	}, nil
}

func (s *NetworkStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *NetworkStore) AppendBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error {
	if s == nil || s.db == nil {
		return errNilNetworkStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || len(tests) == 0 {
		return nil
	}

	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	ctx := context.Background()
	appender := s.db.Appender(ctx)
	committed := false
	appendedSeries := make(map[string]int64)
	defer func() {
		if !committed {
			_ = appender.Rollback()
		}
	}()

	for _, test := range tests {
		identity := networkTestIdentity{
			Type: strings.TrimSpace(test.Type),
			Host: strings.TrimSpace(test.Host),
			Port: test.Port,
			Name: strings.TrimSpace(test.Name),
		}
		if buildNetworkSeriesKey(identity) == "" {
			continue
		}

		tsMillis := resolveTimestampMillis(test.CheckedAt, now)
		if latency := cloneFloatPointer(test.LatencyMs); latency != nil {
			appended, err := s.appendMetricSampleIfFresh(appender, nodeID, identity, networkLatencyMetric, tsMillis, *latency)
			if err != nil {
				return err
			}
			if appended {
				appendedSeries[networkSeriesTimestampKey(networkLatencyMetric, nodeID, identity)] = tsMillis
			}
		}
		if loss := normalizeFloatValue(test.PacketLoss); loss != nil {
			appended, err := s.appendMetricSampleIfFresh(appender, nodeID, identity, networkLossMetric, tsMillis, *loss)
			if err != nil {
				return err
			}
			if appended {
				appendedSeries[networkSeriesTimestampKey(networkLossMetric, nodeID, identity)] = tsMillis
			}
		}
		appended, err := s.appendMetricSampleIfFresh(appender, nodeID, identity, networkAvailabilityMetric, tsMillis, availabilityForTest(test))
		if err != nil {
			return err
		}
		if appended {
			appendedSeries[networkSeriesTimestampKey(networkAvailabilityMetric, nodeID, identity)] = tsMillis
		}
	}

	if err := appender.Commit(); err != nil {
		return err
	}
	committed = true
	for key, tsMillis := range appendedSeries {
		s.latestSeriesTime[key] = tsMillis
	}

	return nil
}

func (s *NetworkStore) QueryRange(nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error) {
	if s == nil || s.db == nil {
		return nil, errNilNetworkStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return map[string]*NetworkHistoryEntry{}, nil
	}
	if to.Before(from) {
		return map[string]*NetworkHistoryEntry{}, nil
	}

	mint := from.UnixMilli()
	maxt := to.UnixMilli()
	querier, err := s.db.Querier(mint, maxt)
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	accumulators := make(map[string]*seriesAccumulator)
	for _, metricName := range []string{
		networkLatencyMetric,
		networkLossMetric,
		networkAvailabilityMetric,
	} {
		if err := collectMetricSeries(context.Background(), querier, nodeID, metricName, mint, maxt, accumulators); err != nil {
			return nil, err
		}
	}

	result := make(map[string]*NetworkHistoryEntry, len(accumulators))
	cutoffSeconds := to.UTC().Add(-networkRetentionDays * 24 * time.Hour).Unix()
	for key, acc := range accumulators {
		entry := buildHistoryEntry(acc)
		if entry != nil {
			trimNetworkHistoryEntryBefore(entry, cutoffSeconds)
			result[key] = entry
		}
	}
	return result, nil
}

func (s *NetworkStore) Clear() error {
	if s == nil || s.db == nil {
		return errNilNetworkStore
	}
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	for _, metricName := range []string{networkLatencyMetric, networkLossMetric, networkAvailabilityMetric} {
		matcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, metricName)
		if err != nil {
			return err
		}
		if err := s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher); err != nil {
			return err
		}
	}
	clear(s.latestSeriesTime)
	return nil
}

func (s *NetworkStore) DeleteNode(nodeID string) error {
	if s == nil || s.db == nil {
		return errNilNetworkStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil
	}
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	matcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}
	if err := s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher); err != nil {
		return err
	}
	for key := range s.latestSeriesTime {
		if strings.Contains(key, "|"+nodeID+"|") {
			delete(s.latestSeriesTime, key)
		}
	}
	return nil
}

func trimNetworkHistoryEntryBefore(entry *NetworkHistoryEntry, cutoffSeconds int64) {
	if entry == nil || cutoffSeconds <= 0 || len(entry.Times) == 0 {
		return
	}
	startIndex := 0
	for startIndex < len(entry.Times) && entry.Times[startIndex] < cutoffSeconds {
		startIndex++
	}
	if startIndex == 0 {
		return
	}
	entry.Times = append([]int64(nil), entry.Times[startIndex:]...)
	entry.Latency = append([]*float64(nil), entry.Latency[startIndex:]...)
	entry.Loss = append([]*float64(nil), entry.Loss[startIndex:]...)
	entry.Availability = append([]*float64(nil), entry.Availability[startIndex:]...)
	if len(entry.Times) == 0 {
		entry.LastAt = 0
		entry.MinIntervalSec = 0
		entry.AvgIntervalSec = 0
		return
	}
	entry.LastAt = entry.Times[len(entry.Times)-1]
	entry.MinIntervalSec, entry.AvgIntervalSec = intervalStats(entry.Times)
}

func resolveTimestampMillis(checkedAt int64, now time.Time) int64 {
	if checkedAt <= 0 {
		return now.UTC().UnixMilli()
	}
	return checkedAt * 1000
}

func appendMetricSample(
	appender storage.Appender,
	nodeID string,
	identity networkTestIdentity,
	metricName string,
	timestampMillis int64,
	value float64,
) error {
	_, err := appender.Append(0, labels.FromStrings(
		labels.MetricName, metricName,
		"node_id", nodeID,
		"type", normalizeIdentityValue(identity.Type, "icmp"),
		"host", strings.ToLower(strings.TrimSpace(identity.Host)),
		"port", strconv.Itoa(identity.Port),
		"name", strings.ToLower(strings.TrimSpace(identity.Name)),
	), timestampMillis, value)
	return err
}

func (s *NetworkStore) appendMetricSampleIfFresh(
	appender storage.Appender,
	nodeID string,
	identity networkTestIdentity,
	metricName string,
	timestampMillis int64,
	value float64,
) (bool, error) {
	latestMillis, known, err := s.latestTimestampMillis(metricName, nodeID, identity)
	if err != nil {
		return false, err
	}
	if known && timestampMillis <= latestMillis {
		return false, nil
	}
	if err := appendMetricSample(appender, nodeID, identity, metricName, timestampMillis, value); err != nil {
		return false, err
	}
	return true, nil
}

func (s *NetworkStore) latestTimestampMillis(metricName, nodeID string, identity networkTestIdentity) (int64, bool, error) {
	key := networkSeriesTimestampKey(metricName, nodeID, identity)
	if latestMillis, ok := s.latestSeriesTime[key]; ok {
		return latestMillis, true, nil
	}

	latestMillis, found, err := s.queryLatestTimestampMillis(metricName, nodeID, identity)
	if err != nil {
		return 0, false, err
	}
	if found {
		s.latestSeriesTime[key] = latestMillis
	}
	return latestMillis, found, nil
}

func (s *NetworkStore) queryLatestTimestampMillis(metricName, nodeID string, identity networkTestIdentity) (int64, bool, error) {
	querier, err := s.db.Querier(math.MinInt64, math.MaxInt64)
	if err != nil {
		return 0, false, err
	}
	defer querier.Close()

	nameMatcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, metricName)
	if err != nil {
		return 0, false, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return 0, false, err
	}
	typeMatcher, err := labels.NewMatcher(labels.MatchEqual, "type", normalizeIdentityValue(identity.Type, "icmp"))
	if err != nil {
		return 0, false, err
	}
	hostMatcher, err := labels.NewMatcher(labels.MatchEqual, "host", strings.ToLower(strings.TrimSpace(identity.Host)))
	if err != nil {
		return 0, false, err
	}
	portMatcher, err := labels.NewMatcher(labels.MatchEqual, "port", strconv.Itoa(identity.Port))
	if err != nil {
		return 0, false, err
	}
	nameLabelMatcher, err := labels.NewMatcher(labels.MatchEqual, "name", strings.ToLower(strings.TrimSpace(identity.Name)))
	if err != nil {
		return 0, false, err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: math.MinInt64,
		End:   math.MaxInt64,
	}, nameMatcher, nodeMatcher, typeMatcher, hostMatcher, portMatcher, nameLabelMatcher)

	var (
		latestMillis int64
		found        bool
	)
	for seriesSet.Next() {
		iterator := seriesSet.At().Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType != chunkenc.ValFloat {
				continue
			}
			tsMillis, _ := iterator.At()
			if !found || tsMillis > latestMillis {
				latestMillis = tsMillis
				found = true
			}
		}
		if err := iterator.Err(); err != nil {
			return 0, false, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return 0, false, err
	}
	return latestMillis, found, nil
}

func networkSeriesTimestampKey(metricName, nodeID string, identity networkTestIdentity) string {
	return metricName + "|" + strings.TrimSpace(nodeID) + "|" + buildNetworkSeriesKey(identity)
}

func collectMetricSeries(
	ctx context.Context,
	querier storage.Querier,
	nodeID string,
	metricName string,
	mint int64,
	maxt int64,
	accumulators map[string]*seriesAccumulator,
) error {
	nameMatcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, metricName)
	if err != nil {
		return err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}

	seriesSet := querier.Select(ctx, false, &storage.SelectHints{
		Start: mint,
		End:   maxt,
	}, nameMatcher, nodeMatcher)
	for seriesSet.Next() {
		series := seriesSet.At()
		identity := networkTestIdentity{
			Type: normalizeIdentityValue(series.Labels().Get("type"), "icmp"),
			Host: strings.TrimSpace(series.Labels().Get("host")),
			Port: parsePortLabel(series.Labels().Get("port")),
			Name: strings.TrimSpace(series.Labels().Get("name")),
		}
		acc := ensureSeriesAccumulator(accumulators, identity)
		if acc == nil {
			continue
		}

		iterator := series.Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType != chunkenc.ValFloat {
				continue
			}
			tsMillis, value := iterator.At()
			tsSeconds := tsMillis / 1000
			switch metricName {
			case networkLatencyMetric:
				acc.latency[tsSeconds] = normalizeFloatValue(value)
			case networkLossMetric:
				acc.loss[tsSeconds] = normalizeFloatValue(value)
			case networkAvailabilityMetric:
				acc.availability[tsSeconds] = normalizeFloatValue(value)
			}
		}
		if err := iterator.Err(); err != nil {
			return err
		}
	}
	return seriesSet.Err()
}

func parsePortLabel(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return value
}

func normalizeIdentityValue(value string, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return fallback
	}
	return normalized
}

func defaultNetworkStoreDir(dataDir string) string {
	return filepath.Join(dataDir, "history", "network")
}
