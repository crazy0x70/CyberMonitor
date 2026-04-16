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
	latestLoaded     bool
}

type preparedNetworkSample struct {
	identity        networkTestIdentity
	seriesKey       string
	typeLabel       string
	hostLabel       string
	portLabel       string
	nameLabel       string
	timestampMillis int64
	latency         *float64
	loss            *float64
	availability    float64
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
		sample, ok := prepareNetworkSample(test, now)
		if !ok {
			continue
		}

		if sample.latency != nil {
			appended, err := s.appendMetricSampleIfFresh(appender, nodeID, sample, networkLatencyMetric, *sample.latency)
			if err != nil {
				return err
			}
			if appended {
				appendedSeries[networkSeriesTimestampKey(networkLatencyMetric, nodeID, sample.seriesKey)] = sample.timestampMillis
			}
		}
		if sample.loss != nil {
			appended, err := s.appendMetricSampleIfFresh(appender, nodeID, sample, networkLossMetric, *sample.loss)
			if err != nil {
				return err
			}
			if appended {
				appendedSeries[networkSeriesTimestampKey(networkLossMetric, nodeID, sample.seriesKey)] = sample.timestampMillis
			}
		}
		appended, err := s.appendMetricSampleIfFresh(appender, nodeID, sample, networkAvailabilityMetric, sample.availability)
		if err != nil {
			return err
		}
		if appended {
			appendedSeries[networkSeriesTimestampKey(networkAvailabilityMetric, nodeID, sample.seriesKey)] = sample.timestampMillis
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
	return s.queryRange(nodeID, from, to, true)
}

func (s *NetworkStore) QueryPublicRange(nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error) {
	return s.queryRange(nodeID, from, to, false)
}

func (s *NetworkStore) queryRange(
	nodeID string,
	from, to time.Time,
	includeAvailability bool,
) (map[string]*NetworkHistoryEntry, error) {
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
	metricsToCollect := []string{
		networkLatencyMetric,
		networkLossMetric,
	}
	if includeAvailability {
		metricsToCollect = append(metricsToCollect, networkAvailabilityMetric)
	}
	if err := collectMetricSeriesBatch(context.Background(), querier, nodeID, metricsToCollect, mint, maxt, accumulators); err != nil {
		return nil, err
	}

	result := make(map[string]*NetworkHistoryEntry, len(accumulators))
	cutoffSeconds := to.UTC().Add(-networkRetentionDays * 24 * time.Hour).Unix()
	for key, acc := range accumulators {
		entry := buildNetworkHistoryEntryWithCutoff(acc, cutoffSeconds)
		if entry != nil {
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
	s.latestLoaded = true
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
	if s.latestLoaded {
		for key := range s.latestSeriesTime {
			if networkSeriesTimestampNodeID(key) == nodeID {
				delete(s.latestSeriesTime, key)
			}
		}
	}
	return nil
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
	sample preparedNetworkSample,
	metricName string,
	value float64,
) error {
	_, err := appender.Append(0, labels.FromStrings(
		labels.MetricName, metricName,
		"node_id", nodeID,
		"type", sample.typeLabel,
		"host", sample.hostLabel,
		"port", sample.portLabel,
		"name", sample.nameLabel,
	), sample.timestampMillis, value)
	return err
}

func (s *NetworkStore) appendMetricSampleIfFresh(
	appender storage.Appender,
	nodeID string,
	sample preparedNetworkSample,
	metricName string,
	value float64,
) (bool, error) {
	latestMillis, known, err := s.latestTimestampMillis(metricName, nodeID, sample.seriesKey)
	if err != nil {
		return false, err
	}
	if known && sample.timestampMillis <= latestMillis {
		return false, nil
	}
	if err := appendMetricSample(appender, nodeID, sample, metricName, value); err != nil {
		return false, err
	}
	return true, nil
}

func (s *NetworkStore) latestTimestampMillis(metricName, nodeID, seriesKey string) (int64, bool, error) {
	if err := s.ensureLatestSeriesTimeLoaded(); err != nil {
		return 0, false, err
	}

	key := networkSeriesTimestampKey(metricName, nodeID, seriesKey)
	if latestMillis, ok := s.latestSeriesTime[key]; ok {
		return latestMillis, true, nil
	}
	return 0, false, nil
}

func (s *NetworkStore) ensureLatestSeriesTimeLoaded() error {
	if s.latestLoaded {
		return nil
	}

	latestSeriesTime, err := s.queryAllLatestTimestampMillis()
	if err != nil {
		return err
	}
	s.latestSeriesTime = latestSeriesTime
	s.latestLoaded = true
	return nil
}

func (s *NetworkStore) queryAllLatestTimestampMillis() (map[string]int64, error) {
	querier, err := s.db.Querier(math.MinInt64, math.MaxInt64)
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	nameMatcher, err := labels.NewMatcher(
		labels.MatchRegexp,
		labels.MetricName,
		"^(?:"+networkLatencyMetric+"|"+networkLossMetric+"|"+networkAvailabilityMetric+")$",
	)
	if err != nil {
		return nil, err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: math.MinInt64,
		End:   math.MaxInt64,
	}, nameMatcher)

	latestSeriesTime := make(map[string]int64)
	for seriesSet.Next() {
		series := seriesSet.At()
		seriesLabels := series.Labels()
		metricName := strings.TrimSpace(seriesLabels.Get(labels.MetricName))
		key := networkSeriesTimestampKey(metricName, seriesLabels.Get("node_id"), buildNetworkSeriesKey(networkIdentityFromLabels(seriesLabels)))
		if key == "" {
			continue
		}

		iterator := series.Iterator(nil)
		var (
			latestMillis int64
			found        bool
		)
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
			return nil, err
		}
		if found {
			latestSeriesTime[key] = latestMillis
		}
	}
	if err := seriesSet.Err(); err != nil {
		return nil, err
	}
	return latestSeriesTime, nil
}

func networkSeriesTimestampKey(metricName, nodeID, seriesKey string) string {
	seriesKey = strings.TrimSpace(seriesKey)
	if seriesKey == "" {
		return ""
	}
	return metricName + "|" + strings.TrimSpace(nodeID) + "|" + seriesKey
}

func networkSeriesTimestampNodeID(key string) string {
	_, remainder, found := strings.Cut(strings.TrimSpace(key), "|")
	if !found {
		return ""
	}
	nodeID, _, found := strings.Cut(remainder, "|")
	if !found {
		return ""
	}
	return strings.TrimSpace(nodeID)
}

func prepareNetworkSample(test metrics.NetworkTestResult, now time.Time) (preparedNetworkSample, bool) {
	sample := preparedNetworkSample{
		identity: networkTestIdentity{
			Type: strings.TrimSpace(test.Type),
			Host: strings.TrimSpace(test.Host),
			Port: test.Port,
			Name: strings.TrimSpace(test.Name),
		},
		timestampMillis: resolveTimestampMillis(test.CheckedAt, now),
		latency:         cloneFloatPointer(test.LatencyMs),
		loss:            normalizeFloatValue(test.PacketLoss),
		availability:    availabilityForTest(test),
	}
	sample.seriesKey = buildNetworkSeriesKey(sample.identity)
	if sample.seriesKey == "" {
		return preparedNetworkSample{}, false
	}
	sample.typeLabel = normalizeIdentityValue(sample.identity.Type, "icmp")
	sample.hostLabel = strings.ToLower(strings.TrimSpace(sample.identity.Host))
	sample.portLabel = strconv.Itoa(sample.identity.Port)
	sample.nameLabel = strings.ToLower(strings.TrimSpace(sample.identity.Name))
	return sample, true
}

func collectMetricSeriesBatch(
	ctx context.Context,
	querier storage.Querier,
	nodeID string,
	metricNames []string,
	mint int64,
	maxt int64,
	accumulators map[string]*seriesAccumulator,
) error {
	if len(metricNames) == 0 {
		return nil
	}

	nameMatcher, err := labels.NewMatcher(
		labels.MatchRegexp,
		labels.MetricName,
		"^(?:"+strings.Join(metricNames, "|")+")$",
	)
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
		seriesLabels := series.Labels()
		metricName := strings.TrimSpace(seriesLabels.Get(labels.MetricName))
		identity := networkIdentityFromLabels(seriesLabels)
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

func networkIdentityFromLabels(seriesLabels labels.Labels) networkTestIdentity {
	return networkTestIdentity{
		Type: normalizeIdentityValue(seriesLabels.Get("type"), "icmp"),
		Host: strings.TrimSpace(seriesLabels.Get("host")),
		Port: parsePortLabel(seriesLabels.Get("port")),
		Name: strings.TrimSpace(seriesLabels.Get("name")),
	}
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
