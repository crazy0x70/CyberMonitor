package history

import (
	"context"
	"errors"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyber_monitor/internal/metrics"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

var errNilNetworkStore = errors.New("network history store is nil")

// MigrationSample 是迁移专用的扁平样本（节点 ID + 原始探测结果）。
type MigrationSample struct {
	NodeID string
	Test   metrics.NetworkTestResult
}

type NetworkStore struct {
	db               *tsdb.DB
	appendMu         sync.Mutex
	latestSeriesTime map[string]int64
	latestLoaded     bool
	// capLogUntil 序列触顶日志的限频闸（UnixNano）：触顶节点可被公开
	// 端点反复查询，逐条打印会成日志洪水。
	capLogUntil atomic.Int64
}

// allowCapLog 触顶日志的限频闸：分钟级窗口至多放行一条，竞争下偶发
// 多放一条无害。
func (s *NetworkStore) allowCapLog(now time.Time) bool {
	next := now.Add(time.Minute).UnixNano()
	prev := s.capLogUntil.Load()
	if prev >= now.UnixNano() {
		return false
	}
	return s.capLogUntil.CompareAndSwap(prev, next)
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

type preparedNetworkMetric struct {
	name  string
	value float64
}

func OpenNetworkStore(dir string) (*NetworkStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("network history dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = int64(networkRetention / time.Millisecond)
	opts.OutOfOrderTimeWindow = int64(networkOutOfOrderWindow / time.Millisecond)
	opts.MaxBytes = networkMaxBytes

	db, err := tsdb.Open(dir, nil, nil, opts, nil)
	if err != nil {
		return nil, err
	}
	return &NetworkStore{
		db:               db,
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
	normalizedID, err := NormalizeNodeID(nodeID)
	if err != nil || normalizedID == "" {
		// 迁移路径的 legacy 键未经上游校验：非法 nodeID 落库后 DeleteNode
		// （同款严格校验）永远匹配不到，TSDB 序列残留。
		log.Printf("history 拒绝非法节点 ID %q", strings.TrimSpace(nodeID))
		return nil
	}
	nodeID = normalizedID
	if len(tests) == 0 {
		return nil
	}

	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	ctx := context.Background()
	appender := s.db.Appender(ctx)
	committed := false
	latestSeriesTimeUpdates := make(map[string]int64)
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

		if err := s.appendPreparedMetricSamples(
			appender,
			nodeID,
			sample,
			latestSeriesTimeUpdates,
			now,
		); err != nil {
			return err
		}
	}

	if err := appender.Commit(); err != nil {
		return err
	}
	committed = true
	s.recordLatestSeriesTime(latestSeriesTimeUpdates)

	return nil
}

// AppendMigrationSamples 以单一 appender、单次 Commit 提交全局升序样本：
// TSDB head maxt 每次提交推进，按节点分批（各自 Commit）时，先落库批次
// 的较新时间戳会让后续批次的更老样本命中 too-old 被静默丢弃。调用方须
// 保证 samples 全局按 CheckedAt 升序。
func (s *NetworkStore) AppendMigrationSamples(samples []MigrationSample) error {
	if s == nil || s.db == nil {
		return errNilNetworkStore
	}
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	now := time.Now()
	appender := s.db.Appender(context.Background())
	committed := false
	defer func() {
		if !committed {
			_ = appender.Rollback()
		}
	}()
	latestSeriesTimeUpdates := make(map[string]int64)
	for _, ms := range samples {
		normalizedID, err := NormalizeNodeID(ms.NodeID)
		if err != nil || normalizedID == "" {
			log.Printf("history 拒绝非法节点 ID %q", strings.TrimSpace(ms.NodeID))
			continue
		}
		sample, ok := prepareNetworkSample(ms.Test, now)
		if !ok {
			continue
		}
		if err := s.appendPreparedMetricSamples(appender, normalizedID, sample, latestSeriesTimeUpdates, now); err != nil {
			return err
		}
	}
	if err := appender.Commit(); err != nil {
		return err
	}
	committed = true
	s.recordLatestSeriesTime(latestSeriesTimeUpdates)
	return nil
}

func (s *NetworkStore) QueryPublicRange(ctx context.Context, nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error) {
	return s.queryRange(ctx, nodeID, from, to, false)
}

// QueryRangeRaw 跳过桶降采样，返回原始采样时间戳。需要精确时间去重的
// 场景（如 legacy 迁移去重）必须走此路径：降采样输出的是桶起点时间。
func (s *NetworkStore) QueryRangeRaw(ctx context.Context, nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error) {
	return s.queryRangeWithOptions(ctx, nodeID, from, to, true, 0)
}

func (s *NetworkStore) HasNodeHistory(nodeID string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errNilNetworkStore
	}
	var err error
	nodeID, err = NormalizeNodeID(nodeID)
	if err != nil || nodeID == "" {
		return false, err
	}
	nameMatcher, err := newMetricNameMatcher(networkMetricNames(true))
	if err != nil {
		return false, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return false, err
	}
	return hasMatchingSeries(s.db, nameMatcher, nodeMatcher)
}

func (s *NetworkStore) queryRange(
	ctx context.Context,
	nodeID string,
	from, to time.Time,
	includeAvailability bool,
) (map[string]*NetworkHistoryEntry, error) {
	if s == nil || s.db == nil {
		return nil, errNilNetworkStore
	}
	nodeID = normalizeNodeID(nodeID)
	if nodeID == "" {
		return map[string]*NetworkHistoryEntry{}, nil
	}
	if to.Before(from) {
		return map[string]*NetworkHistoryEntry{}, nil
	}

	// 长窗口（如 1y）必须先定桶再采集：target ≤ ~1000 点/序列。
	// 短窗口返回 0，走 raw 路径（与历史行为一致）。
	bucketMillis := downsampleBucketMillis(from.UnixMilli(), to.UnixMilli())
	return s.queryRangeWithOptions(ctx, nodeID, from, to, includeAvailability, bucketMillis)
}

func (s *NetworkStore) queryRangeWithOptions(
	ctx context.Context,
	nodeID string,
	from, to time.Time,
	includeAvailability bool,
	bucketMillis int64,
) (map[string]*NetworkHistoryEntry, error) {
	if s == nil || s.db == nil {
		return nil, errNilNetworkStore
	}
	nodeID = normalizeNodeID(nodeID)
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
	dropped, err := collectMetricSeriesBatch(
		ctx,
		querier,
		nodeID,
		networkMetricNames(includeAvailability),
		mint,
		maxt,
		bucketMillis,
		accumulators,
	)
	if err != nil {
		return nil, err
	}
	if dropped > 0 && s.allowCapLog(time.Now()) {
		log.Printf("history 查询丢弃 %d 个超出基数上限（%d）的序列 node=%s", dropped, maxSeriesPerQuery, nodeID)
	}

	result := make(map[string]*NetworkHistoryEntry, len(accumulators))
	cutoffSeconds := to.UTC().Add(-networkRetentionDays * 24 * time.Hour).Unix()
	if bucketMillis == 0 {
		// raw 路径供迁移去重基线使用：保留期截断会让超期 legacy 序列
		// 整体缺席基线，产生无谓的重复 append（TSDB 重复容忍兜底）。
		cutoffSeconds = 0
	}
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
	if err := s.deleteMetricSeries(networkMetricNames(true)); err != nil {
		return err
	}
	s.resetLatestSeriesTime()
	return nil
}

func (s *NetworkStore) DeleteNode(nodeID string) error {
	if s == nil || s.db == nil {
		return errNilNetworkStore
	}
	var err error
	nodeID, err = NormalizeNodeID(nodeID)
	if err != nil {
		return err
	}
	if nodeID == "" {
		return nil
	}
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	matcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}
	if err := s.deleteSeries(matcher); err != nil {
		return err
	}
	s.deleteLatestSeriesTimeForNode(nodeID)
	return nil
}

// networkMaxFutureSkew 容忍 agent 时钟适度超前。上限之外的未来时间戳
// 会把 TSDB head maxt 抬到未来：此后所有节点的实时样本全部命中
// too-old 被静默丢弃（全网 history 瘫痪且无日志），重启后基线回扫还会
// 把未来值重新载入，跨重启持续。
const networkMaxFutureSkew = 5 * time.Minute

func resolveTimestampMillis(checkedAt int64, now time.Time) int64 {
	if checkedAt <= 0 {
		return now.UTC().UnixMilli()
	}
	if checkedAt > math.MaxInt64/1000 {
		// 乘 1000 会溢出为负，按非法处理。
		return now.UTC().UnixMilli()
	}
	millis := checkedAt * 1000
	if millis > now.Add(networkMaxFutureSkew).UTC().UnixMilli() {
		// 只钳上限：过老样本由 TSDB 拒收+容忍路径处理（迁移历史语义
		// 依赖真实时间戳，不得向 now 收敛）。
		return now.UTC().UnixMilli()
	}
	return millis
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

func (s *NetworkStore) appendPreparedMetricSamples(
	appender storage.Appender,
	nodeID string,
	sample preparedNetworkSample,
	latestSeriesTimeUpdates map[string]int64,
	now time.Time,
) error {
	for _, metric := range sample.metrics() {
		if err := s.appendPreparedMetricSample(
			appender,
			nodeID,
			sample,
			latestSeriesTimeUpdates,
			now,
			metric.name,
			metric.value,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *NetworkStore) appendPreparedMetricSample(
	appender storage.Appender,
	nodeID string,
	sample preparedNetworkSample,
	latestSeriesTimeUpdates map[string]int64,
	now time.Time,
	metricName string,
	value float64,
) error {
	appended, err := s.appendMetricSampleIfFresh(appender, nodeID, sample, metricName, value, now)
	if err != nil {
		return err
	}
	if appended {
		latestSeriesTimeUpdates[networkSeriesTimestampKey(metricName, nodeID, sample.seriesKey)] = sample.timestampMillis
	}
	return nil
}

func (s *NetworkStore) appendMetricSampleIfFresh(
	appender storage.Appender,
	nodeID string,
	sample preparedNetworkSample,
	metricName string,
	value float64,
	now time.Time,
) (bool, error) {
	latestMillis, known, err := s.latestTimestampMillis(metricName, nodeID, sample.seriesKey, now)
	if err != nil {
		return false, err
	}
	if known && sample.timestampMillis <= latestMillis {
		return false, nil
	}
	if err := appendMetricSample(appender, nodeID, sample, metricName, value); err != nil {
		// 首扫窗口外的陈旧样本（时钟回拨、久离线节点回连）会被 TSDB 以
		// 越界/重复/乱序拒绝：跳过单个样本，不让它拖垮整批提交。
		// ErrTooOldSample：启用 OOO 窗口后，比 headMaxt-window 更老的样本
		// 走该独立错误（而非 ErrOutOfBounds）。迁移场景下 map 随机序提交
		// 多序列时，第二序列的老样本必然命中——不容忍会让 >24h 跨度的
		// legacy 迁移永久失败（marker 不写、每次启动重试）。
		if errors.Is(err, storage.ErrOutOfBounds) ||
			errors.Is(err, storage.ErrTooOldSample) ||
			errors.Is(err, storage.ErrDuplicateSampleForTimestamp) ||
			errors.Is(err, storage.ErrOutOfOrderSample) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *NetworkStore) latestTimestampMillis(metricName, nodeID, seriesKey string, now time.Time) (int64, bool, error) {
	if err := s.ensureLatestSeriesTimeLoaded(now); err != nil {
		return 0, false, err
	}

	key := networkSeriesTimestampKey(metricName, nodeID, seriesKey)
	if latestMillis, ok := s.latestSeriesTime[key]; ok {
		return latestMillis, true, nil
	}
	return 0, false, nil
}

func (s *NetworkStore) ensureLatestSeriesTimeLoaded(now time.Time) error {
	if s.latestLoaded {
		return nil
	}

	latestSeriesTime, err := s.queryRecentLatestTimestampMillis(now)
	if err != nil {
		return err
	}
	s.latestSeriesTime = latestSeriesTime
	s.latestLoaded = true
	return nil
}

// queryRecentLatestTimestampMillis 只回扫乱序窗口内的样本建立去重基线：
// 更老的样本本来就落在 TSDB 的 OutOfOrderTimeWindow 之外（写入时被拒），
// 全量回扫在 366 天保留下会在重启后阻塞首个 ingest 数分钟。
func (s *NetworkStore) queryRecentLatestTimestampMillis(now time.Time) (map[string]int64, error) {
	// 1×乱序窗口即够：更老样本 TSDB 本就拒收（容忍路径），基线无需覆盖；
	// 2× 会让重启后首次 ingest 在 appendMu 内全量迭代两天样本。
	mint := now.Add(-networkOutOfOrderWindow).UnixMilli()
	querier, err := s.db.Querier(mint, math.MaxInt64)
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	nameMatcher, err := newMetricNameMatcher(networkMetricNames(true))
	if err != nil {
		return nil, err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: mint,
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

// maxLatestSeriesTimeEntries 限制去重基线条目数：host/name 标签由 agent
// 逐条可控，失控 agent 每次换标签即新增条目（数百字节/条），无上限会
// 在进程生命周期内耗尽内存。超限先剪除陈旧条目（早于 2×乱序窗口的样本
// 本就会被 TSDB 拒收，基线无需覆盖），仍超限则不记录新键——TSDB 侧由
// head 截断与保留期自我限界，重复写入走容忍路径，仅损失去重效率。
const maxLatestSeriesTimeEntries = 1 << 16

func (s *NetworkStore) recordLatestSeriesTime(latestSeriesTimeUpdates map[string]int64) {
	if len(s.latestSeriesTime)+len(latestSeriesTimeUpdates) > maxLatestSeriesTimeEntries {
		cutoff := time.Now().Add(-2 * networkOutOfOrderWindow).UnixMilli()
		for key, tsMillis := range s.latestSeriesTime {
			if tsMillis < cutoff {
				delete(s.latestSeriesTime, key)
			}
		}
	}
	for key, tsMillis := range latestSeriesTimeUpdates {
		if _, exists := s.latestSeriesTime[key]; !exists && len(s.latestSeriesTime) >= maxLatestSeriesTimeEntries {
			continue
		}
		s.latestSeriesTime[key] = tsMillis
	}
}

func (s *NetworkStore) deleteMetricSeries(metricNames []string) error {
	for _, metricName := range metricNames {
		matcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, metricName)
		if err != nil {
			return err
		}
		if err := s.deleteSeries(matcher); err != nil {
			return err
		}
	}
	return nil
}

func (s *NetworkStore) deleteSeries(matchers ...*labels.Matcher) error {
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matchers...)
}

func (s *NetworkStore) resetLatestSeriesTime() {
	clear(s.latestSeriesTime)
	s.latestLoaded = true
}

func (s *NetworkStore) deleteLatestSeriesTimeForNode(nodeID string) {
	if !s.latestLoaded {
		return
	}
	nodeID = normalizeNodeID(nodeID)
	for key := range s.latestSeriesTime {
		if networkSeriesTimestampNodeID(key) == nodeID {
			delete(s.latestSeriesTime, key)
		}
	}
}

// escapeNodeIDKey 对去重基线复合键（metric|nodeID|seriesKey）中的 nodeID
// 做 `|`/`%` 转义：ID 含 `|` 时切分错位会让按节点删除漏删，且不得为此
// 拒绝存量持久化 ID（回溯会使升级后启动失败）。
func escapeNodeIDKey(nodeID string) string {
	nodeID = strings.ReplaceAll(nodeID, "%", "%25")
	return strings.ReplaceAll(nodeID, "|", "%7C")
}

func unescapeNodeIDKey(nodeID string) string {
	nodeID = strings.ReplaceAll(nodeID, "%7C", "|")
	return strings.ReplaceAll(nodeID, "%25", "%")
}

func networkSeriesTimestampKey(metricName, nodeID, seriesKey string) string {
	seriesKey = strings.TrimSpace(seriesKey)
	if seriesKey == "" {
		return ""
	}
	return metricName + "|" + escapeNodeIDKey(normalizeNodeID(nodeID)) + "|" + seriesKey
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
	return unescapeNodeIDKey(normalizeNodeID(nodeID))
}

func normalizeNodeID(nodeID string) string {
	return strings.TrimSpace(nodeID)
}

func networkMetricNames(includeAvailability bool) []string {
	if includeAvailability {
		return []string{
			networkLatencyMetric,
			networkLossMetric,
			networkAvailabilityMetric,
		}
	}
	return []string{
		networkLatencyMetric,
		networkLossMetric,
	}
}

func newMetricNameMatcher(metricNames []string) (*labels.Matcher, error) {
	return labels.NewMatcher(
		labels.MatchRegexp,
		labels.MetricName,
		"^(?:"+strings.Join(metricNames, "|")+")$",
	)
}

func prepareNetworkSample(test metrics.NetworkTestResult, now time.Time) (preparedNetworkSample, bool) {
	sample := preparedNetworkSample{
		identity: normalizeNetworkIdentity(networkTestIdentity{
			Type: test.Type,
			Host: test.Host,
			Port: test.Port,
			Name: test.Name,
		}),
		timestampMillis: resolveTimestampMillis(test.CheckedAt, now),
		latency:         CloneFloatPtr(test.LatencyMs),
		loss:            NormalizeFloat(test.PacketLoss),
		availability:    availabilityForTest(test),
	}
	sample.seriesKey = buildNetworkSeriesKey(sample.identity)
	if sample.seriesKey == "" {
		return preparedNetworkSample{}, false
	}
	sample.typeLabel = sample.identity.Type
	sample.hostLabel = sample.identity.Host
	sample.portLabel = strconv.Itoa(sample.identity.Port)
	sample.nameLabel = sample.identity.Name
	return sample, true
}

func (sample preparedNetworkSample) metrics() []preparedNetworkMetric {
	metrics := make([]preparedNetworkMetric, 0, 3)
	if sample.latency != nil {
		metrics = append(metrics, preparedNetworkMetric{
			name:  networkLatencyMetric,
			value: *sample.latency,
		})
	}
	if sample.loss != nil {
		metrics = append(metrics, preparedNetworkMetric{
			name:  networkLossMetric,
			value: *sample.loss,
		})
	}
	return append(metrics, preparedNetworkMetric{
		name:  networkAvailabilityMetric,
		value: sample.availability,
	})
}

func collectMetricSeriesBatch(
	ctx context.Context,
	querier storage.Querier,
	nodeID string,
	metricNames []string,
	mint int64,
	maxt int64,
	bucketMillis int64,
	accumulators map[string]*seriesAccumulator,
) (int, error) {
	if len(metricNames) == 0 {
		return 0, nil
	}

	nameMatcher, err := newMetricNameMatcher(metricNames)
	if err != nil {
		return 0, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return 0, err
	}

	seriesSet := querier.Select(ctx, false, &storage.SelectHints{
		Start: mint,
		End:   maxt,
	}, nameMatcher, nodeMatcher)
	dropped := 0
	for seriesSet.Next() {
		series := seriesSet.At()
		seriesLabels := series.Labels()
		metricName := strings.TrimSpace(seriesLabels.Get(labels.MetricName))
		identity := networkIdentityFromLabels(seriesLabels)
		acc := ensureSeriesAccumulator(accumulators, identity, bucketMillis)
		if acc == nil {
			dropped++
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
				acc.latency.observe(tsSeconds, value)
			case networkLossMetric:
				acc.loss.observe(tsSeconds, value)
			case networkAvailabilityMetric:
				acc.availability.observe(tsSeconds, value)
			}
		}
		if err := iterator.Err(); err != nil {
			return dropped, err
		}
	}
	return dropped, seriesSet.Err()
}

func networkIdentityFromLabels(seriesLabels labels.Labels) networkTestIdentity {
	return normalizeNetworkIdentity(networkTestIdentity{
		Type: normalizeIdentityValue(seriesLabels.Get("type"), "icmp"),
		Host: strings.TrimSpace(seriesLabels.Get("host")),
		Port: parsePortLabel(seriesLabels.Get("port")),
		Name: strings.TrimSpace(seriesLabels.Get("name")),
	})
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
