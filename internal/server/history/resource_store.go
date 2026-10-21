package history

import (
	"context"
	"errors"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyber_monitor/internal/metrics"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

// 资源历史（CPU / 内存 / 网络）的存储层约定：
//   - Agent 每秒上报，服务端按 30 秒桶累加求平均，桶结束（收到下一个桶的首个样本，
//     或周期性巡检发现桶已过期）时以「桶起点」写入一个点，降低写入量与存储量；
//   - 节点离线不补点，查询结果里自然形成缺口；
//   - 保留天数由设置项 resource_history_days 决定（1/7/30）：查询侧按保留期精确截断，
//     磁盘由 TSDB 自身的时间保留按 block 淘汰，只在缩短保留期时做一次后台 Delete。
const (
	resourceCPUMetric      = "cm_node_cpu_usage_percent"
	resourceMemoryMetric   = "cm_node_memory_used_percent"
	resourceRxMetric       = "cm_node_network_rx_bytes_per_sec"
	resourceTxMetric       = "cm_node_network_tx_bytes_per_sec"
	resourceBucketInterval = 30 * time.Second
	resourceMaxBytes       = 1 << 30
	// resourceAccumulatorLimit 是内存中未落盘桶的节点上限，防止异常节点 ID 撑爆内存。
	resourceAccumulatorLimit = 4096
	// resourcePendingBucketLimit 是每节点「已结束但提交失败」桶的积压上限（约 4 分钟
	// 数据）。长期写入故障时丢弃最旧的桶并限速告警，避免无限占用内存。
	resourcePendingBucketLimit = 8
)

// ResourceRetentionDayOptions 是设置项 resource_history_days 的允许值。
var ResourceRetentionDayOptions = []int{1, 7, 30}

// DefaultResourceRetentionDays 是未配置时的资源历史保留天数。
const DefaultResourceRetentionDays = 7

var (
	errNilResourceStore = errors.New("resource history store is nil")

	resourceMetricNames = []string{
		resourceCPUMetric,
		resourceMemoryMetric,
		resourceRxMetric,
		resourceTxMetric,
	}
)

// ResourceHistoryEntry 是公开接口返回的资源历史：四个序列共用 times，缺口为 null。
type ResourceHistoryEntry struct {
	Times         []int64    `json:"times"`
	CPU           []*float64 `json:"cpu"`
	Memory        []*float64 `json:"memory"`
	RxBytesPerSec []*float64 `json:"rx"`
	TxBytesPerSec []*float64 `json:"tx"`
}

// ValidResourceRetentionDays 判断设置值是否在允许集合内。
func ValidResourceRetentionDays(days int) bool {
	for _, option := range ResourceRetentionDayOptions {
		if days == option {
			return true
		}
	}
	return false
}

// normalizeResourceRetentionDays 把非法值收敛到默认值，用于加载旧配置文件。
func normalizeResourceRetentionDays(days int) int {
	if ValidResourceRetentionDays(days) {
		return days
	}
	return DefaultResourceRetentionDays
}

type resourceBucket struct {
	start time.Time
	sum   [4]float64
	count [4]int
}

// ResourceStore 是独立的资源历史 TSDB（data/history/resource）。
type ResourceStore struct {
	db *tsdb.DB
	// mu 串行化累积器、待写队列与保留天数的访问：写入是每个节点每 30 秒一次的小事务，
	// 持锁完成能保证同一序列的时间戳始终单调，不会触发乱序写入。
	mu           sync.Mutex
	accumulators map[string]*resourceBucket
	// pending 保存已结束但尚未提交成功的桶（按桶起点升序）：写入失败时保留并按序
	// 重试，避免临时 I/O 故障造成永久丢点；后续桶必须排在它之后提交。
	pending map[string][]*resourceBucket
	// committed 记录每个节点已提交桶的起点（毫秒水位），用于识别迟到样本。
	committed map[string]int64
	// clock 是存储自身的单调时间基准：调用方传入的 now 可能是锁等待前捕获的旧值
	// （ingest 早于持久化），分桶与刷新都以这里的「已见最大时间」为准。
	clock         time.Time
	retentionDays int
	// retentionMu 串行化「应用 TSDB 保留配置 → 更新内存保留期 → 安排清理」这一整段。
	// ApplyConfig 只保护自己的保留字段，不与其他调用串行化：并发交错（A 写内存 1 天、
	// B 写内存 30 天并 ApplyConfig(30)、A 再 ApplyConfig(1)）会让内存值与磁盘实际保留
	// 期分叉，而巡检只比较内存值，从此不再纠正。锁顺序固定为 retentionMu → mu。
	retentionMu sync.Mutex
	// appender 返回写入用的 Appender；测试可替换为故障注入实现。
	appender func(context.Context) storage.Appender
	// applyConfig 是 TSDB 保留配置的测试钩子，nil 时直接调用 db.ApplyConfig。
	applyConfig func(*config.Config) error
	capLogUntil atomic.Int64
	diagLog     atomic.Int64

	// 后台一次性清理：只在缩短保留期时投递 cutoff，主 tick 不同步等待磁盘删除/压缩
	// （DB.Delete 会等压缩锁，并重写边界 block 的 tombstone）。
	purgeCh   chan int64
	purgeStop chan struct{}
	purgeDone chan struct{}
	// purgeCtx 让 Close 能取消进行中的 Delete：purgeStop 只终止循环，取消不了已经
	// 卡在压缩锁上的 DB.Delete，Close 会因此被拖住。
	purgeCtx    context.Context
	purgeCancel context.CancelFunc
	purgeDelete func(context.Context, int64, int64, ...*labels.Matcher) error
	purgeClose  sync.Once
}

// ResourceSeriesStats 是单个资源序列在窗口内「已保存点」的流式统计（AI 摘要专用，
// 不物化原始序列）。落盘的 30 秒桶平均值就是真实样本，这里按点而非按降采样桶统计：
// 对降采样桶再做等权平均会在桶内点数不同（窗口边界、离线缺口、新接入节点）时失真。
type ResourceSeriesStats struct {
	Count   int
	Sum     float64
	Max     float64
	MaxAt   int64 // 最大值对应的真实样本时间（秒）
	FirstAt int64 // 窗口内首个真实样本时间（秒）
}

// Avg 返回窗口内真实保存点的等权平均。
func (s ResourceSeriesStats) Avg() float64 {
	if s.Count == 0 {
		return 0
	}
	return s.Sum / float64(s.Count)
}

func (s *ResourceSeriesStats) add(tsSeconds int64, value float64) {
	s.Count++
	s.Sum += value
	if s.Count == 1 || value > s.Max {
		s.Max = value
		s.MaxAt = tsSeconds
	}
	if s.Count == 1 || tsSeconds < s.FirstAt {
		s.FirstAt = tsSeconds
	}
}

// ResourceStatsEntry 是节点四个资源序列的窗口统计。
type ResourceStatsEntry struct {
	CPU    ResourceSeriesStats
	Memory ResourceSeriesStats
	Rx     ResourceSeriesStats
	Tx     ResourceSeriesStats
}

// MaxCount 返回四个序列里最大的真实点数（用于快照里的 samples 字段）。
func (e *ResourceStatsEntry) MaxCount() int {
	if e == nil {
		return 0
	}
	maxCount := 0
	for _, series := range [...]ResourceSeriesStats{e.CPU, e.Memory, e.Rx, e.Tx} {
		if series.Count > maxCount {
			maxCount = series.Count
		}
	}
	return maxCount
}

// FirstSampleAt 返回四个序列里最早的真实样本时间（秒），无样本时为 0。
func (e *ResourceStatsEntry) FirstSampleAt() int64 {
	if e == nil {
		return 0
	}
	var first int64
	for _, series := range [...]ResourceSeriesStats{e.CPU, e.Memory, e.Rx, e.Tx} {
		if series.Count == 0 {
			continue
		}
		if first == 0 || series.FirstAt < first {
			first = series.FirstAt
		}
	}
	return first
}

func (e *ResourceStatsEntry) statsFor(metricName string) *ResourceSeriesStats {
	switch strings.TrimSpace(metricName) {
	case resourceCPUMetric:
		return &e.CPU
	case resourceMemoryMetric:
		return &e.Memory
	case resourceRxMetric:
		return &e.Rx
	case resourceTxMetric:
		return &e.Tx
	}
	return nil
}

func OpenResourceStore(dir string, retentionDays int) (*ResourceStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("resource history dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	days := normalizeResourceRetentionDays(retentionDays)
	opts := tsdb.DefaultOptions()
	// TSDB 自身按当前保留期做 block 级淘汰（运行时可通过 ApplyConfig 修改）。
	opts.RetentionDuration = int64(time.Duration(days) * 24 * time.Hour / time.Millisecond)
	opts.OutOfOrderTimeWindow = 0
	opts.MaxBytes = resourceMaxBytes

	db, err := tsdb.Open(dir, nil, nil, opts, nil)
	if err != nil {
		return nil, err
	}
	purgeCtx, purgeCancel := context.WithCancel(context.Background())
	store := &ResourceStore{
		db:            db,
		accumulators:  make(map[string]*resourceBucket),
		pending:       make(map[string][]*resourceBucket),
		committed:     make(map[string]int64),
		retentionDays: days,
		purgeCh:       make(chan int64, 1),
		purgeStop:     make(chan struct{}),
		purgeDone:     make(chan struct{}),
		purgeCtx:      purgeCtx,
		purgeCancel:   purgeCancel,
		purgeDelete:   db.Delete,
	}
	store.appender = func(ctx context.Context) storage.Appender { return store.db.Appender(ctx) }
	go store.runPurgeLoop()
	return store, nil
}

func (s *ResourceStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.mu.Lock()
	// 已完成的桶尽力落盘，未完成的桶（仍可能被后续样本补全）直接丢弃。
	flushErr := s.flushCompletedLocked(time.Now().UTC())
	s.accumulators = make(map[string]*resourceBucket)
	s.mu.Unlock()
	// 先取消并停掉后台清理，避免它在数据库关闭后继续 Delete。取消先于等待：
	// 进行中的 DB.Delete 会等压缩锁，只能靠 context 打断。
	s.purgeClose.Do(func() {
		if s.purgeCancel != nil {
			s.purgeCancel()
		}
		close(s.purgeStop)
		<-s.purgeDone
	})
	return errors.Join(flushErr, s.db.Close())
}

// Observe 把一次上报计入 30 秒桶。分桶以存储内的单调时间为准，不信任调用方传入的
// 早期 now（ingest 在锁等待/持久化之前就捕获了它），否则迟到样本会重建已被
// FlushExpired 提交并移除的旧桶，产生同时间戳/乱序写入。
func (s *ResourceStore) Observe(nodeID string, stats metrics.NodeStats, now time.Time) error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	normalizedID, err := NormalizeNodeID(nodeID)
	if err != nil || normalizedID == "" {
		log.Printf("history 拒绝非法节点 ID %q", strings.TrimSpace(nodeID))
		return nil
	}
	nodeID = normalizedID
	sample := resourceSampleFromStats(stats)
	if sample.empty() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bucketStart := s.advanceClockLocked(now).Truncate(resourceBucketInterval)
	if watermark, ok := s.committed[nodeID]; ok && bucketStart.UnixMilli() <= watermark {
		// 迟到样本：所属桶已提交（单调时间正常情况下已排除），样本并入当前打开的
		// 桶；没有打开的桶时开一个严格晚于水位的桶，信息不丢也不会撞时间戳。
		if s.allowDiagLog(now) {
			log.Printf("history 资源迟到样本并入当前桶 node=%s bucket=%d watermark=%d", nodeID, bucketStart.Unix(), watermark/1000)
		}
		bucketStart = time.UnixMilli(watermark).UTC().Add(resourceBucketInterval)
	}
	acc := s.openBucketLocked(nodeID, bucketStart, now)
	if acc == nil {
		return nil
	}
	sample.addTo(acc)
	// 切桶时立即尝试提交待写队列（与旧行为一致：数据不等下一次巡检才落盘）；
	// 失败时桶保留在队列里，由 FlushExpired 重试并统一下报错误。
	_ = s.flushPendingLocked(nodeID, s.clock)
	return nil
}

// FlushExpired 由服务端巡检每秒调用：落盘已结束的桶，并重试之前失败的桶。
func (s *ResourceStore) FlushExpired(now time.Time) error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushCompletedLocked(now)
}

// SetRetentionDays 运行时修改保留天数：查询侧立即截断，磁盘交给 TSDB 的 block 级
// 保留；缩短保留期时额外在后台做一次受控 Delete（不持 s.mu，不阻塞 tick）。
func (s *ResourceStore) SetRetentionDays(days int) error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	if !ValidResourceRetentionDays(days) {
		return errors.New("invalid resource retention days")
	}
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	return s.applyRetentionDaysLocked(days)
}

// SyncRetention 与 SetRetentionDays 相同，但在串行锁内重新读取最新设置再应用：调用方
// 读到的值可能在等锁期间已经过期，只有锁内取值才能保证最终策略就是最新设置，而不是
// 把旧值覆盖到更新的配置上。latest 不能反过来依赖 s.retentionMu。
func (s *ResourceStore) SyncRetention(latest func() int) error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	if latest == nil {
		return errors.New("resource retention resolver is nil")
	}
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	days := normalizeResourceRetentionDays(latest())
	if s.RetentionDays() == days {
		return nil
	}
	return s.applyRetentionDaysLocked(days)
}

// applyRetentionDaysLocked 假设调用方持有 s.retentionMu：先让 TSDB 生效，成功后
// 才更新内存保留期并安排一次性清理。ApplyConfig 失败时内存值不变（否则巡检会以为
// 已经生效而不再纠正），返回错误后由下一次巡检重试。
func (s *ResourceStore) applyRetentionDaysLocked(days int) error {
	if err := s.applyTSDBRetention(days); err != nil {
		return err
	}
	s.mu.Lock()
	previous := s.retentionDays
	s.retentionDays = days
	s.mu.Unlock()
	if days < previous {
		cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
		select {
		case s.purgeCh <- cutoff:
		default:
			// 已有清理在排队：block 级淘汰会继续兜底，查询结果也已按新保留期截断。
			log.Printf("资源历史已有清理任务在排队，跳过本次一次性删除")
		}
	}
	return nil
}

// applyTSDBRetention 把保存天数写成 TSDB 的时间保留，由 block 级淘汰负责磁盘回收。
// ApplyConfig 会把 Size / OOO 一起覆盖，因此原样带上启动时的取值。
func (s *ResourceStore) applyTSDBRetention(days int) error {
	apply := s.applyConfig
	if apply == nil {
		apply = s.db.ApplyConfig
	}
	return apply(&config.Config{
		StorageConfig: config.StorageConfig{
			TSDBConfig: &config.TSDBConfig{
				Retention: &config.TSDBRetentionConfig{
					Time: model.Duration(time.Duration(days) * 24 * time.Hour),
					Size: resourceMaxBytes,
				},
			},
		},
	})
}

// runPurgeLoop 在后台执行保留期缩短时的一次性清理。
func (s *ResourceStore) runPurgeLoop() {
	defer close(s.purgeDone)
	for {
		select {
		case cutoff := <-s.purgeCh:
			s.purgeOlderThan(cutoff)
		case <-s.purgeStop:
			return
		}
	}
}

// purgeOlderThan 删除早于 cutoff（毫秒）的样本。故意不持有 s.mu：DB.Delete 会等待
// 压缩锁并重写边界 block 的 tombstone，持锁会让所有节点的 Observe 和查询取 cutoff 阻塞。
func (s *ResourceStore) purgeOlderThan(cutoffMillis int64) {
	if s == nil || s.db == nil || cutoffMillis <= 0 {
		return
	}
	matcher, err := newMetricNameMatcher(resourceMetricNames)
	if err != nil {
		log.Printf("资源历史清理准备 matcher 失败: %v", err)
		return
	}
	ctx := s.purgeCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	deleteFn := s.purgeDelete
	if deleteFn == nil {
		deleteFn = s.db.Delete
	}
	if err := deleteFn(ctx, math.MinInt64, cutoffMillis, matcher); err != nil {
		if ctx.Err() != nil {
			// Close 取消了清理：不是故障，不打日志。
			return
		}
		log.Printf("资源历史清理失败: %v", err)
	}
}

func (s *ResourceStore) RetentionDays() int {
	if s == nil {
		return DefaultResourceRetentionDays
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retentionDays
}

func (s *ResourceStore) DeleteNode(nodeID string) error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	var err error
	nodeID, err = NormalizeNodeID(nodeID)
	if err != nil {
		return err
	}
	if nodeID == "" {
		return nil
	}
	matcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accumulators, nodeID)
	delete(s.pending, nodeID)
	delete(s.committed, nodeID)
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher)
}

func (s *ResourceStore) Clear() error {
	if s == nil || s.db == nil {
		return errNilResourceStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accumulators = make(map[string]*resourceBucket)
	s.pending = make(map[string][]*resourceBucket)
	s.committed = make(map[string]int64)
	matcher, err := newMetricNameMatcher(resourceMetricNames)
	if err != nil {
		return err
	}
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher)
}

func (s *ResourceStore) HasNodeHistory(nodeID string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errNilResourceStore
	}
	var err error
	nodeID, err = NormalizeNodeID(nodeID)
	if err != nil || nodeID == "" {
		return false, err
	}
	nameMatcher, err := newMetricNameMatcher(resourceMetricNames)
	if err != nil {
		return false, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return false, err
	}
	// 保留期缩小时查询侧必须立即截断，不能等磁盘上的 Delete 完成。
	return hasMatchingSeriesSince(s.db, s.retentionCutoffMillis(time.Now().UTC()), nameMatcher, nodeMatcher)
}

// QueryPublicRange 查询节点在 [from, to] 内的资源历史，按 maxPointsPerSeries 降采样。
func (s *ResourceStore) QueryPublicRange(ctx context.Context, nodeID string, from, to time.Time) (*ResourceHistoryEntry, error) {
	entry := NewEmptyResourceHistoryEntry()
	if s == nil || s.db == nil {
		return nil, errNilResourceStore
	}
	nodeID = normalizeNodeID(nodeID)
	if nodeID == "" || to.Before(from) {
		return entry, nil
	}

	mint := from.UnixMilli()
	maxt := to.UnixMilli()
	bucketMillis := downsampleBucketMillis(mint, maxt)
	cutoffMillis := s.retentionCutoffMillis(to.UTC())

	querier, err := s.db.Querier(mint, maxt)
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	nameMatcher, err := newMetricNameMatcher(resourceMetricNames)
	if err != nil {
		return nil, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return nil, err
	}

	accumulator := newResourceAccumulator(bucketMillis)
	seriesSet := querier.Select(ctx, false, &storage.SelectHints{
		Start: mint,
		End:   maxt,
	}, nameMatcher, nodeMatcher)
	for seriesSet.Next() {
		series := seriesSet.At()
		target := accumulator.seriesFor(series.Labels().Get(labels.MetricName))
		if target == nil {
			continue
		}
		iterator := series.Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType != chunkenc.ValFloat {
				continue
			}
			tsMillis, value := iterator.At()
			if cutoffMillis > 0 && tsMillis < cutoffMillis {
				continue
			}
			target.observe(tsMillis/1000, value)
		}
		if err := iterator.Err(); err != nil {
			return nil, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return nil, err
	}
	return buildResourceHistoryEntry(accumulator), nil
}

// QueryResourceStats 按序列流式统计节点在 [from, to] 内已保存的资源点：点数、均值、
// 最大值及其真实样本时间、窗口内首个样本时间。只给 AI 摘要使用：不走面向图表的
// 降采样（那会把桶均值再等权平均，桶内点数不同时结果失真），也不物化原始序列。
func (s *ResourceStore) QueryResourceStats(ctx context.Context, nodeID string, from, to time.Time) (*ResourceStatsEntry, error) {
	entry := &ResourceStatsEntry{}
	if s == nil || s.db == nil {
		return nil, errNilResourceStore
	}
	nodeID = normalizeNodeID(nodeID)
	if nodeID == "" || to.Before(from) {
		return entry, nil
	}

	mint := from.UnixMilli()
	maxt := to.UnixMilli()
	cutoffMillis := s.retentionCutoffMillis(to.UTC())

	querier, err := s.db.Querier(mint, maxt)
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	nameMatcher, err := newMetricNameMatcher(resourceMetricNames)
	if err != nil {
		return nil, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return nil, err
	}

	seriesSet := querier.Select(ctx, false, &storage.SelectHints{
		Start: mint,
		End:   maxt,
	}, nameMatcher, nodeMatcher)
	for seriesSet.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		series := seriesSet.At()
		target := entry.statsFor(series.Labels().Get(labels.MetricName))
		if target == nil {
			continue
		}
		iterator := series.Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType != chunkenc.ValFloat {
				continue
			}
			tsMillis, value := iterator.At()
			if cutoffMillis > 0 && tsMillis < cutoffMillis {
				continue
			}
			if math.IsNaN(value) || math.IsInf(value, 0) {
				continue
			}
			target.add(tsMillis/1000, value)
		}
		if err := iterator.Err(); err != nil {
			return nil, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return nil, err
	}
	return entry, nil
}

func (s *ResourceStore) retentionCutoffMillis(to time.Time) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	days := s.retentionDays
	s.mu.Unlock()
	if days <= 0 {
		return 0
	}
	return to.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
}

type resourceSample struct {
	values [4]float64
	valid  [4]bool
}

func (sample resourceSample) empty() bool {
	for _, ok := range sample.valid {
		if ok {
			return false
		}
	}
	return true
}

func (sample resourceSample) addTo(bucket *resourceBucket) {
	for idx, ok := range sample.valid {
		if !ok {
			continue
		}
		bucket.sum[idx] += sample.values[idx]
		bucket.count[idx]++
	}
}

func resourceSampleFromStats(stats metrics.NodeStats) resourceSample {
	raw := [4]float64{
		stats.CPU.UsagePercent,
		stats.Memory.UsedPercent,
		stats.Network.RxBytesPerSec,
		stats.Network.TxBytesPerSec,
	}
	var sample resourceSample
	for idx, value := range raw {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			continue
		}
		sample.values[idx] = value
		sample.valid[idx] = true
	}
	return sample
}

// advanceClockLocked 推进存储的单调时间基准并返回当前值。
func (s *ResourceStore) advanceClockLocked(now time.Time) time.Time {
	ts := now.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if ts.After(s.clock) {
		s.clock = ts
	}
	return s.clock
}

// openBucketLocked 返回节点当前的 30 秒桶：start 晚于现有桶时把旧桶排入待写队列，
// 落后或相同的样本（迟到样本）并入现有桶。没有可用的桶（新节点且已达上限）时返回 nil。
func (s *ResourceStore) openBucketLocked(nodeID string, start time.Time, now time.Time) *resourceBucket {
	if existing, ok := s.accumulators[nodeID]; ok {
		if !start.After(existing.start) {
			return existing
		}
		s.enqueuePendingLocked(nodeID, existing)
	} else if len(s.accumulators) >= resourceAccumulatorLimit {
		if s.allowCapLog(now) {
			log.Printf("history 资源累积器已达上限（%d），忽略新节点 %s", resourceAccumulatorLimit, nodeID)
		}
		return nil
	}
	bucket := &resourceBucket{start: start}
	s.accumulators[nodeID] = bucket
	return bucket
}

// enqueuePendingLocked 把已结束的桶排入待写队列（按起点升序），超出积压上限时丢弃
// 最旧的桶并限速告警。
func (s *ResourceStore) enqueuePendingLocked(nodeID string, bucket *resourceBucket) {
	if bucket == nil {
		return
	}
	queue := append(s.pending[nodeID], bucket)
	if len(queue) > resourcePendingBucketLimit {
		dropped := len(queue) - resourcePendingBucketLimit
		queue = append([]*resourceBucket(nil), queue[dropped:]...)
		if s.allowDiagLog(time.Now()) {
			log.Printf("history 资源待写桶积压超上限（%d），节点 %s 丢弃最旧的 %d 个桶", resourcePendingBucketLimit, nodeID, dropped)
		}
	}
	s.pending[nodeID] = queue
}

func (s *ResourceStore) markCommittedLocked(nodeID string, bucket *resourceBucket) {
	if bucket == nil {
		return
	}
	if start := bucket.start.UnixMilli(); start > s.committed[nodeID] {
		s.committed[nodeID] = start
	}
}

func (s *ResourceStore) appendBucketLocked(nodeID string, bucket *resourceBucket) error {
	if bucket == nil {
		return nil
	}
	appenderSource := s.appender
	if appenderSource == nil {
		appenderSource = func(ctx context.Context) storage.Appender { return s.db.Appender(ctx) }
	}
	appender := appenderSource(context.Background())
	if appender == nil {
		return errors.New("resource store appender is nil")
	}
	tsMillis := bucket.start.UnixMilli()
	committed := false
	defer func() {
		if !committed {
			_ = appender.Rollback()
		}
	}()

	appended := false
	for idx, metricName := range resourceMetricNames {
		if bucket.count[idx] == 0 {
			continue
		}
		value := bucket.sum[idx] / float64(bucket.count[idx])
		if _, err := appender.Append(0, labels.FromStrings(
			labels.MetricName, metricName,
			"node_id", nodeID,
		), tsMillis, value); err != nil {
			if errors.Is(err, storage.ErrDuplicateSampleForTimestamp) ||
				errors.Is(err, storage.ErrOutOfOrderSample) {
				// 迟到的旧桶样本：不重写已提交的时间戳，但必须留下诊断（限速）。
				if s.allowDiagLog(time.Now()) {
					log.Printf("history 资源样本时间戳重复/乱序已跳过 node=%s ts=%d metric=%s: %v", nodeID, tsMillis/1000, metricName, err)
				}
				continue
			}
			if errors.Is(err, storage.ErrOutOfBounds) || errors.Is(err, storage.ErrTooOldSample) {
				if s.allowDiagLog(time.Now()) {
					log.Printf("history 资源样本超出 TSDB 保留范围已跳过 node=%s ts=%d metric=%s: %v", nodeID, tsMillis/1000, metricName, err)
				}
				continue
			}
			return err
		}
		appended = true
	}
	if !appended {
		return nil
	}
	if err := appender.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// flushCompletedLocked 把已结束的桶移入待写队列，并按时间顺序提交（失败的桶保留，
// 下次重试；同节点的后续桶必须等它提交成功）。
func (s *ResourceStore) flushCompletedLocked(now time.Time) error {
	flushAt := s.advanceClockLocked(now)
	for nodeID, bucket := range s.accumulators {
		if bucket.start.Add(resourceBucketInterval).After(flushAt) {
			continue
		}
		s.enqueuePendingLocked(nodeID, bucket)
		delete(s.accumulators, nodeID)
	}

	var errs []error
	for nodeID := range s.pending {
		if err := s.flushPendingLocked(nodeID, flushAt); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// flushPendingLocked 按时间顺序提交某个节点的待写桶；遇到失败立即停下并保留它，
// 避免后续桶越过它造成乱序。
func (s *ResourceStore) flushPendingLocked(nodeID string, now time.Time) error {
	queue := s.pending[nodeID]
	for len(queue) > 0 {
		bucket := queue[0]
		if err := s.appendBucketLocked(nodeID, bucket); err != nil {
			s.pending[nodeID] = queue
			if s.allowDiagLog(now) {
				log.Printf("history 资源桶写入失败，保留待重试 node=%s ts=%d: %v", nodeID, bucket.start.Unix(), err)
			}
			return err
		}
		s.markCommittedLocked(nodeID, bucket)
		queue = queue[1:]
	}
	delete(s.pending, nodeID)
	return nil
}

func (s *ResourceStore) allowCapLog(now time.Time) bool {
	return s.allowLog(&s.capLogUntil, now)
}

func (s *ResourceStore) allowDiagLog(now time.Time) bool {
	return s.allowLog(&s.diagLog, now)
}

// allowLog 让同一类日志每分钟最多输出一次（now 可能是历史时间，只与自身比较）。
func (s *ResourceStore) allowLog(target *atomic.Int64, now time.Time) bool {
	reference := now.UnixNano()
	next := now.Add(time.Minute).UnixNano()
	prev := target.Load()
	if prev >= reference {
		return false
	}
	return target.CompareAndSwap(prev, next)
}

type resourceAccumulator struct {
	cpu    *metricSeries
	memory *metricSeries
	rx     *metricSeries
	tx     *metricSeries
}

func newResourceAccumulator(bucketMillis int64) *resourceAccumulator {
	return &resourceAccumulator{
		cpu:    newMetricSeries(bucketMillis),
		memory: newMetricSeries(bucketMillis),
		rx:     newMetricSeries(bucketMillis),
		tx:     newMetricSeries(bucketMillis),
	}
}

func (a *resourceAccumulator) seriesFor(metricName string) *metricSeries {
	switch strings.TrimSpace(metricName) {
	case resourceCPUMetric:
		return a.cpu
	case resourceMemoryMetric:
		return a.memory
	case resourceRxMetric:
		return a.rx
	case resourceTxMetric:
		return a.tx
	}
	return nil
}

func (a *resourceAccumulator) eachTime(visit func(int64)) {
	if a == nil {
		return
	}
	for _, series := range [...]*metricSeries{a.cpu, a.memory, a.rx, a.tx} {
		series.eachTime(visit)
	}
}

// NewEmptyResourceHistoryEntry 返回各数组均为空切片的资源历史（JSON 输出 []）。
func NewEmptyResourceHistoryEntry() *ResourceHistoryEntry {
	return &ResourceHistoryEntry{
		Times:         []int64{},
		CPU:           []*float64{},
		Memory:        []*float64{},
		RxBytesPerSec: []*float64{},
		TxBytesPerSec: []*float64{},
	}
}

func buildResourceHistoryEntry(accumulator *resourceAccumulator) *ResourceHistoryEntry {
	entry := NewEmptyResourceHistoryEntry()
	if accumulator == nil {
		return entry
	}
	timeSet := make(map[int64]struct{}, 4*maxPointsPerSeries)
	accumulator.eachTime(func(ts int64) {
		timeSet[ts] = struct{}{}
	})
	if len(timeSet) == 0 {
		return entry
	}

	times := make([]int64, 0, len(timeSet))
	for ts := range timeSet {
		times = append(times, ts)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	entry.Times = times
	entry.CPU = cloneHistorySeriesValues(accumulator.cpu, times)
	entry.Memory = cloneHistorySeriesValues(accumulator.memory, times)
	entry.RxBytesPerSec = cloneHistorySeriesValues(accumulator.rx, times)
	entry.TxBytesPerSec = cloneHistorySeriesValues(accumulator.tx, times)
	return entry
}

func defaultResourceStoreDir(dataDir string) string {
	return filepath.Join(dataDir, "history", "resource")
}
