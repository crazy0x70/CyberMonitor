package history

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

const offlineDurationMetric = "cm_node_offline_duration_seconds"

var errNilOfflineStore = errors.New("offline history store is nil")

type OfflineSummary struct {
	TotalCount             int
	LongestDurationSec     float64
	AvgDurationSec         float64
	LastOfflineRecoveredAt time.Time
}

type OfflineSession struct {
	StartedAt   time.Time
	RecoveredAt time.Time
	DurationSec float64
}

type OfflineInsights struct {
	TotalCount             int
	Last30dCount           int
	LongestDurationSec     float64
	AvgDurationSec         float64
	LastOfflineRecoveredAt time.Time
	RecentSessions         []OfflineSession
}

type OfflineStore struct {
	db  *tsdb.DB
	dir string
}

func OpenOfflineStore(dir string) (*OfflineStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("offline history dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = 0

	db, err := tsdb.Open(dir, nil, nil, opts, nil)
	if err != nil {
		return nil, err
	}
	return &OfflineStore{
		db:  db,
		dir: dir,
	}, nil
}

func (s *OfflineStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *OfflineStore) AppendEvent(nodeID string, recoveredAt time.Time, duration time.Duration) error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || duration <= 0 {
		return nil
	}

	appender := s.db.Appender(context.Background())
	committed := false
	defer func() {
		if !committed {
			_ = appender.Rollback()
		}
	}()

	if _, err := appender.Append(0, labels.FromStrings(
		labels.MetricName, offlineDurationMetric,
		"node_id", nodeID,
	), recoveredAt.UTC().UnixMilli(), duration.Seconds()); err != nil {
		return err
	}

	if err := appender.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *OfflineStore) QuerySummary(nodeID string, from, to time.Time) (OfflineSummary, error) {
	if s == nil || s.db == nil {
		return OfflineSummary{}, errNilOfflineStore
	}

	var stats offlineSessionStats
	if err := s.collectSessions(nodeID, from, to, &stats, nil, nil); err != nil {
		return OfflineSummary{}, err
	}
	return stats.Summary(), nil
}

func (s *OfflineStore) QueryRecentSessions(nodeID string, from, to time.Time, limit int) ([]OfflineSession, error) {
	if s == nil || s.db == nil {
		return nil, errNilOfflineStore
	}
	if limit <= 0 {
		return nil, nil
	}

	recent := newRecentOfflineSessions(limit)
	if err := s.collectSessions(nodeID, from, to, nil, recent, nil); err != nil {
		return nil, err
	}
	return recent.NewestFirst(), nil
}

func (s *OfflineStore) QueryInsights(nodeID string, now time.Time, recentLimit int) (OfflineInsights, error) {
	if s == nil || s.db == nil {
		return OfflineInsights{}, errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return OfflineInsights{}, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	last30dStart := now.Add(-30 * 24 * time.Hour)

	var (
		insights OfflineInsights
		stats    offlineSessionStats
		recent   *recentOfflineSessions
	)
	if recentLimit > 0 {
		recent = newRecentOfflineSessions(recentLimit)
	}
	if err := s.collectSessions(nodeID, time.Unix(0, 0).UTC(), now, &stats, recent, func(session OfflineSession) {
		if !session.RecoveredAt.Before(last30dStart) && !session.RecoveredAt.After(now) {
			insights.Last30dCount++
		}
	}); err != nil {
		return OfflineInsights{}, err
	}
	stats.FillInsights(&insights)
	if recent != nil {
		insights.RecentSessions = recent.NewestFirst()
	}
	return insights, nil
}

func (s *OfflineStore) scanSessions(nodeID string, from, to time.Time, visit func(OfflineSession) bool) error {
	nodeID, ok, err := s.scanNodeID(nodeID)
	if err != nil {
		return err
	}
	if !ok || to.Before(from) {
		return nil
	}
	return s.scanSessionsMillis(nodeID, from.UnixMilli(), to.UnixMilli(), visit)
}

func (s *OfflineStore) scanSessionsMillis(nodeID string, mint, maxt int64, visit func(OfflineSession) bool) error {
	nodeID, ok, err := s.scanNodeID(nodeID)
	if err != nil {
		return err
	}
	if !ok || maxt < mint {
		return nil
	}

	querier, err := s.db.Querier(mint, maxt)
	if err != nil {
		return err
	}
	defer querier.Close()

	nameMatcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, offlineDurationMetric)
	if err != nil {
		return err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: mint,
		End:   maxt,
	}, nameMatcher, nodeMatcher)

	for seriesSet.Next() {
		iterator := seriesSet.At().Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType != chunkenc.ValFloat {
				continue
			}
			tsMillis, value := iterator.At()
			if math.IsNaN(value) || math.IsInf(value, 0) {
				continue
			}
			recoveredAt := time.UnixMilli(tsMillis).UTC()
			duration := time.Duration(math.Round(value * float64(time.Second)))
			if visit != nil && !visit(OfflineSession{
				StartedAt:   recoveredAt.Add(-duration),
				RecoveredAt: recoveredAt,
				DurationSec: value,
			}) {
				return nil
			}
		}
		if err := iterator.Err(); err != nil {
			return err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return err
	}
	return nil
}

func (s *OfflineStore) scanNodeID(nodeID string) (string, bool, error) {
	if s == nil || s.db == nil {
		return "", false, errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", false, nil
	}
	return nodeID, true, nil
}

func (s *OfflineStore) collectSessions(
	nodeID string,
	from, to time.Time,
	stats *offlineSessionStats,
	recent *recentOfflineSessions,
	extra func(OfflineSession),
) error {
	return s.scanSessions(nodeID, from, to, func(session OfflineSession) bool {
		if stats != nil {
			stats.Append(session)
		}
		if recent != nil {
			recent.Append(session)
		}
		if extra != nil {
			extra(session)
		}
		return true
	})
}

type offlineSessionStats struct {
	totalCount             int
	totalSecs              float64
	longestDurationSec     float64
	lastOfflineRecoveredAt time.Time
}

func (stats *offlineSessionStats) Append(session OfflineSession) {
	if stats == nil {
		return
	}
	stats.totalCount++
	stats.totalSecs += session.DurationSec
	if session.DurationSec > stats.longestDurationSec {
		stats.longestDurationSec = session.DurationSec
	}
	if stats.lastOfflineRecoveredAt.IsZero() || session.RecoveredAt.After(stats.lastOfflineRecoveredAt) {
		stats.lastOfflineRecoveredAt = session.RecoveredAt
	}
}

func (stats offlineSessionStats) AvgDurationSec() float64 {
	if stats.totalCount == 0 {
		return 0
	}
	return stats.totalSecs / float64(stats.totalCount)
}

func (stats offlineSessionStats) Summary() OfflineSummary {
	return OfflineSummary{
		TotalCount:             stats.totalCount,
		LongestDurationSec:     stats.longestDurationSec,
		AvgDurationSec:         stats.AvgDurationSec(),
		LastOfflineRecoveredAt: stats.lastOfflineRecoveredAt,
	}
}

func (stats offlineSessionStats) FillInsights(insights *OfflineInsights) {
	if insights == nil {
		return
	}
	insights.TotalCount = stats.totalCount
	insights.LongestDurationSec = stats.longestDurationSec
	insights.AvgDurationSec = stats.AvgDurationSec()
	insights.LastOfflineRecoveredAt = stats.lastOfflineRecoveredAt
}

type recentOfflineSessions struct {
	items []OfflineSession
	start int
	size  int
}

func newRecentOfflineSessions(limit int) *recentOfflineSessions {
	if limit <= 0 {
		return &recentOfflineSessions{}
	}
	return &recentOfflineSessions{
		items: make([]OfflineSession, limit),
	}
}

func (buffer *recentOfflineSessions) Append(session OfflineSession) {
	if buffer == nil || len(buffer.items) == 0 {
		return
	}
	index := (buffer.start + buffer.size) % len(buffer.items)
	if buffer.size < len(buffer.items) {
		buffer.items[index] = session
		buffer.size++
		return
	}
	buffer.items[buffer.start] = session
	buffer.start = (buffer.start + 1) % len(buffer.items)
}

func (buffer *recentOfflineSessions) NewestFirst() []OfflineSession {
	if buffer == nil || buffer.size == 0 {
		return nil
	}
	result := make([]OfflineSession, buffer.size)
	for index := 0; index < buffer.size; index++ {
		sourceIndex := (buffer.start + buffer.size - 1 - index + len(buffer.items)) % len(buffer.items)
		result[index] = buffer.items[sourceIndex]
	}
	return result
}

func (s *OfflineStore) HasEventForSession(nodeID string, startedAt time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || startedAt.IsZero() {
		return false, nil
	}

	targetStartedAt := normalizeOfflineSessionStartedAt(startedAt)
	mint := targetStartedAt.UnixMilli()
	found := false
	if err := s.scanSessionsMillis(nodeID, mint, math.MaxInt64, func(session OfflineSession) bool {
		if session.DurationSec <= 0 {
			return true
		}
		if normalizeOfflineSessionStartedAt(session.StartedAt).Equal(targetStartedAt) {
			found = true
			return false
		}
		return true
	}); err != nil {
		return false, err
	}
	return found, nil
}

func normalizeOfflineSessionStartedAt(startedAt time.Time) time.Time {
	return startedAt.UTC().Add(500 * time.Millisecond).Truncate(time.Second)
}

func (s *OfflineStore) DeleteNode(nodeID string) error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil
	}
	matcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return err
	}
	return s.deleteAll(matcher)
}

func (s *OfflineStore) Clear() error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	matcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, offlineDurationMetric)
	if err != nil {
		return err
	}
	return s.deleteAll(matcher)
}

func (s *OfflineStore) deleteAll(matchers ...*labels.Matcher) error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matchers...)
}

func defaultOfflineStoreDir(dataDir string) string {
	return filepath.Join(dataDir, "history", "offline")
}
