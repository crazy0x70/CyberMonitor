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
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || to.Before(from) {
		return OfflineSummary{}, nil
	}

	sessions, err := s.querySessions(nodeID, from, to)
	if err != nil {
		return OfflineSummary{}, err
	}

	var (
		summary   OfflineSummary
		totalSecs float64
	)
	for _, session := range sessions {
		summary.TotalCount++
		totalSecs += session.DurationSec
		if session.DurationSec > summary.LongestDurationSec {
			summary.LongestDurationSec = session.DurationSec
		}
		if summary.LastOfflineRecoveredAt.IsZero() || session.RecoveredAt.After(summary.LastOfflineRecoveredAt) {
			summary.LastOfflineRecoveredAt = session.RecoveredAt
		}
	}
	if summary.TotalCount > 0 {
		summary.AvgDurationSec = totalSecs / float64(summary.TotalCount)
	}
	return summary, nil
}

func (s *OfflineStore) QueryRecentSessions(nodeID string, from, to time.Time, limit int) ([]OfflineSession, error) {
	if s == nil || s.db == nil {
		return nil, errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || to.Before(from) || limit <= 0 {
		return nil, nil
	}

	sessions, err := s.querySessions(nodeID, from, to)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, nil
	}
	if limit > len(sessions) {
		limit = len(sessions)
	}
	recent := make([]OfflineSession, 0, limit)
	for i := len(sessions) - 1; i >= 0 && len(recent) < limit; i-- {
		recent = append(recent, sessions[i])
	}
	return recent, nil
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

	allTime, err := s.QuerySummary(nodeID, time.Unix(0, 0).UTC(), now)
	if err != nil {
		return OfflineInsights{}, err
	}
	last30d, err := s.QuerySummary(nodeID, now.Add(-30*24*time.Hour), now)
	if err != nil {
		return OfflineInsights{}, err
	}
	recentSessions, err := s.QueryRecentSessions(nodeID, time.Unix(0, 0).UTC(), now, recentLimit)
	if err != nil {
		return OfflineInsights{}, err
	}
	return OfflineInsights{
		TotalCount:             allTime.TotalCount,
		Last30dCount:           last30d.TotalCount,
		LongestDurationSec:     allTime.LongestDurationSec,
		AvgDurationSec:         allTime.AvgDurationSec,
		LastOfflineRecoveredAt: allTime.LastOfflineRecoveredAt,
		RecentSessions:         recentSessions,
	}, nil
}

func (s *OfflineStore) querySessions(nodeID string, from, to time.Time) ([]OfflineSession, error) {
	if s == nil || s.db == nil {
		return nil, errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || to.Before(from) {
		return nil, nil
	}

	querier, err := s.db.Querier(from.UnixMilli(), to.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer querier.Close()

	nameMatcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, offlineDurationMetric)
	if err != nil {
		return nil, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return nil, err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: from.UnixMilli(),
		End:   to.UnixMilli(),
	}, nameMatcher, nodeMatcher)

	sessions := make([]OfflineSession, 0)
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
			sessions = append(sessions, OfflineSession{
				StartedAt:   recoveredAt.Add(-duration),
				RecoveredAt: recoveredAt,
				DurationSec: value,
			})
		}
		if err := iterator.Err(); err != nil {
			return nil, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
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
	querier, err := s.db.Querier(mint, math.MaxInt64)
	if err != nil {
		return false, err
	}
	defer querier.Close()

	nameMatcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, offlineDurationMetric)
	if err != nil {
		return false, err
	}
	nodeMatcher, err := labels.NewMatcher(labels.MatchEqual, "node_id", nodeID)
	if err != nil {
		return false, err
	}

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: mint,
		End:   math.MaxInt64,
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
			duration := time.Duration(math.Round(value * float64(time.Second)))
			if duration <= 0 {
				continue
			}
			recoveredAt := time.UnixMilli(tsMillis).UTC()
			derivedStartedAt := normalizeOfflineSessionStartedAt(recoveredAt.Add(-duration))
			if derivedStartedAt.Equal(targetStartedAt) {
				return true, nil
			}
		}
		if err := iterator.Err(); err != nil {
			return false, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return false, err
	}
	return false, nil
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
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher)
}

func (s *OfflineStore) Clear() error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	matcher, err := labels.NewMatcher(labels.MatchEqual, labels.MetricName, offlineDurationMetric)
	if err != nil {
		return err
	}
	return s.db.Delete(context.Background(), math.MinInt64, math.MaxInt64, matcher)
}

func defaultOfflineStoreDir(dataDir string) string {
	return filepath.Join(dataDir, "history", "offline")
}
