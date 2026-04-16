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

	var (
		summary   OfflineSummary
		totalSecs float64
	)
	err := s.scanSessions(nodeID, from, to, func(session OfflineSession) bool {
		summary.TotalCount++
		totalSecs += session.DurationSec
		if session.DurationSec > summary.LongestDurationSec {
			summary.LongestDurationSec = session.DurationSec
		}
		if summary.LastOfflineRecoveredAt.IsZero() || session.RecoveredAt.After(summary.LastOfflineRecoveredAt) {
			summary.LastOfflineRecoveredAt = session.RecoveredAt
		}
		return true
	})
	if err != nil {
		return OfflineSummary{}, err
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

	recent := make([]OfflineSession, 0, limit)
	if err := s.scanSessions(nodeID, from, to, func(session OfflineSession) bool {
		recent = appendRecentSession(recent, session, limit)
		return true
	}); err != nil {
		return nil, err
	}
	if len(recent) == 0 {
		return nil, nil
	}
	return reverseOfflineSessions(recent), nil
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
		insights  OfflineInsights
		totalSecs float64
		recent    []OfflineSession
	)
	err := s.scanSessions(nodeID, time.Unix(0, 0).UTC(), now, func(session OfflineSession) bool {
		insights.TotalCount++
		totalSecs += session.DurationSec
		if session.DurationSec > insights.LongestDurationSec {
			insights.LongestDurationSec = session.DurationSec
		}
		if insights.LastOfflineRecoveredAt.IsZero() || session.RecoveredAt.After(insights.LastOfflineRecoveredAt) {
			insights.LastOfflineRecoveredAt = session.RecoveredAt
		}
		if !session.RecoveredAt.Before(last30dStart) && !session.RecoveredAt.After(now) {
			insights.Last30dCount++
		}
		if recentLimit > 0 {
			recent = appendRecentSession(recent, session, recentLimit)
		}
		return true
	})
	if err != nil {
		return OfflineInsights{}, err
	}
	if insights.TotalCount > 0 {
		insights.AvgDurationSec = totalSecs / float64(insights.TotalCount)
	}
	if len(recent) > 0 {
		insights.RecentSessions = reverseOfflineSessions(recent)
	}
	return insights, nil
}

func (s *OfflineStore) querySessions(nodeID string, from, to time.Time) ([]OfflineSession, error) {
	sessions := make([]OfflineSession, 0)
	if err := s.scanSessions(nodeID, from, to, func(session OfflineSession) bool {
		sessions = append(sessions, session)
		return true
	}); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *OfflineStore) scanSessions(nodeID string, from, to time.Time, visit func(OfflineSession) bool) error {
	if s == nil || s.db == nil {
		return errNilOfflineStore
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || to.Before(from) {
		return nil
	}

	querier, err := s.db.Querier(from.UnixMilli(), to.UnixMilli())
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
		Start: from.UnixMilli(),
		End:   to.UnixMilli(),
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

func appendRecentSession(recent []OfflineSession, session OfflineSession, limit int) []OfflineSession {
	if limit <= 0 {
		return recent
	}
	if len(recent) < limit {
		return append(recent, session)
	}
	copy(recent, recent[1:])
	recent[len(recent)-1] = session
	return recent
}

func reverseOfflineSessions(sessions []OfflineSession) []OfflineSession {
	reversed := make([]OfflineSession, 0, len(sessions))
	for i := len(sessions) - 1; i >= 0; i-- {
		reversed = append(reversed, sessions[i])
	}
	return reversed
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
