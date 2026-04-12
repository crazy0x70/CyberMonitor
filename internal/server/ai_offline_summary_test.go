package server

import (
	"testing"
	"time"
)

func TestBuildAIOfflineSummaryIncludesAggregatesAndRecentSessions(t *testing.T) {
	t.Parallel()

	store := newHistoryIntegratedStore(t)
	now := time.Unix(1_960_000_000, 0).UTC()
	events := []struct {
		recoveredAt time.Time
		duration    time.Duration
	}{
		{recoveredAt: now.Add(-45 * 24 * time.Hour), duration: 5 * time.Minute},
		{recoveredAt: now.Add(-20 * 24 * time.Hour), duration: 15 * time.Minute},
		{recoveredAt: now.Add(-5 * 24 * time.Hour), duration: 7 * time.Minute},
		{recoveredAt: now.Add(-24 * time.Hour), duration: 3 * time.Minute},
	}
	for _, event := range events {
		seedOfflineHistoryStore(t, store, "node-1", event.recoveredAt, event.duration)
	}
	seedOfflineHistoryStore(t, store, "node-2", now.Add(-2*time.Hour), 99*time.Minute)

	summary := buildAIOfflineSummary(store, "node-1", now)
	if summary == nil {
		t.Fatal("expected offline summary to be populated")
	}
	if summary.TotalCount != 4 {
		t.Fatalf("expected total_count 4, got %d", summary.TotalCount)
	}
	if summary.Last30dCount != 3 {
		t.Fatalf("expected last_30d_count 3, got %d", summary.Last30dCount)
	}
	if summary.LongestDurationSec != 900 {
		t.Fatalf("expected longest_duration_sec 900, got %v", summary.LongestDurationSec)
	}
	if summary.AvgDurationSec != 450 {
		t.Fatalf("expected avg_duration_sec 450, got %v", summary.AvgDurationSec)
	}
	if summary.LastOfflineRecoveredAt != events[len(events)-1].recoveredAt.Unix() {
		t.Fatalf("expected last_offline_recovered_at %d, got %d", events[len(events)-1].recoveredAt.Unix(), summary.LastOfflineRecoveredAt)
	}
	if len(summary.RecentSessions) != 3 {
		t.Fatalf("expected 3 recent sessions, got %d", len(summary.RecentSessions))
	}

	expectedRecent := []struct {
		recoveredAt int64
		durationSec float64
	}{
		{recoveredAt: events[3].recoveredAt.Unix(), durationSec: 180},
		{recoveredAt: events[2].recoveredAt.Unix(), durationSec: 420},
		{recoveredAt: events[1].recoveredAt.Unix(), durationSec: 900},
	}
	for idx, want := range expectedRecent {
		got := summary.RecentSessions[idx]
		if got.RecoveredAt != want.recoveredAt {
			t.Fatalf("recent session %d: expected recovered_at %d, got %d", idx, want.recoveredAt, got.RecoveredAt)
		}
		if got.DurationSec != want.durationSec {
			t.Fatalf("recent session %d: expected duration_sec %v, got %v", idx, want.durationSec, got.DurationSec)
		}
		expectedStartedAt := time.Unix(want.recoveredAt, 0).UTC().Add(-time.Duration(want.durationSec * float64(time.Second))).Unix()
		if got.StartedAt != expectedStartedAt {
			t.Fatalf("recent session %d: expected started_at %d, got %d", idx, expectedStartedAt, got.StartedAt)
		}
	}
}

func TestBuildAIOfflineSummaryReturnsZeroSummaryWhenNoEventsExist(t *testing.T) {
	t.Parallel()

	store := newHistoryIntegratedStore(t)
	now := time.Unix(1_970_000_000, 0).UTC()

	summary := buildAIOfflineSummary(store, "node-1", now)
	if summary == nil {
		t.Fatal("expected zero-value offline summary instead of nil")
	}
	if summary.TotalCount != 0 || summary.Last30dCount != 0 {
		t.Fatalf("expected zero counts, got total=%d last_30d=%d", summary.TotalCount, summary.Last30dCount)
	}
	if summary.LongestDurationSec != 0 || summary.AvgDurationSec != 0 {
		t.Fatalf("expected zero durations, got longest=%v avg=%v", summary.LongestDurationSec, summary.AvgDurationSec)
	}
	if summary.LastOfflineRecoveredAt != 0 {
		t.Fatalf("expected zero last_offline_recovered_at, got %d", summary.LastOfflineRecoveredAt)
	}
	if len(summary.RecentSessions) != 0 {
		t.Fatalf("expected no recent sessions, got %d", len(summary.RecentSessions))
	}
}
