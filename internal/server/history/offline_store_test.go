package history

import (
	"testing"
	"time"
)

func TestOfflineStoreQuerySummarySingleEvent(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	recoveredAt := time.Unix(1_900_000_000, 0).UTC()

	if err := store.AppendEvent("node-a", recoveredAt, 12*time.Minute); err != nil {
		t.Fatalf("append offline event: %v", err)
	}

	summary, err := store.QuerySummary("node-a", recoveredAt.Add(-time.Hour), recoveredAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if summary.TotalCount != 1 {
		t.Fatalf("expected total count 1, got %d", summary.TotalCount)
	}
	if summary.LongestDurationSec != 720 {
		t.Fatalf("expected longest duration 720 seconds, got %v", summary.LongestDurationSec)
	}
	if summary.AvgDurationSec != 720 {
		t.Fatalf("expected average duration 720 seconds, got %v", summary.AvgDurationSec)
	}
	if !summary.LastOfflineRecoveredAt.Equal(recoveredAt) {
		t.Fatalf("expected last recovered at %s, got %s", recoveredAt, summary.LastOfflineRecoveredAt)
	}
}

func TestOfflineStoreQuerySummaryMultipleEvents(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	base := time.Unix(1_910_000_000, 0).UTC()

	events := []struct {
		recoveredAt time.Time
		duration    time.Duration
	}{
		{recoveredAt: base.Add(-48 * time.Hour), duration: 4 * time.Minute},
		{recoveredAt: base.Add(-24 * time.Hour), duration: 10 * time.Minute},
		{recoveredAt: base, duration: 16 * time.Minute},
	}
	for _, event := range events {
		if err := store.AppendEvent("node-a", event.recoveredAt, event.duration); err != nil {
			t.Fatalf("append offline event at %s: %v", event.recoveredAt, err)
		}
	}

	summary, err := store.QuerySummary("node-a", base.Add(-7*24*time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if summary.TotalCount != len(events) {
		t.Fatalf("expected total count %d, got %d", len(events), summary.TotalCount)
	}
	if summary.LongestDurationSec != 960 {
		t.Fatalf("expected longest duration 960 seconds, got %v", summary.LongestDurationSec)
	}
	if summary.AvgDurationSec != 600 {
		t.Fatalf("expected average duration 600 seconds, got %v", summary.AvgDurationSec)
	}
	if !summary.LastOfflineRecoveredAt.Equal(base) {
		t.Fatalf("expected last recovered at %s, got %s", base, summary.LastOfflineRecoveredAt)
	}
}

func TestOfflineStoreDoesNotApplyNetworkRetentionWindow(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	base := time.Unix(1_920_000_000, 0).UTC()
	oldRecoveredAt := base.Add(-500 * 24 * time.Hour)

	if err := store.AppendEvent("node-a", oldRecoveredAt, 3*time.Hour); err != nil {
		t.Fatalf("append old offline event: %v", err)
	}
	if err := store.AppendEvent("node-a", base, 30*time.Minute); err != nil {
		t.Fatalf("append recent offline event: %v", err)
	}

	summary, err := store.QuerySummary("node-a", oldRecoveredAt.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if summary.TotalCount != 2 {
		t.Fatalf("expected permanent retention to keep 2 events, got %d", summary.TotalCount)
	}
	if summary.LongestDurationSec != 10_800 {
		t.Fatalf("expected longest duration 10800 seconds, got %v", summary.LongestDurationSec)
	}
}

func TestOfflineStoreQueryRecentSessionsReturnsMostRecentFirst(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	base := time.Unix(1_925_000_000, 0).UTC()
	events := []struct {
		recoveredAt time.Time
		duration    time.Duration
	}{
		{recoveredAt: base.Add(-72 * time.Hour), duration: 4 * time.Minute},
		{recoveredAt: base.Add(-24 * time.Hour), duration: 10 * time.Minute},
		{recoveredAt: base, duration: 16 * time.Minute},
	}
	for _, event := range events {
		if err := store.AppendEvent("node-a", event.recoveredAt, event.duration); err != nil {
			t.Fatalf("append offline event at %s: %v", event.recoveredAt, err)
		}
	}

	sessions, err := store.QueryRecentSessions("node-a", base.Add(-7*24*time.Hour), base.Add(time.Hour), 2)
	if err != nil {
		t.Fatalf("query recent sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 recent sessions, got %d", len(sessions))
	}
	if !sessions[0].RecoveredAt.Equal(events[2].recoveredAt) {
		t.Fatalf("expected most recent recovered_at %s, got %s", events[2].recoveredAt, sessions[0].RecoveredAt)
	}
	if sessions[0].DurationSec != 960 {
		t.Fatalf("expected most recent duration 960, got %v", sessions[0].DurationSec)
	}
	if !sessions[1].RecoveredAt.Equal(events[1].recoveredAt) {
		t.Fatalf("expected second recovered_at %s, got %s", events[1].recoveredAt, sessions[1].RecoveredAt)
	}
}

func TestOfflineStoreQueryInsightsIncludesRecentSessionsAndLast30dCount(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	now := time.Unix(1_926_000_000, 0).UTC()
	events := []struct {
		recoveredAt time.Time
		duration    time.Duration
	}{
		{recoveredAt: now.Add(-45 * 24 * time.Hour), duration: 5 * time.Minute},
		{recoveredAt: now.Add(-20 * 24 * time.Hour), duration: 15 * time.Minute},
		{recoveredAt: now.Add(-5 * 24 * time.Hour), duration: 7 * time.Minute},
	}
	for _, event := range events {
		if err := store.AppendEvent("node-a", event.recoveredAt, event.duration); err != nil {
			t.Fatalf("append offline event at %s: %v", event.recoveredAt, err)
		}
	}

	insights, err := store.QueryInsights("node-a", now, 2)
	if err != nil {
		t.Fatalf("query insights: %v", err)
	}
	if insights.TotalCount != 3 {
		t.Fatalf("expected total_count 3, got %d", insights.TotalCount)
	}
	if insights.Last30dCount != 2 {
		t.Fatalf("expected last_30d_count 2, got %d", insights.Last30dCount)
	}
	if insights.LongestDurationSec != 900 {
		t.Fatalf("expected longest_duration_sec 900, got %v", insights.LongestDurationSec)
	}
	if len(insights.RecentSessions) != 2 {
		t.Fatalf("expected 2 recent sessions, got %d", len(insights.RecentSessions))
	}
	if !insights.RecentSessions[0].RecoveredAt.Equal(events[2].recoveredAt) {
		t.Fatalf("expected most recent recovered_at %s, got %s", events[2].recoveredAt, insights.RecentSessions[0].RecoveredAt)
	}
}

func TestOfflineStoreHasEventForSessionMatchesSubsecondRecoveryOfSameSession(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	startedAt := time.Unix(1_930_000_000, 0).UTC()
	recoveredAt := startedAt.Add(9*time.Minute + 250*time.Millisecond + 750*time.Microsecond)

	if err := store.AppendEvent("node-a", recoveredAt, recoveredAt.Sub(startedAt)); err != nil {
		t.Fatalf("append offline event: %v", err)
	}

	hasEvent, err := store.HasEventForSession("node-a", startedAt)
	if err != nil {
		t.Fatalf("has event for session: %v", err)
	}
	if !hasEvent {
		t.Fatal("expected same session with subsecond recovery timestamp to be found")
	}
}

func TestOfflineStoreHasEventForSessionDoesNotMatchAdjacentSecondSession(t *testing.T) {
	t.Parallel()

	store := newTestOfflineStore(t)
	targetStartedAt := time.Unix(1_931_000_000, 0).UTC()
	laterStartedAt := targetStartedAt.Add(time.Second)
	recoveredAt := laterStartedAt.Add(9*time.Minute + 250*time.Millisecond + 750*time.Microsecond)

	if err := store.AppendEvent("node-a", recoveredAt, recoveredAt.Sub(laterStartedAt)); err != nil {
		t.Fatalf("append offline event: %v", err)
	}

	hasEvent, err := store.HasEventForSession("node-a", targetStartedAt)
	if err != nil {
		t.Fatalf("has event for session: %v", err)
	}
	if hasEvent {
		t.Fatal("expected adjacent-second session identity to remain distinct")
	}
}

func newTestOfflineStore(t *testing.T) *OfflineStore {
	t.Helper()

	store, err := OpenOfflineStore(t.TempDir())
	if err != nil {
		t.Fatalf("open offline store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close offline store: %v", err)
		}
	})
	return store
}
