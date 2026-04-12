package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestMigrateLegacyJSONIfNeededImportsQueryableSeries(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := newTestNetworkStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	legacyPath := filepath.Join(tempDir, "test_history.json")

	writeLegacyHistoryPayload(t, legacyPath, map[string]any{
		"version":    1,
		"updated_at": now.Unix(),
		"nodes": map[string]any{
			"node-a": map[string]any{
				"tcp|example.com|443|https": map[string]any{
					"latency": []any{12.5, 18.75},
					"loss":    []any{0.0, 2.5},
					"times": []int64{
						now.Add(-48 * time.Hour).Unix(),
						now.Add(-24 * time.Hour).Unix(),
					},
					"last_at":          now.Add(-24 * time.Hour).Unix(),
					"min_interval_sec": 86400,
					"avg_interval_sec": 86400,
				},
			},
		},
	})

	result, err := MigrateLegacyJSONIfNeeded(legacyPath, store, now)
	if err != nil {
		t.Fatalf("migrate legacy json: %v", err)
	}
	if !result.LegacyFound {
		t.Fatal("expected migration to detect legacy payload")
	}
	if result.SourcePath != legacyPath {
		t.Fatalf("expected source path %q, got %q", legacyPath, result.SourcePath)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("expected legacy file to remain available until finalize: %v", err)
	}

	got, err := store.QueryRange("node-a", now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("query migrated history: %v", err)
	}
	entry := got["tcp|example.com|443|https"]
	if entry == nil {
		t.Fatalf("expected migrated series to be queryable, got keys=%v", mapKeys(got))
	}
	if len(entry.Times) != 2 {
		t.Fatalf("expected 2 migrated samples, got %d", len(entry.Times))
	}
	if entry.Latency[0] == nil || *entry.Latency[0] != 12.5 {
		t.Fatalf("expected first latency sample 12.5, got %+v", entry.Latency)
	}
	if entry.Availability[0] == nil || *entry.Availability[0] != 1 {
		t.Fatalf("expected first availability sample to be 1, got %+v", entry.Availability)
	}
}

func TestMigrateLegacyJSONIfNeededDerivesUnavailableAvailabilityFromLegacyFailureSample(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := newTestNetworkStore(t)
	now := time.Unix(1_810_000_000, 0).UTC()
	legacyPath := filepath.Join(tempDir, "test_history.json")

	writeLegacyHistoryPayload(t, legacyPath, map[string]any{
		"nodes": map[string]any{
			"node-a": map[string]any{
				"icmp|1.1.1.1|0|edge": map[string]any{
					"latency": []any{nil},
					"loss":    []any{100.0},
					"times":   []int64{now.Add(-time.Hour).Unix()},
					"last_at": now.Add(-time.Hour).Unix(),
				},
			},
		},
	})

	if _, err := MigrateLegacyJSONIfNeeded(legacyPath, store, now); err != nil {
		t.Fatalf("migrate legacy json: %v", err)
	}

	got, err := store.QueryRange("node-a", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("query migrated history: %v", err)
	}
	entry := got["icmp|1.1.1.1|0|edge"]
	if entry == nil {
		t.Fatalf("expected migrated failure series to exist, got keys=%v", mapKeys(got))
	}
	if len(entry.Availability) != 1 || entry.Availability[0] == nil {
		t.Fatalf("expected one derived availability sample, got %+v", entry.Availability)
	}
	if *entry.Availability[0] != 0 {
		t.Fatalf("expected derived availability 0 for failure sample, got %v", *entry.Availability[0])
	}
}

func TestMigrateLegacyJSONIfNeededSkipsSamplesOutsideRetentionWindow(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := newTestNetworkStore(t)
	now := time.Unix(1_860_000_000, 0).UTC()
	legacyPath := filepath.Join(tempDir, "test_history.json")
	oldSampleAt := now.Add(-(networkRetentionDays*24*time.Hour + 24*time.Hour)).Unix()
	retainedSampleAt := now.Add(-24 * time.Hour).Unix()

	writeLegacyHistoryPayload(t, legacyPath, map[string]any{
		"nodes": map[string]any{
			"node-a": map[string]any{
				"tcp|example.com|443|retained": map[string]any{
					"latency": []any{11.0, 22.0},
					"loss":    []any{0.0, 0.0},
					"times":   []int64{oldSampleAt, retainedSampleAt},
					"last_at": retainedSampleAt,
				},
			},
		},
	})

	if _, err := MigrateLegacyJSONIfNeeded(legacyPath, store, now); err != nil {
		t.Fatalf("migrate legacy json with stale sample: %v", err)
	}

	got, err := store.QueryRange("node-a", now.Add(-(networkRetentionDays+7)*24*time.Hour), now)
	if err != nil {
		t.Fatalf("query migrated history: %v", err)
	}
	entry := got["tcp|example.com|443|retained"]
	if entry == nil {
		t.Fatalf("expected retained series to remain queryable, got keys=%v", mapKeys(got))
	}
	if len(entry.Times) != 1 {
		t.Fatalf("expected only in-window sample to remain, got %d", len(entry.Times))
	}
	if entry.Times[0] != retainedSampleAt {
		t.Fatalf("expected retained timestamp %d, got %d", retainedSampleAt, entry.Times[0])
	}
}

func TestMigrateLegacyJSONIfNeededIsRetrySafeAfterPartialMigration(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backingStore := newTestNetworkStore(t)
	now := time.Unix(1_820_000_000, 0).UTC()
	legacyPath := filepath.Join(tempDir, "test_history.json")

	writeLegacyHistoryPayload(t, legacyPath, map[string]any{
		"nodes": map[string]any{
			"node-a": map[string]any{
				"icmp|1.1.1.1|0|a": map[string]any{
					"latency": []any{11.0},
					"loss":    []any{0.0},
					"times":   []int64{now.Add(-2 * time.Hour).Unix()},
					"last_at": now.Add(-2 * time.Hour).Unix(),
				},
				"icmp|8.8.8.8|0|b": map[string]any{
					"latency": []any{22.0},
					"loss":    []any{0.0},
					"times":   []int64{now.Add(-time.Hour).Unix()},
					"last_at": now.Add(-time.Hour).Unix(),
				},
			},
		},
	})

	flaky := &flakyMigrationStore{
		inner:      backingStore,
		failOnCall: 2,
	}
	if _, err := MigrateLegacyJSONIfNeeded(legacyPath, flaky, now); err == nil {
		t.Fatal("expected first migration attempt to fail")
	}

	firstPass, err := backingStore.QueryRange("node-a", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("query after failed migration: %v", err)
	}
	if len(firstPass) != 1 {
		t.Fatalf("expected one migrated series after partial failure, got %d", len(firstPass))
	}

	result, err := MigrateLegacyJSONIfNeeded(legacyPath, backingStore, now)
	if err != nil {
		t.Fatalf("retry migration: %v", err)
	}
	if !result.LegacyFound {
		t.Fatal("expected retry to still consume legacy payload")
	}

	secondPass, err := backingStore.QueryRange("node-a", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("query after retry migration: %v", err)
	}
	if len(secondPass) != 2 {
		t.Fatalf("expected both series after retry, got %d", len(secondPass))
	}
	if got := len(secondPass["icmp|1.1.1.1|0|a"].Times); got != 1 {
		t.Fatalf("expected first series to keep one deduplicated sample, got %d", got)
	}
	if got := len(secondPass["icmp|8.8.8.8|0|b"].Times); got != 1 {
		t.Fatalf("expected second series to be migrated on retry, got %d", got)
	}
}

func TestEnsureLegacyMigrationBackupAndMarkerAreRecoverable(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	legacyPath := filepath.Join(tempDir, "test_history.json")
	const payload = `{"nodes":{"node-a":{}}}`
	if err := os.WriteFile(legacyPath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	if err := EnsureLegacyMigrationBackup(legacyPath); err != nil {
		t.Fatalf("ensure backup: %v", err)
	}
	backupData, err := os.ReadFile(legacyBackupPath(legacyPath))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupData) != payload {
		t.Fatalf("expected backup payload %q, got %q", payload, string(backupData))
	}

	now := time.Unix(1_830_000_000, 0).UTC()
	if err := MarkLegacyMigrationComplete(legacyPath, now); err != nil {
		t.Fatalf("mark migration complete: %v", err)
	}
	markerData, err := os.ReadFile(legacyMarkerPath(legacyPath))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if len(markerData) == 0 {
		t.Fatal("expected marker file to contain completion timestamp")
	}
}

func TestMigrateLegacyJSONIfNeededRecoversFromBackupUntilCompletionMarker(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := newTestNetworkStore(t)
	now := time.Unix(1_835_000_000, 0).UTC()
	legacyPath := filepath.Join(tempDir, "test_history.json")

	writeLegacyHistoryPayload(t, legacyPath, map[string]any{
		"nodes": map[string]any{
			"node-a": map[string]any{
				"icmp|9.9.9.9|0|backup": map[string]any{
					"latency": []any{33.0},
					"loss":    []any{0.0},
					"times":   []int64{now.Add(-time.Hour).Unix()},
					"last_at": now.Add(-time.Hour).Unix(),
				},
			},
		},
	})

	if err := EnsureLegacyMigrationBackup(legacyPath); err != nil {
		t.Fatalf("ensure backup before recovery test: %v", err)
	}
	if err := os.Remove(legacyPath); err != nil {
		t.Fatalf("remove primary legacy path: %v", err)
	}

	result, err := MigrateLegacyJSONIfNeeded(legacyPath, store, now)
	if err != nil {
		t.Fatalf("migrate from backup: %v", err)
	}
	if !result.LegacyFound {
		t.Fatal("expected backup copy to remain recoverable before completion marker")
	}
	if result.SourcePath != legacyBackupPath(legacyPath) {
		t.Fatalf("expected migration to load from backup %q, got %q", legacyBackupPath(legacyPath), result.SourcePath)
	}

	firstPass, err := store.QueryRange("node-a", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("query migrated backup history: %v", err)
	}
	if got := len(firstPass["icmp|9.9.9.9|0|backup"].Times); got != 1 {
		t.Fatalf("expected one migrated sample from backup, got %d", got)
	}

	if err := MarkLegacyMigrationComplete(legacyPath, now); err != nil {
		t.Fatalf("mark migration complete: %v", err)
	}

	skipped, err := MigrateLegacyJSONIfNeeded(legacyPath, store, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("migrate after marker: %v", err)
	}
	if skipped.LegacyFound {
		t.Fatalf("expected completion marker to suppress backup replay, got %+v", skipped)
	}

	secondPass, err := store.QueryRange("node-a", now.Add(-24*time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("query history after marker: %v", err)
	}
	if got := len(secondPass["icmp|9.9.9.9|0|backup"].Times); got != 1 {
		t.Fatalf("expected marker to avoid duplicate backup replay, got %d samples", got)
	}
}

func writeLegacyHistoryPayload(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy payload: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy payload: %v", err)
	}
}

type flakyMigrationStore struct {
	inner      networkHistoryStore
	callCount  int
	failOnCall int
}

func (s *flakyMigrationStore) AppendBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error {
	s.callCount++
	if s.callCount == s.failOnCall {
		return errors.New("injected migration append failure")
	}
	return s.inner.AppendBatch(nodeID, tests, now)
}

func (s *flakyMigrationStore) QueryRange(nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error) {
	return s.inner.QueryRange(nodeID, from, to)
}
