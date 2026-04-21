package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

type legacyHistoryEntry struct {
	Latency        []*float64 `json:"latency"`
	Loss           []*float64 `json:"loss"`
	Times          []int64    `json:"times"`
	LastAt         int64      `json:"last_at"`
	MinIntervalSec int64      `json:"min_interval_sec,omitempty"`
	AvgIntervalSec float64    `json:"avg_interval_sec,omitempty"`
}

type legacyHistoryPayload struct {
	Version   int                                       `json:"version"`
	UpdatedAt int64                                     `json:"updated_at,omitempty"`
	Nodes     map[string]map[string]*legacyHistoryEntry `json:"nodes,omitempty"`
}

type networkHistoryStore interface {
	AppendBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error
	QueryRange(nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error)
}

type LegacyMigrationResult struct {
	LegacyFound bool
	SourcePath  string
	BackupPath  string
	MarkerPath  string
	Migrated    bool
}

func MigrateLegacyJSONIfNeeded(path string, store networkHistoryStore, now time.Time) (LegacyMigrationResult, error) {
	if store == nil {
		return LegacyMigrationResult{}, errNilNetworkStore
	}
	legacyPath, err := normalizeLegacyHistoryPath(path)
	if err != nil {
		return LegacyMigrationResult{}, err
	}

	sourcePath, exists, err := resolveLegacySourcePath(legacyPath)
	if err != nil {
		return LegacyMigrationResult{}, err
	}
	if !exists {
		return LegacyMigrationResult{}, nil
	}

	payload, exists, err := loadLegacyHistoryPayload(sourcePath, now)
	if err != nil || !exists {
		return LegacyMigrationResult{}, err
	}

	result := LegacyMigrationResult{
		LegacyFound: true,
		SourcePath:  sourcePath,
		BackupPath:  legacyBackupPath(legacyPath),
		MarkerPath:  legacyMarkerPath(legacyPath),
	}

	result.Migrated, err = migrateLegacyNodes(store, payload.Nodes, now)
	if err != nil {
		return result, err
	}

	return result, nil
}

func migrateLegacyNodes(
	store networkHistoryStore,
	nodes map[string]map[string]*legacyHistoryEntry,
	now time.Time,
) (bool, error) {
	var migrated bool
	for nodeID, tests := range nodes {
		nodeMigrated, err := migrateLegacyNode(store, nodeID, tests, now)
		if nodeMigrated {
			migrated = true
		}
		if err != nil {
			return migrated, err
		}
	}
	return migrated, nil
}

func migrateLegacyNode(
	store networkHistoryStore,
	nodeID string,
	tests map[string]*legacyHistoryEntry,
	now time.Time,
) (bool, error) {
	existingTimesBySeries, err := loadExistingNodeHistoryTimestamps(store, nodeID, tests)
	if err != nil {
		return false, err
	}

	var migrated bool
	for key, entry := range tests {
		batch, err := buildLegacyMigrationBatch(key, entry, existingTimesBySeries)
		if err != nil {
			return migrated, err
		}
		if len(batch) == 0 {
			continue
		}
		if err := store.AppendBatch(nodeID, batch, now); err != nil {
			return migrated, fmt.Errorf("append migrated history for %s/%s: %w", nodeID, key, err)
		}
		migrated = true
	}

	return migrated, nil
}

func buildLegacyMigrationBatch(
	key string,
	entry *legacyHistoryEntry,
	existingTimesBySeries map[string]map[int64]struct{},
) ([]metrics.NetworkTestResult, error) {
	identity, err := parseNetworkSeriesKey(key)
	if err != nil {
		return nil, err
	}

	normalizeLegacyHistoryEntry(entry)
	existingTimes := existingTimesBySeries[buildNetworkSeriesKey(identity)]
	batch := make([]metrics.NetworkTestResult, 0, len(entry.Times))
	for idx, checkedAt := range entry.Times {
		if _, ok := existingTimes[checkedAt]; ok {
			continue
		}
		batch = append(batch, buildLegacyNetworkTestResult(identity, entry, idx, checkedAt))
	}
	return batch, nil
}

func buildLegacyNetworkTestResult(
	identity networkTestIdentity,
	entry *legacyHistoryEntry,
	index int,
	checkedAt int64,
) metrics.NetworkTestResult {
	latency, loss := legacyEntryValues(entry, index)
	available := deriveLegacyAvailability(latency)
	status := "offline"
	if available {
		status = "online"
	}
	return metrics.NetworkTestResult{
		Type:       identity.Type,
		Host:       identity.Host,
		Port:       identity.Port,
		Name:       identity.Name,
		CheckedAt:  checkedAt,
		LatencyMs:  latency,
		PacketLoss: loss,
		Status:     status,
	}
}

func deriveLegacyAvailability(latency *float64) bool {
	return latency != nil
}

func loadExistingNodeHistoryTimestamps(
	store networkHistoryStore,
	nodeID string,
	tests map[string]*legacyHistoryEntry,
) (map[string]map[int64]struct{}, error) {
	result := make(map[string]map[int64]struct{}, len(tests))
	from, to, ok := legacyNodeTimeWindow(tests)
	if !ok {
		return result, nil
	}

	seriesMap, err := store.QueryRange(nodeID, from, to)
	if err != nil {
		return nil, err
	}
	for seriesKey, entry := range seriesMap {
		if entry == nil || len(entry.Times) == 0 {
			continue
		}
		timestamps := make(map[int64]struct{}, len(entry.Times))
		for _, ts := range entry.Times {
			timestamps[ts] = struct{}{}
		}
		result[seriesKey] = timestamps
	}
	return result, nil
}

func legacyNodeTimeWindow(tests map[string]*legacyHistoryEntry) (time.Time, time.Time, bool) {
	var (
		minTime int64
		maxTime int64
		found   bool
	)
	for _, entry := range tests {
		if entry == nil || len(entry.Times) == 0 {
			continue
		}
		for _, ts := range entry.Times {
			if !found || ts < minTime {
				minTime = ts
			}
			if !found || ts > maxTime {
				maxTime = ts
			}
			found = true
		}
	}
	if !found {
		return time.Time{}, time.Time{}, false
	}
	return time.Unix(minTime, 0).UTC().Add(-time.Second), time.Unix(maxTime, 0).UTC().Add(time.Second), true
}

func resolveLegacySourcePath(path string) (string, bool, error) {
	if completed, err := legacyMigrationMarked(path); err != nil {
		return "", false, err
	} else if completed {
		return "", false, nil
	}

	if _, err := os.Stat(path); err == nil {
		return path, true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}

	backupPath := legacyBackupPath(path)
	if _, err := os.Stat(backupPath); err == nil {
		return backupPath, true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	return "", false, nil
}

func EnsureLegacyMigrationBackup(path string) error {
	legacyPath, err := normalizeLegacyHistoryPath(path)
	if err != nil {
		return err
	}
	backupPath := legacyBackupPath(legacyPath)
	if _, err := os.Stat(backupPath); err == nil {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return err
	}
	return writeLegacyMigrationArtifact(legacyPath, legacyBackupPath, data)
}

func MarkLegacyMigrationComplete(path string, now time.Time) error {
	legacyPath, err := normalizeLegacyHistoryPath(path)
	if err != nil {
		return err
	}
	payload := []byte(strconv.FormatInt(now.Unix(), 10))
	return writeLegacyMigrationArtifact(legacyPath, legacyMarkerPath, payload)
}

func normalizeLegacyHistoryPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("legacy history path required")
	}
	return path, nil
}

func writeLegacyMigrationArtifact(path string, pathFunc func(string) string, payload []byte) error {
	return writeLegacyFileAtomic(pathFunc(path), payload)
}

func writeLegacyFileAtomic(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func legacyMigrationMarked(path string) (bool, error) {
	markerPath := legacyMarkerPath(path)
	if _, err := os.Stat(markerPath); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, err
	}
}

func legacyBackupPath(path string) string {
	return path + ".bak"
}

func legacyMarkerPath(path string) string {
	return path + ".migrated"
}

func normalizeLegacyHistoryEntry(entry *legacyHistoryEntry) {
	if entry == nil {
		return
	}
	if entry.Times == nil {
		entry.Times = []int64{}
	}
	count := len(entry.Times)
	entry.Latency = normalizeLegacySeriesValues(entry.Latency, count)
	entry.Loss = normalizeLegacySeriesValues(entry.Loss, count)
}

func normalizeLegacySeriesValues(values []*float64, count int) []*float64 {
	if values == nil {
		values = make([]*float64, 0, count)
	}
	if len(values) > count {
		values = values[len(values)-count:]
	}
	for len(values) < count {
		values = append(values, nil)
	}
	return values
}

func legacyEntryValues(entry *legacyHistoryEntry, idx int) (*float64, float64) {
	if entry == nil || idx < 0 {
		return nil, 0
	}

	var latency *float64
	if idx < len(entry.Latency) {
		latency = cloneFloatPointer(entry.Latency[idx])
	}
	if idx >= len(entry.Loss) || entry.Loss[idx] == nil {
		return latency, 0
	}
	return latency, *entry.Loss[idx]
}

func loadLegacyHistoryPayload(path string, now time.Time) (legacyHistoryPayload, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return legacyHistoryPayload{}, false, nil
		}
		return legacyHistoryPayload{}, false, err
	}

	normalized := normalizeJSONBytes(data)
	var payload legacyHistoryPayload
	trailing, err := decodeFirstJSONValue(normalized, &payload)
	if err == nil {
		if payload.Nodes != nil || payload.Version != 0 || payload.UpdatedAt != 0 {
			if trailing {
				return legacyHistoryPayload{}, false, errors.New("extra content after JSON value")
			}
			if payload.Nodes == nil {
				payload.Nodes = make(map[string]map[string]*legacyHistoryEntry)
			}
			return payload, true, nil
		}
	}

	var rawNodes map[string]map[string]*legacyHistoryEntry
	trailing, err = decodeFirstJSONValue(normalized, &rawNodes)
	if err != nil {
		return legacyHistoryPayload{}, false, err
	}
	if trailing {
		return legacyHistoryPayload{}, false, errors.New("extra content after JSON value")
	}
	if rawNodes == nil {
		rawNodes = make(map[string]map[string]*legacyHistoryEntry)
	}
	return legacyHistoryPayload{
		Version:   1,
		UpdatedAt: now.Unix(),
		Nodes:     rawNodes,
	}, true, nil
}

func normalizeJSONBytes(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	return bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
}

func decodeFirstJSONValue(data []byte, target any) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return false, err
		}
		return false, err
	}
	rest := bytes.TrimSpace(data[decoder.InputOffset():])
	return len(rest) > 0, nil
}
