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
	path = strings.TrimSpace(path)
	if path == "" {
		return LegacyMigrationResult{}, errors.New("legacy history path required")
	}

	sourcePath, exists, err := resolveLegacySourcePath(path)
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
		BackupPath:  legacyBackupPath(path),
		MarkerPath:  legacyMarkerPath(path),
	}

	for nodeID, tests := range payload.Nodes {
		for key, entry := range tests {
			identity, err := parseNetworkSeriesKey(key)
			if err != nil {
				return result, err
			}
			normalizeLegacyHistoryEntry(entry)
			existingTimes, err := loadExistingHistoryTimestamps(store, nodeID, key, entry.Times)
			if err != nil {
				return result, err
			}

			batch := make([]metrics.NetworkTestResult, 0, len(entry.Times))
			for idx, checkedAt := range entry.Times {
				if _, ok := existingTimes[checkedAt]; ok {
					continue
				}
				batch = append(batch, buildLegacyNetworkTestResult(identity, entry, idx, checkedAt))
			}
			if len(batch) == 0 {
				continue
			}
			if err := store.AppendBatch(nodeID, batch, now); err != nil {
				return result, fmt.Errorf("append migrated history for %s/%s: %w", nodeID, key, err)
			}
			result.Migrated = true
		}
	}

	return result, nil
}

func buildLegacyNetworkTestResult(
	identity networkTestIdentity,
	entry *legacyHistoryEntry,
	index int,
	checkedAt int64,
) metrics.NetworkTestResult {
	loss := legacyLossValue(entry, index)
	latency := legacyLatencyValue(entry, index)
	available := deriveLegacyAvailability(latency, loss)
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

func deriveLegacyAvailability(latency *float64, loss float64) bool {
	if latency != nil {
		return true
	}
	if loss >= 100 {
		return false
	}
	return false
}

func loadExistingHistoryTimestamps(
	store networkHistoryStore,
	nodeID string,
	seriesKey string,
	timestamps []int64,
) (map[int64]struct{}, error) {
	result := make(map[int64]struct{})
	if len(timestamps) == 0 {
		return result, nil
	}
	minTime := timestamps[0]
	maxTime := timestamps[0]
	for _, ts := range timestamps[1:] {
		if ts < minTime {
			minTime = ts
		}
		if ts > maxTime {
			maxTime = ts
		}
	}

	seriesMap, err := store.QueryRange(
		nodeID,
		time.Unix(minTime, 0).UTC().Add(-time.Second),
		time.Unix(maxTime, 0).UTC().Add(time.Second),
	)
	if err != nil {
		return nil, err
	}
	entry := seriesMap[seriesKey]
	if entry == nil {
		return result, nil
	}
	for _, ts := range entry.Times {
		result[ts] = struct{}{}
	}
	return result, nil
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
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("legacy history path required")
	}
	backupPath := legacyBackupPath(path)
	if _, err := os.Stat(backupPath); err == nil {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		return err
	}
	tmpPath := backupPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, backupPath)
}

func MarkLegacyMigrationComplete(path string, now time.Time) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("legacy history path required")
	}
	markerPath := legacyMarkerPath(path)
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		return err
	}
	payload := []byte(strconv.FormatInt(now.Unix(), 10))
	tmpPath := markerPath + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, markerPath)
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

func legacyLatencyValue(entry *legacyHistoryEntry, idx int) *float64 {
	if entry == nil || idx < 0 || idx >= len(entry.Latency) {
		return nil
	}
	return cloneFloatPointer(entry.Latency[idx])
}

func normalizeLegacyHistoryEntry(entry *legacyHistoryEntry) {
	if entry == nil {
		return
	}
	if entry.Times == nil {
		entry.Times = []int64{}
	}
	count := len(entry.Times)
	if entry.Latency == nil {
		entry.Latency = make([]*float64, 0, count)
	}
	if entry.Loss == nil {
		entry.Loss = make([]*float64, 0, count)
	}
	if len(entry.Latency) > count {
		entry.Latency = entry.Latency[len(entry.Latency)-count:]
	}
	if len(entry.Loss) > count {
		entry.Loss = entry.Loss[len(entry.Loss)-count:]
	}
	for len(entry.Latency) < count {
		entry.Latency = append(entry.Latency, nil)
	}
	for len(entry.Loss) < count {
		entry.Loss = append(entry.Loss, nil)
	}
}

func legacyLossValue(entry *legacyHistoryEntry, idx int) float64 {
	if entry == nil || idx < 0 || idx >= len(entry.Loss) {
		return 0
	}
	if entry.Loss[idx] == nil {
		return 0
	}
	return *entry.Loss[idx]
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
