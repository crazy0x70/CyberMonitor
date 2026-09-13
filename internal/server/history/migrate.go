package history

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	// AppendMigrationSamples 以单一事务提交全局按 CheckedAt 升序的迁移
	// 样本（TSDB head maxt 全局单调且每次 Commit 推进，按节点分批提交
	// 会让后处理批次的更老样本命中 too-old 被静默丢弃）。
	AppendMigrationSamples(samples []MigrationSample) error
	// QueryRangeRaw 返回原始采样时间戳：迁移去重需要精确时间匹配，
	// 降采样查询输出的是桶起点时间，会造成漏判与幂等失效。
	QueryRangeRaw(ctx context.Context, nodeID string, from, to time.Time) (map[string]*NetworkHistoryEntry, error)
}

type LegacyMigrationResult struct {
	LegacyFound bool
	SourcePath  string
	BackupPath  string
	MarkerPath  string
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

	payload, data, exists, err := loadLegacyHistoryPayload(sourcePath, now)
	if err != nil || !exists {
		return LegacyMigrationResult{}, err
	}

	result := LegacyMigrationResult{
		LegacyFound: true,
		SourcePath:  sourcePath,
		BackupPath:  legacyBackupPath(legacyPath),
		MarkerPath:  legacyMarkerPath(legacyPath),
	}

	err = migrateLegacyNodes(store, payload.Nodes, now)
	if err != nil {
		return result, err
	}

	// 迁移成功即用已读入的原始字节写备份：同一文件不再二次 ReadFile
	//（7d×多序列的大文件原先在内存中同时存在 2-3 份）。source 为 .bak
	// 回退时（marker 丢失场景）不再造二级备份。
	if sourcePath == legacyPath {
		if err := WriteFileAtomic(legacyBackupPath(legacyPath), data); err != nil {
			return result, fmt.Errorf("backup legacy history: %w", err)
		}
	}

	return result, nil
}

func migrateLegacyNodes(
	store networkHistoryStore,
	nodes map[string]map[string]*legacyHistoryEntry,
	now time.Time,
) error {
	// 全部节点/序列的样本展平后按 CheckedAt 全局升序、单事务提交：
	// TSDB head maxt 全局单调且每次 Commit 推进，任何"节点内有序/节点间
	// 排序"的局部形态都无法约束跨批次的 maxt 重叠，后处理批次的更老样本
	// 会命中 too-old 被"容忍"路径静默丢弃（不计数不打日志，源文件照删）。
	maxCheckedAt := now.Add(networkMaxFutureSkew).Unix()
	flat := make([]MigrationSample, 0)
	for nodeID, tests := range nodes {
		if normalizedID, err := NormalizeNodeID(nodeID); err != nil || normalizedID == "" {
			log.Printf("legacy 迁移跳过非法节点 ID %q", nodeID)
			continue
		}
		existingTimesBySeries, err := loadExistingNodeHistoryTimestamps(store, nodeID, tests)
		if err != nil {
			return err
		}
		for key, entry := range tests {
			identity, err := ParseNetworkSeriesKey(key)
			if err != nil {
				// 单个畸形序列键只跳过自身：向上返回错误会中止全部节点的
				// 迁移，marker 不写导致每次启动重试、legacy 永不清理。
				log.Printf("legacy 探测序列键 %q（节点 %s）解析失败，已跳过: %v", key, nodeID, err)
				continue
			}
			normalizeLegacyHistoryEntry(entry)
			existingTimes := existingTimesBySeries[buildNetworkSeriesKey(identity)]
			for idx, checkedAt := range entry.Times {
				if checkedAt <= 0 || checkedAt > maxCheckedAt {
					// 与 <=0 同理：非法/未来时间戳会经
					// resolveTimestampMillis 回落为迁移时刻落库，污染当天
					// 曲线且破坏重迁移幂等（去重按原始时间戳匹配）。
					continue
				}
				if _, ok := existingTimes[checkedAt]; ok {
					continue
				}
				flat = append(flat, MigrationSample{
					NodeID: nodeID,
					Test:   buildLegacyNetworkTestResult(identity, entry, idx, checkedAt),
				})
			}
		}
	}
	if len(flat) == 0 {
		return nil
	}
	// CheckedAt 已在构建时原样携带，直接按其排序，无需旁路结构。
	sort.Slice(flat, func(i, j int) bool { return flat[i].Test.CheckedAt < flat[j].Test.CheckedAt })
	return store.AppendMigrationSamples(flat)
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

	seriesMap, err := store.QueryRangeRaw(context.Background(), nodeID, from, to)
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
	return WriteFileAtomic(pathFunc(path), payload)
}

// WriteFileAtomic durably writes data to path: it writes a temp file in the
// target directory, fsyncs it, renames it into place, and syncs the parent
// directory. The parent directory is created if missing.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	syncParentDir(dir)
	return nil
}

func syncParentDir(dir string) {
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
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
		latency = CloneFloatPtr(entry.Latency[idx])
	}
	if idx >= len(entry.Loss) || entry.Loss[idx] == nil {
		return latency, 0
	}
	return latency, *entry.Loss[idx]
}

func loadLegacyHistoryPayload(path string, now time.Time) (legacyHistoryPayload, []byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return legacyHistoryPayload{}, nil, false, nil
		}
		return legacyHistoryPayload{}, nil, false, err
	}

	normalized := normalizeJSONBytes(data)
	var payload legacyHistoryPayload
	trailing, err := DecodeFirstJSONValue(normalized, &payload)
	if err == nil {
		if payload.Nodes != nil || payload.Version != 0 || payload.UpdatedAt != 0 {
			if trailing {
				return legacyHistoryPayload{}, nil, false, errors.New("extra content after JSON value")
			}
			if payload.Nodes == nil {
				payload.Nodes = make(map[string]map[string]*legacyHistoryEntry)
			}
			return payload, data, true, nil
		}
	}

	var rawNodes map[string]map[string]*legacyHistoryEntry
	trailing, err = DecodeFirstJSONValue(normalized, &rawNodes)
	if err != nil {
		return legacyHistoryPayload{}, nil, false, err
	}
	if trailing {
		return legacyHistoryPayload{}, nil, false, errors.New("extra content after JSON value")
	}
	if rawNodes == nil {
		rawNodes = make(map[string]map[string]*legacyHistoryEntry)
	}
	return legacyHistoryPayload{
		Version:   1,
		UpdatedAt: now.Unix(),
		Nodes:     rawNodes,
	}, data, true, nil
}

func normalizeJSONBytes(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	return bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF})
}

// DecodeFirstJSONValue decodes the first JSON value in data (after trimming
// surrounding whitespace and any UTF-8 BOM) into target. It reports whether
// non-whitespace content remains after the decoded value, and returns io.EOF
// when data holds no JSON value at all.
func DecodeFirstJSONValue(data []byte, target any) (bool, error) {
	normalized := normalizeJSONBytes(data)
	if len(normalized) == 0 {
		return false, io.EOF
	}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	if err := decoder.Decode(target); err != nil {
		return false, err
	}
	rest := bytes.TrimSpace(normalized[decoder.InputOffset():])
	return len(rest) > 0, nil
}
