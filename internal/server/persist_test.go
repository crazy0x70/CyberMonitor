package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyber_monitor/internal/metrics"
)

func writeStateFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}

func marshalState(t *testing.T, payload PersistedData) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化 PersistedData 失败: %v", err)
	}
	return string(data)
}

func TestLoadPersistedDataFallbackBranches(t *testing.T) {
	mainState := PersistedData{Settings: Settings{SiteTitle: "main-title"}}
	backupState := PersistedData{Settings: Settings{SiteTitle: "backup-title"}}

	tests := []struct {
		name         string
		mainFile     string // 空串表示不写主文件
		backupFile   string // 空串表示不写备份
		wantLoaded   bool
		wantErr      bool
		wantTitle    string
		wantMainGone bool // 加载后主文件是否应被移除
	}{
		{
			name:       "主文件正常加载",
			mainFile:   marshalState(t, mainState),
			wantLoaded: true,
			wantTitle:  "main-title",
		},
		{
			name:       "主文件与备份均缺失，全新启动",
			wantLoaded: false,
			wantErr:    false,
		},
		{
			name:       "主文件损坏且无备份，返回读取错误",
			mainFile:   "{not-json",
			wantLoaded: false,
			wantErr:    true,
		},
		{
			name:         "主文件损坏，从备份恢复并移除损坏主文件",
			mainFile:     "{not-json",
			backupFile:   marshalState(t, backupState),
			wantLoaded:   true,
			wantTitle:    "backup-title",
			wantMainGone: true,
		},
		{
			name:       "主文件缺失，从备份恢复",
			backupFile: marshalState(t, backupState),
			wantLoaded: true,
			wantTitle:  "backup-title",
		},
		{
			name:       "主文件与备份均损坏，返回合并错误",
			mainFile:   "{not-json",
			backupFile: "}{",
			wantLoaded: false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub := t.TempDir()
			statePath := filepath.Join(sub, "state.json")
			if tt.mainFile != "" {
				writeStateFile(t, statePath, tt.mainFile)
			}
			if tt.backupFile != "" {
				writeStateFile(t, statePath+".bak", tt.backupFile)
			}

			payload, loaded, err := loadPersistedData(statePath)
			if tt.wantErr && err == nil {
				t.Fatalf("期望返回错误，实际 err = nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("不期望错误，实际 err = %v", err)
			}
			if loaded != tt.wantLoaded {
				t.Fatalf("loaded = %v, want %v", loaded, tt.wantLoaded)
			}
			if tt.wantTitle != "" && payload.Settings.SiteTitle != tt.wantTitle {
				t.Fatalf("SiteTitle = %q, want %q", payload.Settings.SiteTitle, tt.wantTitle)
			}
			if tt.wantMainGone {
				if _, statErr := os.Stat(statePath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("期望损坏主文件被移除，实际存在（stat err = %v）", statErr)
				}
			}
		})
	}
}

func TestReadPersistedDataFileDropsInvalidNodeIDEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeStateFile(t, path, `{
		"nodes": {
			"bad/id": {"stats": {"node_id": "x"}},
			"good-node": {"stats": {"node_id": "x"}}
		},
		"offline_sessions": {"../escape": {"started_at": 1}, "good-node": {"started_at": 2}},
		"alerted": {"bad\\id": {}, "good-node": {"offline_since": "2024-01-01T00:00:00Z"}},
		"profiles": {
			"bad/id": {"alias": "bad"},
			"good-node": {"alias": "good", "test_interval_sec": 60}
		},
		"pending_history_deletes": ["bad/id", "good-node", "good-node", "another"]
	}`)

	payload, loaded, err := loadPersistedData(path)
	if err != nil {
		t.Fatalf("单个坏 ID 不应导致加载失败: %v", err)
	}
	if !loaded {
		t.Fatalf("loaded = false, want true")
	}
	if _, exists := payload.Nodes["bad/id"]; exists {
		t.Errorf("nodes 中非法 ID 条目应被丢弃")
	}
	if _, exists := payload.Nodes["good-node"]; !exists {
		t.Errorf("nodes 中合法条目应保留")
	}
	if payload.Nodes["good-node"].Stats.NodeID != "good-node" {
		t.Errorf("nodes 统计 NodeID = %q, want good-node", payload.Nodes["good-node"].Stats.NodeID)
	}
	if _, exists := payload.OfflineSessions["../escape"]; exists {
		t.Errorf("offline_sessions 中非法 ID 条目应被丢弃")
	}
	if _, exists := payload.OfflineSessions["good-node"]; !exists {
		t.Errorf("offline_sessions 中合法条目应保留")
	}
	if _, exists := payload.Alerted["bad\\id"]; exists {
		t.Errorf("alerted 中非法 ID 条目应被丢弃")
	}
	if _, exists := payload.Alerted["good-node"]; !exists {
		t.Errorf("alerted 中合法条目应保留")
	}
	if _, exists := payload.Profiles["bad/id"]; exists {
		t.Errorf("profiles 中非法 ID 条目应被丢弃")
	}
	if _, exists := payload.Profiles["good-node"]; !exists {
		t.Errorf("profiles 中合法条目应保留")
	}
	wantDeletes := []string{"another", "good-node"}
	if got := strings.Join(payload.PendingHistoryDeletes, ","); got != strings.Join(wantDeletes, ",") {
		t.Errorf("pending_history_deletes = %v, want %v（去重+丢弃非法+排序）", payload.PendingHistoryDeletes, wantDeletes)
	}
}

func TestSavePersistedDataRotatesBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := savePersistedData(path, PersistedData{Settings: Settings{SiteTitle: "v1"}}); err != nil {
		t.Fatalf("首次保存失败: %v", err)
	}
	if got := readStateTitle(t, path); got != "v1" {
		t.Fatalf("首次保存后主文件 SiteTitle = %q, want v1", got)
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("首次保存不应产生 .bak（此前无旧文件），stat err = %v", err)
	}

	if err := savePersistedData(path, PersistedData{Settings: Settings{SiteTitle: "v2"}}); err != nil {
		t.Fatalf("第二次保存失败: %v", err)
	}
	if got := readStateTitle(t, path); got != "v2" {
		t.Fatalf("保存后主文件 SiteTitle = %q, want v2", got)
	}
	if got := readStateTitle(t, path+".bak"); got != "v1" {
		t.Fatalf("备份文件 SiteTitle = %q, want v1", got)
	}
	if _, err := os.Stat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("保存完成后不应残留 .new 文件，stat err = %v", err)
	}
}

func TestNormalizeNodeIDMapTrimConflictDeterministic(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]int
		want map[string]int
	}{
		{
			name: "干净 key 优先于待 trim key",
			raw:  map[string]int{" node ": 1, "node": 2},
			want: map[string]int{"node": 2},
		},
		{
			name: "字面顺序颠倒后结果一致",
			raw:  map[string]int{"node": 2, " node ": 1},
			want: map[string]int{"node": 2},
		},
		{
			name: "两个待 trim key 冲突时按原始 key 排序取确定胜者",
			raw:  map[string]int{"node ": 4, " node": 3, "other": 5},
			want: map[string]int{"node": 3, "other": 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeNodeIDMap("nodes", tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("结果条目数 = %d, want %d（got = %v）", len(got), len(tt.want), got)
			}
			for key, wantVal := range tt.want {
				gotVal, ok := got[key]
				if !ok || gotVal != wantVal {
					t.Errorf("key %q = %d（存在 = %v）, want %d", key, gotVal, ok, wantVal)
				}
			}
		})
	}

	// 跨表一致：同一组原始 key 在不同表里胜出的规范化 key 必须相同，避免 A 的 stats 配 B 的 profile。
	rawKeys := map[string]int{" node ": 1, "node": 2}
	for _, prefix := range []string{"nodes", "offline_sessions", "alerted", "profiles"} {
		got := normalizeNodeIDMap(prefix, rawKeys)
		if len(got) != 1 || got["node"] != 2 {
			t.Errorf("%s 表规范化结果 = %v, want 仅 {node: 2}", prefix, got)
		}
	}
}

func readStateTitle(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var payload PersistedData
	if err := strictUnmarshalJSON(data, &payload); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return payload.Settings.SiteTitle
}

func TestMigrateLegacyProfileTests(t *testing.T) {
	legacyJSON := func(t *testing.T, tests []metrics.NetworkTestConfig) map[string]json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(legacyPersistedProfile{Tests: tests})
		if err != nil {
			t.Fatalf("序列化 legacy profile 失败: %v", err)
		}
		return map[string]json.RawMessage{"node-1": raw}
	}

	t.Run("legacy tests 迁入空目录并生成 selections", func(t *testing.T) {
		payload := &PersistedData{
			Settings: Settings{TestCatalog: []TestCatalogItem{}},
			Profiles: map[string]*NodeProfile{"node-1": {Alias: "n1"}},
		}
		rawProfiles := legacyJSON(t, []metrics.NetworkTestConfig{
			{Name: "Ping", Type: "icmp", Host: "1.1.1.1", IntervalSec: 30},
			{Name: "Web", Type: "tcp", Host: "example.com", Port: 443, IntervalSec: 60},
		})
		if err := migrateLegacyProfileTests(rawProfiles, payload); err != nil {
			t.Fatalf("migrateLegacyProfileTests 失败: %v", err)
		}
		if len(payload.Settings.TestCatalog) != 2 {
			t.Fatalf("测试目录条目 = %d, want 2", len(payload.Settings.TestCatalog))
		}
		catalogByID := make(map[string]TestCatalogItem, len(payload.Settings.TestCatalog))
		for _, item := range payload.Settings.TestCatalog {
			if item.ID == "" {
				t.Fatalf("迁移后的目录条目缺少 ID: %+v", item)
			}
			catalogByID[item.ID] = item
		}
		selections := payload.Profiles["node-1"].TestSelections
		if len(selections) != 2 {
			t.Fatalf("TestSelections 数量 = %d, want 2", len(selections))
		}
		intervalByID := make(map[string]int, len(selections))
		for _, sel := range selections {
			intervalByID[sel.TestID] = sel.IntervalSec
		}
		for id, item := range catalogByID {
			wantInterval := 0
			if item.Type == "tcp" {
				wantInterval = 60
			}
			if got := intervalByID[id]; got != wantInterval {
				t.Errorf("selection %s（%s/%s）IntervalSec = %d, want %d", id, item.Name, item.Type, got, wantInterval)
			}
		}
	})

	t.Run("已有 selections 的 profile 不被 legacy tests 覆盖", func(t *testing.T) {
		payload := &PersistedData{
			Settings: Settings{TestCatalog: []TestCatalogItem{
				{ID: "cat-1", Name: "Ping", Type: "icmp", Host: "1.1.1.1"},
			}},
			Profiles: map[string]*NodeProfile{"node-1": {
				TestSelections: []TestSelection{{TestID: "cat-1", IntervalSec: 5}},
			}},
		}
		rawProfiles := legacyJSON(t, []metrics.NetworkTestConfig{
			{Name: "Other", Type: "icmp", Host: "8.8.8.8", IntervalSec: 30},
		})
		if err := migrateLegacyProfileTests(rawProfiles, payload); err != nil {
			t.Fatalf("migrateLegacyProfileTests 失败: %v", err)
		}
		if len(payload.Settings.TestCatalog) != 1 {
			t.Fatalf("已有 selections 时不应新增目录条目，实际 %d", len(payload.Settings.TestCatalog))
		}
		selections := payload.Profiles["node-1"].TestSelections
		if len(selections) != 1 || selections[0].TestID != "cat-1" {
			t.Fatalf("TestSelections = %+v, want 仅保留既有 cat-1", selections)
		}
	})

	t.Run("命中现有目录条目时复用 ID 不新增", func(t *testing.T) {
		payload := &PersistedData{
			Settings: Settings{TestCatalog: []TestCatalogItem{
				{ID: "web-1", Name: "Web", Type: "tcp", Host: "example.com", Port: 443, IntervalSec: 60},
			}},
			Profiles: map[string]*NodeProfile{"node-1": {}},
		}
		rawProfiles := legacyJSON(t, []metrics.NetworkTestConfig{
			{Name: "Web", Type: "tcp", Host: "example.com", Port: 443, IntervalSec: 120},
		})
		if err := migrateLegacyProfileTests(rawProfiles, payload); err != nil {
			t.Fatalf("migrateLegacyProfileTests 失败: %v", err)
		}
		if len(payload.Settings.TestCatalog) != 1 {
			t.Fatalf("应复用现有目录条目，实际条目数 %d", len(payload.Settings.TestCatalog))
		}
		selections := payload.Profiles["node-1"].TestSelections
		if len(selections) != 1 || selections[0].TestID != "web-1" {
			t.Fatalf("TestSelections = %+v, want 复用 web-1", selections)
		}
		if selections[0].IntervalSec != 120 {
			t.Fatalf("IntervalSec = %d, want 120（沿用 legacy 间隔）", selections[0].IntervalSec)
		}
	})
}

func TestMigrateLegacyAISettings(t *testing.T) {
	t.Run("default_provider 迁移为 CommandProvider", func(t *testing.T) {
		payload := &PersistedData{}
		if err := migrateLegacyAISettings(json.RawMessage(`{"default_provider":"openai"}`), payload); err != nil {
			t.Fatalf("migrateLegacyAISettings 失败: %v", err)
		}
		if got := payload.Settings.AISettings.CommandProvider; got != "openai" {
			t.Fatalf("CommandProvider = %q, want openai", got)
		}
		if len(payload.Settings.AISettings.OpenAICompatibles) != 0 {
			t.Fatalf("无 compat 配置时不应追加 OpenAICompatibles，实际 %d 条", len(payload.Settings.AISettings.OpenAICompatibles))
		}
	})

	t.Run("openai_compatible 迁移为 legacy 兼容档", func(t *testing.T) {
		payload := &PersistedData{}
		raw := json.RawMessage(`{"default_provider":"openai_compatible","openai_compatible":{"api_key":"sk-x","base_url":"https://api.example.com","model":"gpt-4o"}}`)
		if err := migrateLegacyAISettings(raw, payload); err != nil {
			t.Fatalf("migrateLegacyAISettings 失败: %v", err)
		}
		compat := payload.Settings.AISettings.OpenAICompatibles
		if len(compat) != 1 {
			t.Fatalf("OpenAICompatibles 条目 = %d, want 1", len(compat))
		}
		if compat[0].ID != "legacy-openai-compatible" || compat[0].Model != "gpt-4o" || compat[0].APIKey != "sk-x" {
			t.Fatalf("compat 条目 = %+v, want ID legacy-openai-compatible 且保留配置", compat[0])
		}
		if got, want := payload.Settings.AISettings.CommandProvider, "openai_compatible:legacy-openai-compatible"; got != want {
			t.Fatalf("CommandProvider = %q, want %q", got, want)
		}
	})

	t.Run("已有 CommandProvider 时不被覆盖", func(t *testing.T) {
		payload := &PersistedData{}
		payload.Settings.AISettings.CommandProvider = "openai"
		if err := migrateLegacyAISettings(json.RawMessage(`{"default_provider":"anthropic"}`), payload); err != nil {
			t.Fatalf("migrateLegacyAISettings 失败: %v", err)
		}
		if got := payload.Settings.AISettings.CommandProvider; got != "openai" {
			t.Fatalf("CommandProvider = %q, want 保持 openai", got)
		}
	})
}

func TestNormalizeTestCatalog(t *testing.T) {
	t.Run("规范化合法条目", func(t *testing.T) {
		normalized, err := normalizeTestCatalog([]TestCatalogItem{
			{Name: "  Web  ", Type: "  TCP ", Host: " example.com ", Port: 443, IntervalSec: 7200},
			{Name: "Ping", Host: "1.1.1.1"},
			{Name: "Ping2", Type: "icmp", Host: "8.8.8.8", Port: 999},
		})
		if err != nil {
			t.Fatalf("normalizeTestCatalog 失败: %v", err)
		}
		if len(normalized) != 3 {
			t.Fatalf("条目数 = %d, want 3", len(normalized))
		}
		web := normalized[0]
		if web.Name != "Web" || web.Type != "tcp" || web.Host != "example.com" || web.Port != 443 {
			t.Fatalf("web 条目规范化错误: %+v", web)
		}
		if web.IntervalSec != 3600 {
			t.Fatalf("IntervalSec = %d, want 钳制到 3600", web.IntervalSec)
		}
		if web.ID == "" {
			t.Fatalf("缺少生成 ID: %+v", web)
		}
		if normalized[1].Type != "icmp" {
			t.Fatalf("无 type 无 port 应推断为 icmp，实际 %q", normalized[1].Type)
		}
		if normalized[2].Port != 0 {
			t.Fatalf("icmp 条目 Port = %d, want 0", normalized[2].Port)
		}
	})

	t.Run("重复 ID 重新生成", func(t *testing.T) {
		normalized, err := normalizeTestCatalog([]TestCatalogItem{
			{ID: "dup", Name: "A", Type: "icmp", Host: "1.1.1.1"},
			{ID: "dup", Name: "B", Type: "icmp", Host: "8.8.8.8"},
		})
		if err != nil {
			t.Fatalf("normalizeTestCatalog 失败: %v", err)
		}
		if len(normalized) != 2 || normalized[0].ID == normalized[1].ID {
			t.Fatalf("重复 ID 应重新生成: %+v", normalized)
		}
	})

	t.Run("非法条目返回错误", func(t *testing.T) {
		for _, item := range []TestCatalogItem{
			{Name: "X", Host: "   "},
			{Name: "X", Host: "exa<mple.com"},
			{Name: "X", Host: "example.com", Port: 70000},
			{Host: "1.1.1.1"},
		} {
			if _, err := normalizeTestCatalog([]TestCatalogItem{item}); err == nil {
				t.Errorf("条目 %+v 应返回错误", item)
			}
		}
	})
}

func TestNormalizeStatsPayloadClearsNetworkTestError(t *testing.T) {
	latency := 24.5
	payload, apiErr := normalizeStatsPayload(metrics.NodeStats{
		NodeID: "node-1",
		NetworkTests: []metrics.NetworkTestResult{
			{Name: "CF", Type: "tcp", Host: "1.1.1.1", Port: 443, Status: "error", Error: "远程网络测试不允许使用本地或内网主机名", PacketLoss: 100},
			{Name: "Ping", Type: "icmp", Host: "8.8.8.8", Status: "ok", LatencyMs: &latency, Error: "boom"},
		},
	})
	if apiErr != nil {
		t.Fatalf("normalizeStatsPayload 失败: %v", apiErr)
	}
	if len(payload.NetworkTests) != 2 {
		t.Fatalf("network tests 数量 = %d, want 2", len(payload.NetworkTests))
	}
	for _, test := range payload.NetworkTests {
		if test.Error != "" {
			t.Errorf("测试 %s 的 Error = %q, want 清空（agent 侧诊断文案不得进入公开快照）", test.Name, test.Error)
		}
	}
	if payload.NetworkTests[0].Status != "error" || payload.NetworkTests[1].Status != "ok" {
		t.Errorf("status 应保留用于前端推导: %+v", payload.NetworkTests)
	}
	if payload.NetworkTests[1].LatencyMs == nil || *payload.NetworkTests[1].LatencyMs != 24.5 {
		t.Errorf("latency 应保留: %+v", payload.NetworkTests[1])
	}
}
