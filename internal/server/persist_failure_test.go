package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newPersistBrokenStore 构造一个「父路径是普通文件」的 Store：WriteFileAtomic 的
// MkdirAll 必然失败，从而稳定注入落盘失败；repair 后指向可写目录，模拟磁盘恢复。
func newPersistBrokenStore(t *testing.T, settings Settings) (*Store, func()) {
	t.Helper()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("创建落盘阻断文件失败: %v", err)
	}
	store := &Store{
		settings:          settings,
		dataPath:          filepath.Join(blocker, "state.json"),
		profiles:          map[string]*NodeProfile{},
		loginAttempts:     map[string]*loginAttempt{},
		configRefresh:     map[string]struct{}{},
		agentIngestRate:   map[string]agentRateWindow{},
		agentRegisterRate: map[string]agentRateWindow{},
	}
	repair := func() {
		store.dataPath = filepath.Join(dir, "state.json")
	}
	return store, repair
}

// 回归 R04①：首次签发落盘失败返回 503 且 token 留在内存；重试命中「token 已存在」
// 分支时必须补落盘（仍失败则 503），磁盘恢复后重试成功且返回同一 token、状态落盘。
func TestRegisterAgentAuthTokenRetriesPersistAfterFailure(t *testing.T) {
	settings, err := initSettings(Config{AgentToken: "boot-tok"})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	store, repair := newPersistBrokenStore(t, settings)
	now := time.Now()

	_, apiErr := store.registerAgentAuthToken("node-a", "boot-tok", now)
	if apiErr == nil {
		t.Fatalf("落盘失败时首次注册必须返回错误")
	}
	if apiErr.statusCode != http.StatusServiceUnavailable {
		t.Errorf("首次注册状态码 = %d, want %d", apiErr.statusCode, http.StatusServiceUnavailable)
	}
	if token := store.profiles["node-a"].AgentAuthToken; token == "" {
		t.Fatalf("落盘失败后 token 应留在内存，供重试补落盘")
	}
	if !store.hasPersistPending() {
		t.Errorf("落盘失败后 persistPending 应置位")
	}

	// 磁盘仍坏：重试命中已存在分支，补落盘仍失败 → 继续 503。
	token2, apiErr := store.registerAgentAuthToken("node-a", "boot-tok", now.Add(time.Second))
	if apiErr == nil || apiErr.statusCode != http.StatusServiceUnavailable {
		t.Fatalf("磁盘未恢复时重试应继续 503，实际 err=%v", apiErr)
	}
	if token2 != "" {
		t.Errorf("失败路径不应返回 token")
	}

	// 磁盘恢复：重试应补落盘成功并返回内存中的同一 token。
	token1 := store.profiles["node-a"].AgentAuthToken
	repair()
	token3, apiErr := store.registerAgentAuthToken("node-a", "boot-tok", now.Add(2*time.Second))
	if apiErr != nil {
		t.Fatalf("磁盘恢复后重试应成功: %v", apiErr)
	}
	if token3 != token1 {
		t.Errorf("重试返回 token = %q, want 首次签发的 %q", token3, token1)
	}
	if store.hasPersistPending() {
		t.Errorf("落盘成功后 persistPending 应清除")
	}
	data, err := os.ReadFile(store.dataPath)
	if err != nil {
		t.Fatalf("读取落盘文件失败: %v", err)
	}
	if !strings.Contains(string(data), token1) {
		t.Errorf("落盘文件中缺少签发的 agent token")
	}
}

// 回归 R04②：终态报告先清 AgentUpdate 再落盘，失败后若不恢复快照，Agent 重试时
// 已无 pending instruction 会被判冲突（503 永远无法收敛）。
func TestApplyAgentUpdateReportRestoresSnapshotOnPersistFailure(t *testing.T) {
	settings, err := initSettings(Config{})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	store, repair := newPersistBrokenStore(t, settings)
	instruction := AgentUpdateInstruction{ID: "upd-1", Version: "1.2.3", RequestedAt: time.Now().Unix()}
	store.profiles["node-a"] = &NodeProfile{
		TestIntervalSec:          defaultTestIntervalSec,
		AgentUpdate:              cloneAgentUpdateInstruction(&instruction),
		AgentUpdateState:         agentUpdateStatePending,
		AgentUpdateTargetVersion: "1.2.3",
	}
	report := AgentUpdateReport{State: agentUpdateStateSucceeded, ID: "upd-1", Version: "1.2.3"}

	_, applied, err := store.applyAgentUpdateReportNodeLocked("node-a", report)
	if err == nil {
		t.Fatalf("落盘失败必须返回错误")
	}
	if !applied {
		t.Fatalf("报告已应用，applied 应为 true")
	}
	if !errors.Is(err, errPersistFailed) {
		t.Errorf("错误应携带 errPersistFailed（供 503 分类）: %v", err)
	}
	profile := store.profiles["node-a"]
	if profile == nil || profile.AgentUpdate == nil {
		t.Fatalf("落盘失败后必须恢复快照（AgentUpdate 需保留，重试才能重新匹配）")
	}
	if profile.AgentUpdateState != agentUpdateStatePending {
		t.Errorf("恢复后的状态 = %q, want %q", profile.AgentUpdateState, agentUpdateStatePending)
	}

	// 磁盘恢复后重试同一终态报告：应成功应用并清空指令。
	repair()
	result, applied, err := store.applyAgentUpdateReportNodeLocked("node-a", report)
	if err != nil || !applied {
		t.Fatalf("磁盘恢复后重试应成功: applied=%v err=%v", applied, err)
	}
	if result.AgentUpdate != nil || result.AgentUpdateState != agentUpdateStateSucceeded {
		t.Errorf("重试后终态未生效: update=%v state=%q", result.AgentUpdate, result.AgentUpdateState)
	}
}

// 回归 R02/R03：设置落盘失败时不回滚——内存保持已生效并返回已应用的 view，
// 错误携带 errPersistFailed（路由层据此 500，而非 400）。
func TestUpdateSettingsKeepsAppliedStateOnPersistFailure(t *testing.T) {
	settings, err := initSettings(Config{})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	store, _ := newPersistBrokenStore(t, settings)

	title := "新标题"
	view, err := store.UpdateSettings(SettingsUpdate{SiteTitle: &title})
	if err == nil {
		t.Fatalf("落盘失败必须返回错误")
	}
	if !errors.Is(err, errPersistFailed) {
		t.Errorf("错误应携带 errPersistFailed: %v", err)
	}
	if view.SiteTitle != title {
		t.Errorf("失败路径应返回已应用的 view（SiteTitle = %q, want %q）", view.SiteTitle, title)
	}
	if got := store.SettingsView().SiteTitle; got != title {
		t.Errorf("内存设置应保持已生效（SiteTitle = %q, want %q）", got, title)
	}

	// 校验失败仍是普通 400 语义：内存不生效。
	badPath := "/api/reserved" // 与 /api 前缀冲突，必被 normalizeAdminPath 拒绝
	view, err = store.UpdateSettings(SettingsUpdate{AdminPath: &badPath})
	if err == nil || errors.Is(err, errPersistFailed) {
		t.Fatalf("校验失败不应归类为落盘失败: %v", err)
	}
	if view.SiteTitle != "" {
		t.Errorf("校验失败不应返回 view")
	}
	if got := store.SettingsView().SiteTitle; got != title {
		t.Errorf("校验失败不应改动已生效设置（SiteTitle = %q, want %q）", got, title)
	}
}
