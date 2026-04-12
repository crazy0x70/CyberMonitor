# Agent TSDB 与节点身份稳定化 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 CyberMonitor 引入网络连通性与离线事件 TSDB，修复 Docker / watchtower / 服务端更新后的 Agent `node id` 漂移问题，并让公共前台按 `1D / 1W / 1M / 1Y` 真实读取对应历史数据。

**Architecture:** 实现分三层推进：先重构 Agent 身份解析与 Docker 重建回填逻辑，保证节点身份稳定；再引入独立的历史管理层，把网络历史与离线事件分别接入 TSDB；最后补齐公共历史查询 API 与前台按节点＋范围取数链路，并把 AI 上下文扩展到离线统计。整体保持 `state.json` 管配置资料，TSDB 管时序与事件历史，避免将底层 TSDB API 散落进 `server.go`。

**Tech Stack:** Go、Prometheus TSDB、现有 Go test、现有前台原生 JS（`monitor.js`）、Docker helper 更新链路。

---

## 文件结构与职责边界

### 需要修改的现有文件

- `cmd/agent/main.go`
  - Agent CLI 启动入口；接入新的状态路径解析。
- `cmd/cyber-monitor/main.go`
  - `mode=agent` 启动入口；保持与 `cmd/agent/main.go` 一致的身份解析行为。
- `internal/agent/identity.go`
  - 节点 ID / token 路径解析、旧路径迁移、Docker 指纹 UUID 逻辑。
- `internal/agent/identity_test.go`
  - Agent 身份解析与迁移测试。
- `internal/agent/agent.go`
  - 启动时读取 persisted token、上报与更新时沿用稳定身份。
- `internal/updater/docker_managed.go`
  - Docker helper 重建容器时回填 `CM_NODE_ID`。
- `internal/server/server.go`
  - 历史管理器接入、公共历史 API、删除节点联动删除历史、离线 tracker 挂接、AI 历史数据来源替换。
- `internal/server/persist.go`
  - 从 `test_history.json` 迁移逻辑、离线 tracker 持久化状态结构。
- `internal/server/ai.go`
  - AI 上下文新增离线统计摘要。
- `internal/server/web/assets/monitor.js`
  - 默认 `1D`、按范围请求历史、按 `node_id + range_key` 缓存。
- `internal/server/web/assets/styles.css`
  - 如有必要，补充历史加载态样式。
- `Dockerfile`
  - 如需要，显式确保运行用户 home 目录可写。
- `README.md`
  - 文档更新：`node id` 默认路径、Docker 无卷 fallback、历史曲线范围与离线统计说明。
- `agent-example.yml`
  - 说明 Docker 运行参数与可选 home 挂载方式。

### 需要新增的文件

- `internal/agent/state_paths.go`（可选，若不想继续堆在 `identity.go`）
  - 状态目录 / home / 旧路径迁移辅助函数。
- `internal/updater/docker_managed_test.go`
  - Docker helper 回填 `CM_NODE_ID` 行为测试。
- `internal/server/history/manager.go`
  - 统一历史管理入口，屏蔽 network/offline 两类 TSDB 实现。
- `internal/server/history/network_store.go`
  - 网络连通性历史写入、查询、删除。
- `internal/server/history/offline_store.go`
  - 离线事件写入、查询、删除。
- `internal/server/history/query.go`
  - 时间窗查询、下采样、转 `TestHistoryEntry`。
- `internal/server/history/migrate.go`
  - `test_history.json` -> network TSDB 迁移。
- `internal/server/history/types.go`
  - 统一历史查询响应结构、离线摘要结构。
- `internal/server/history/network_store_test.go`
  - 网络连通性 366 天滚动窗口与删除测试。
- `internal/server/history/offline_store_test.go`
  - 离线事件永久保存与统计测试。
- `internal/server/history/migrate_test.go`
  - 历史迁移测试。
- `internal/server/history/delete_test.go`
  - 精确按 `node_id` 删除测试。
- `internal/server/public_history_test.go`
  - 公共历史查询接口测试。
- `internal/server/offline_tracker_test.go`
  - 离线 tracker 恢复写事件测试。
- `internal/server/ai_offline_summary_test.go`
  - AI 离线摘要测试。
- `docs/superpowers/specs/2026-04-09-agent-tsdb-node-identity-design.md`
  - 已存在，作为本计划执行依据。

### 不建议直接修改的边界

- 不要把 Prometheus TSDB API 直接散落进 `internal/server/server.go`。
- 不要让前台继续依赖 `/api/v1/public/snapshot` 中的 `test_history` 作为长期历史来源。
- 不要把离线事件统计混入现有告警状态 `alerted`，必须有独立 tracker。

---

## Task 1：重构 Agent 节点身份解析与旧路径迁移

**Files:**
- Modify: `internal/agent/identity.go`
- Modify: `cmd/agent/main.go`
- Modify: `cmd/cyber-monitor/main.go`
- Test: `internal/agent/identity_test.go`

- [ ] **Step 1: 写失败测试，覆盖新优先级与迁移行为**

```go
func TestResolveNodeIDPrefersHomeFileBeforeLegacyPath(t *testing.T) {
    home := t.TempDir()
    legacyDir := t.TempDir()
    t.Setenv("HOME", home)

    homeFile := filepath.Join(home, ".cybermonitor-node-id")
    legacyFile := filepath.Join(legacyDir, ".cybermonitor-node-id")
    os.WriteFile(homeFile, []byte("home-node\n"), 0o600)
    os.WriteFile(legacyFile, []byte("legacy-node\n"), 0o600)

    got, migrated, err := resolveNodeIDWithFallbacks(resolveNodeIDOptions{
        Explicit:    "",
        ExplicitFile:"",
        LegacyPath:  legacyFile,
        IsDocker:    false,
    })

    if err != nil { t.Fatal(err) }
    if got != "home-node" { t.Fatalf("want home-node, got %q", got) }
    if migrated { t.Fatal("did not expect migration when home file already exists") }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/agent -run 'TestResolveNodeID|TestResolveOrCreateNodeID' -count=1`
Expected: FAIL，当前实现只认识显式值 / 指定文件 / 二进制旁文件，不支持 home 路径优先与旧路径迁移。

- [ ] **Step 3: 实现新的状态路径解析与旧路径迁移**

关键实现要点：

```go
func defaultNodeIDHomePath() (string, error) {
    home, err := os.UserHomeDir()
    if err != nil || strings.TrimSpace(home) == "" {
        return "", fmt.Errorf("resolve home dir: %w", err)
    }
    return filepath.Join(home, ".cybermonitor-node-id"), nil
}

func resolveNodeIDWithFallbacks(opts resolveNodeIDOptions) (nodeID string, migrated bool, err error) {
    if explicit := strings.TrimSpace(opts.Explicit); explicit != "" {
        return explicit, false, nil
    }
    if opts.ExplicitFile != "" {
        return readTrimmedFile(opts.ExplicitFile)
    }
    homeFile, err := defaultNodeIDHomePath()
    if err == nil {
        if value, readErr := readTrimmedFile(homeFile); readErr == nil && value != "" {
            return value, false, nil
        }
    }
    if value, readErr := readTrimmedFile(opts.LegacyPath); readErr == nil && value != "" {
        if homeFile != "" {
            _ = writeTrimmedFile(homeFile, value)
        }
        return value, true, nil
    }
    return "", false, os.ErrNotExist
}
```

- [ ] **Step 4: 增加新节点 UUID 生成逻辑，仅用于真正首次生成**

```go
func generateRandomNodeUUID() string {
    id, err := uuid.NewRandom()
    if err != nil {
        return uuid.NewSHA1(uuid.NameSpaceOID, []byte(strconv.FormatInt(time.Now().UnixNano(), 10))).String()
    }
    return id.String()
}
```

要求：
- 旧值保持原样，不做格式转换。
- 只有在完全没有可复用 ID 时才生成 UUID。

- [ ] **Step 5: 在两个 Agent 启动入口接入统一解析函数**

将 `cmd/agent/main.go` 与 `cmd/cyber-monitor/main.go` 中对 `ResolveStateFilePath()` / `ResolveOrCreateNodeID()` 的调用替换成新的统一入口，例如：

```go
resolvedNodeID, nodeIDFileUsed, err := agent.ResolveNodeID(agent.NodeIDOptions{
    Explicit:      *nodeID,
    ExplicitFile:  *nodeIDFile,
    DeployMode:    updater.DetectDeployMode(),
    HostRoot:      *hostRoot,
})
```

- [ ] **Step 6: 运行测试确认通过**

Run: `go test ./internal/agent -run 'TestResolveNodeID|TestResolveOrCreateNodeID|TestPersistAgentToken' -count=1`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add internal/agent/identity.go internal/agent/identity_test.go cmd/agent/main.go cmd/cyber-monitor/main.go
git commit -m "feat: persist agent node id in home directory"
```

---

## Task 2：实现 Docker 无卷场景的宿主机指纹 UUID 与 token 持久化延续

**Files:**
- Modify: `internal/agent/identity.go`
- Modify: `internal/agent/agent.go`
- Test: `internal/agent/identity_test.go`
- Test: `internal/agent/update_test.go`

- [ ] **Step 1: 写失败测试，覆盖 Docker fallback 指纹 UUID**

```go
func TestResolveNodeIDUsesStableDockerFingerprintWhenNoFilesExist(t *testing.T) {
    hostRoot := t.TempDir()
    os.MkdirAll(filepath.Join(hostRoot, "etc"), 0o755)
    os.WriteFile(filepath.Join(hostRoot, "etc", "machine-id"), []byte("abcd-machine-id\n"), 0o644)

    got1, _, err := resolveNodeIDWithFallbacks(resolveNodeIDOptions{
        IsDocker: true,
        HostRoot: hostRoot,
    })
    if err != nil { t.Fatal(err) }

    got2, _, err := resolveNodeIDWithFallbacks(resolveNodeIDOptions{
        IsDocker: true,
        HostRoot: hostRoot,
    })
    if err != nil { t.Fatal(err) }

    if got1 != got2 { t.Fatalf("expected stable node id, got %q vs %q", got1, got2) }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/agent -run 'TestResolveNodeIDUsesStableDockerFingerprint|TestMaybeApplyRemoteUpdate' -count=1`
Expected: FAIL，当前没有宿主机指纹逻辑。

- [ ] **Step 3: 实现宿主机指纹读取与确定性 UUID 生成**

```go
func resolveHostFingerprint(hostRoot string) (string, error) {
    candidates := []string{
        filepath.Join(hostRoot, "etc", "machine-id"),
        filepath.Join(hostRoot, "var", "lib", "dbus", "machine-id"),
        filepath.Join(hostRoot, "etc", "hostname"),
    }
    for _, path := range candidates {
        if value, err := readTrimmedFile(path); err == nil && value != "" {
            return value, nil
        }
    }
    return "", fmt.Errorf("no stable host fingerprint")
}

func deriveStableNodeIDFromFingerprint(fingerprint string) string {
    return uuid.NewSHA1(uuid.NameSpaceURL, []byte("cybermonitor-node:"+strings.TrimSpace(fingerprint))).String()
}
```

- [ ] **Step 4: 确保 persisted dedicated token 仍优先读取**

在 `internal/agent/agent.go` 中保持以下行为：
- 启动时优先读取 `~/.cybermonitor-agent-token`
- 服务端返回 dedicated token 后写回该文件
- 后续重启优先使用 dedicated token

补一条测试，证明 bootstrap -> dedicated token -> persisted token 的路径不被新身份逻辑破坏。

- [ ] **Step 5: 运行测试确认通过**

Run: `go test ./internal/agent -run 'TestResolveNodeIDUsesStableDockerFingerprint|TestPersistAgentToken|TestMaybeApplyRemoteUpdate' -count=1`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add internal/agent/identity.go internal/agent/identity_test.go internal/agent/agent.go internal/agent/update_test.go
git commit -m "feat: stabilize docker agent identity with host fingerprint"
```

---

## Task 3：增强 Docker helper，重建容器时回填 `CM_NODE_ID`

**Files:**
- Modify: `internal/updater/docker_managed.go`
- Add: `internal/updater/docker_managed_test.go`

- [ ] **Step 1: 写失败测试，验证 helper 会把当前 `node id` 回填进新容器 env**

```go
func TestBuildReplacementSpecBackfillsCMNodeID(t *testing.T) {
    inspect := fakeContainerInspectWithEnv([]string{
        "CM_SERVER_URL=http://127.0.0.1:25012",
        "CM_AGENT_TOKEN=bootstrap-token",
    })

    cfg, _, _, _ := buildReplacementSpec(inspect, "ghcr.io/example/agent:1.2.3", "node-abc")

    joined := strings.Join(cfg.Env, "\n")
    if !strings.Contains(joined, "CM_NODE_ID=node-abc") {
        t.Fatalf("expected replacement env to include CM_NODE_ID, got %v", cfg.Env)
    }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/updater -run TestBuildReplacementSpecBackfillsCMNodeID -count=1`
Expected: FAIL，当前 `buildReplacementSpec()` 不接收 node id，也不注入 env。

- [ ] **Step 3: 修改 replacement spec 构造逻辑**

关键改动：

```go
func buildReplacementSpec(inspect dockertypes.ContainerJSON, targetImage, currentNodeID string) (*container.Config, *container.HostConfig, *network.NetworkingConfig, map[string]*network.EndpointSettings) {
    cfg := &container.Config{ ... }
    if strings.TrimSpace(currentNodeID) != "" && !envContainsKey(cfg.Env, "CM_NODE_ID") {
        cfg.Env = append(cfg.Env, "CM_NODE_ID="+strings.TrimSpace(currentNodeID))
    }
    return cfg, &hostCfg, netCfg, extraNetworks
}
```

`currentNodeID` 需要来自当前容器 env、状态文件或 helper 环境变量。最简单的策略是在 Agent 发起更新前，将当前节点 ID 放入 helper env，例如 `CM_DOCKER_HELPER_NODE_ID`。

- [ ] **Step 4: 从 Agent 更新链路传递当前 `node id` 到 helper**

在 `internal/agent/agent.go` -> `maybeApplyRemoteUpdate()` 调用 Docker helper 时，将当前 `cfg.NodeID` 传入 helper 环境。

- [ ] **Step 5: 运行测试确认通过**

Run: `go test ./internal/updater -run TestBuildReplacementSpecBackfillsCMNodeID -count=1`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add internal/updater/docker_managed.go internal/updater/docker_managed_test.go internal/agent/agent.go
git commit -m "feat: preserve node id during docker agent recreation"
```

---

## Task 4：引入历史管理层与 network TSDB（366 天滚动窗口）

**Files:**
- Add: `internal/server/history/manager.go`
- Add: `internal/server/history/network_store.go`
- Add: `internal/server/history/query.go`
- Add: `internal/server/history/network_store_test.go`
- Add: `internal/server/history/migrate.go`
- Add: `internal/server/history/migrate_test.go`
- Modify: `internal/server/persist.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: 写失败测试，覆盖 366 天滚动窗口**

```go
func TestNetworkHistoryRetentionKeepsRolling366DayWindow(t *testing.T) {
    store := newTestNetworkHistoryStore(t)
    start := time.Unix(1700000000, 0).UTC()

    for i := 0; i < 367; i++ {
        day := start.Add(time.Duration(i) * 24 * time.Hour)
        err := store.AppendBatch("node-a", []metrics.NetworkTestResult{{
            Type: "tcp", Host: "example.com", Port: 443, Name: "https", CheckedAt: day.Unix(),
            LatencyMs: ptr(12.3), PacketLoss: 0,
        }}, day)
        if err != nil { t.Fatal(err) }
    }

    got, err := store.QueryRange("node-a", start, start.Add(367*24*time.Hour))
    if err != nil { t.Fatal(err) }
    entry := got["tcp|example.com|443|https"]
    if len(entry.Times) != 366 { t.Fatalf("want 366 points, got %d", len(entry.Times)) }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server/history -run TestNetworkHistoryRetentionKeepsRolling366DayWindow -count=1`
Expected: FAIL（目录 / store 尚不存在）。

- [ ] **Step 3: 实现 history manager 与 network store**

关键接口建议：

```go
type Manager struct {
    network *NetworkStore
    offline *OfflineStore
}

type NetworkStore interface {
    AppendBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error
    QueryRange(nodeID string, from, to time.Time, rangeKey string) (map[string]*server.TestHistoryEntry, error)
    DeleteNode(nodeID string) error
    Close() error
}
```

network store 要点：
- metric：`cm_network_test_latency_ms` / `cm_network_test_packet_loss` / `cm_network_test_availability`
- label：`node_id` / `type` / `host` / `port` / `name`
- retention：最近 366 天
- 返回结果仍适配现有 `TestHistoryEntry`

- [ ] **Step 4: 将旧 `test_history.json` 迁移逻辑放入独立 migrate 层**

迁移流程：

```go
func MigrateLegacyJSONIfNeeded(path string, networkStore *PromNetworkStore) error {
    payload, exists, _, err := loadTestHistoryData(path)
    if err != nil || !exists { return err }
    for nodeID, tests := range payload.Nodes {
        for key, entry := range tests {
            // parse key -> write samples into TSDB
        }
    }
    return os.Rename(path, path+".bak")
}
```

- [ ] **Step 5: 在服务端初始化时创建 history manager，并迁移旧历史**

在 `internal/server/server.go` 中新增：
- 初始化 history manager
- 启动时尝试迁移 `test_history.json`
- `Store` 中增加 history manager 字段，作为新的历史主存储

- [ ] **Step 6: 运行测试确认通过**

Run: `go test ./internal/server/history -count=1`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add internal/server/history internal/server/persist.go internal/server/server.go
git commit -m "feat: add tsdb-backed network history store"
```

---

## Task 5：实现离线事件 TSDB 与独立 offline tracker（永久保存）

**Files:**
- Add: `internal/server/history/offline_store.go`
- Add: `internal/server/history/offline_store_test.go`
- Add: `internal/server/offline_tracker_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/persist.go`

- [ ] **Step 1: 写失败测试，覆盖“离线后恢复写 1 条事件”**

```go
func TestOfflineTrackerWritesEventOnRecovery(t *testing.T) {
    tracker := newTestOfflineTracker(t)
    nodeID := "node-a"
    start := time.Unix(1700000000, 0)
    end := start.Add(5 * time.Minute)

    tracker.MarkOffline(nodeID, start)
    if err := tracker.MarkOnline(nodeID, end); err != nil { t.Fatal(err) }

    summary, err := tracker.QuerySummary(nodeID, time.Unix(0, 0), end.Add(time.Hour))
    if err != nil { t.Fatal(err) }
    if summary.TotalCount != 1 { t.Fatalf("want 1 event, got %d", summary.TotalCount) }
    if summary.LongestDurationSec != 300 { t.Fatalf("want 300, got %d", summary.LongestDurationSec) }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server -run TestOfflineTrackerWritesEventOnRecovery -count=1`
Expected: FAIL，当前没有独立 offline tracker / offline TSDB。

- [ ] **Step 3: 实现独立 offline tracker，不复用 `alerted`**

要点：
- tracker 维护“当前离线会话状态”（节点是否离线、离线起始时间）
- 该状态要进入持久化层，而不是只存在内存
- 节点恢复时写入 metric `cm_node_offline_duration_seconds`
- 离线事件永久保存，不参与 366 天清理

建议新增持久化结构：

```go
type OfflineSessionState struct {
    StartedAt int64 `json:"started_at"`
}
```

- [ ] **Step 4: 将 tracker 挂到 Store.Update / 状态收集流程**

在 `Store.Update(stats)` 旁边引入统一 offline transition 检查：
- 在线 -> 离线：标记 start
- 离线 -> 在线：写事件并清理会话

不要把这个逻辑只挂在告警函数 `CollectAlertEvents()` 中，否则关闭告警后历史会失真。

- [ ] **Step 5: 运行测试确认通过**

Run: `go test ./internal/server -run 'TestOfflineTracker|TestAlert' -count=1`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add internal/server/history/offline_store.go internal/server/history/offline_store_test.go internal/server/server.go internal/server/persist.go internal/server/offline_tracker_test.go
git commit -m "feat: persist offline events in tsdb"
```

---

## Task 6：删除节点时精确删除该节点 TSDB 数据

**Files:**
- Add: `internal/server/history/delete_test.go`
- Modify: `internal/server/history/manager.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: 写失败测试，验证删除 `node-a` 不影响 `node-b`**

```go
func TestDeleteNodeRemovesOnlyTargetNodeHistory(t *testing.T) {
    mgr := newTestHistoryManager(t)
    seedNodeHistory(t, mgr, "node-a")
    seedNodeHistory(t, mgr, "node-b")

    if err := mgr.DeleteNode("node-a"); err != nil { t.Fatal(err) }

    aSummary, _ := mgr.QueryOfflineSummary("node-a", time.Unix(0,0), time.Now())
    bSummary, _ := mgr.QueryOfflineSummary("node-b", time.Unix(0,0), time.Now())

    if aSummary.TotalCount != 0 { t.Fatalf("expected node-a data removed") }
    if bSummary.TotalCount == 0 { t.Fatalf("expected node-b data to remain") }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server/history -run TestDeleteNodeRemovesOnlyTargetNodeHistory -count=1`
Expected: FAIL

- [ ] **Step 3: 实现 `DeleteNode(nodeID)` 同时删除两类历史**

```go
func (m *Manager) DeleteNode(nodeID string) error {
    if err := m.network.DeleteNode(nodeID); err != nil { return err }
    if err := m.offline.DeleteNode(nodeID); err != nil { return err }
    return nil
}
```

并在 `Store.DeleteNode()` 中调用 `historyManager.DeleteNode(nodeID)`。

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/server/history -run TestDeleteNodeRemovesOnlyTargetNodeHistory -count=1`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/server/history/delete_test.go internal/server/history/manager.go internal/server/server.go
git commit -m "feat: delete node-specific history from tsdb"
```

---

## Task 7：新增公共历史查询 API，并让前台按时间范围真实取数

**Files:**
- Add: `internal/server/public_history_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/web/assets/monitor.js`
- Modify: `internal/server/web/assets/styles.css`

- [ ] **Step 1: 写失败测试，覆盖公共历史接口不同范围返回不同窗口**

```go
func TestPublicNodeHistoryRangeReturnsRequestedWindow(t *testing.T) {
    baseURL, store := startTestServerWithHistory(t)
    seedNetworkHistoryDays(t, store, "node-a", 30)

    resp := httpGetJSON(t, baseURL+"/api/v1/public/nodes/node-a/history?range=7d")
    got := decodeHistoryResponse(t, resp)

    if got.RangeKey != "7d" { t.Fatalf("want 7d, got %q", got.RangeKey) }
    if !coversRecentDays(got, 7) { t.Fatal("expected 7d window") }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server -run TestPublicNodeHistoryRangeReturnsRequestedWindow -count=1`
Expected: FAIL，当前无该接口。

- [ ] **Step 3: 新增公共历史接口与 server 侧范围解析**

示意：

```go
publicMux.HandleFunc("/api/v1/public/nodes/", func(w http.ResponseWriter, r *http.Request) {
    // parse /api/v1/public/nodes/{node_id}/history
    // parse range=1d|7d|30d|1y
    // call historyManager.QueryNetworkRange(nodeID, from, to, rangeKey)
    // return { node_id, range_key, from, to, tests }
})
```

- [ ] **Step 4: 修改 `monitor.js`，首次展开固定默认 `1D`**

关键要求：
- 删除“按已有历史跨度自动猜默认 `1W` / `1D`”的逻辑
- 节点首次展开固定 `1D`
- 用户切换后按节点记住选择

- [ ] **Step 5: 修改 `monitor.js`，按 `node_id + range_key` 请求并缓存历史**

关键实现：

```js
async function fetchNodeHistory(nodeId, rangeKey) {
  const resp = await fetch(`${base}/api/v1/public/nodes/${encodeURIComponent(nodeId)}/history?range=${rangeKey}`, {
    cache: "no-store",
  });
  // save by nodeId + rangeKey
}
```

绝不能继续只依赖：
- `payload.test_history`
- 页面运行期临时缓存
- `localStorage` 中某一份全局历史

- [ ] **Step 6: 写前端数据流测试 / 至少补服务端断言 + JS 单元断言**

如果当前前端没有现成测试框架，至少要：
- 在 Go 侧证明 `1d / 7d / 30d / 1y` 返回窗口正确
- 在 JS 层为范围切换逻辑补最小可运行测试，或提炼纯函数后测试其缓存 key / 请求参数逻辑

- [ ] **Step 7: 运行测试确认通过**

Run:
- `go test ./internal/server -run 'TestPublicNodeHistory|TestServer' -count=1`
- 如果引入前端测试：`npm --prefix admin-ui test` 或项目内对应命令

Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add internal/server/server.go internal/server/public_history_test.go internal/server/web/assets/monitor.js internal/server/web/assets/styles.css
git commit -m "feat: fetch public history by node and range"
```

---

## Task 8：修复“只能看到最近 24H”的端到端数据窗口问题

**Files:**
- Modify: `internal/server/web/assets/monitor.js`
- Test: `internal/server/public_history_test.go`
- Test: `internal/server/test_history_trim_test.go`（必要时调整或补充）

- [ ] **Step 1: 写失败测试，证明 `1W / 1M / 1Y` 不是 24H 缩水数据**

```go
func TestPublicNodeHistoryOneYearDoesNotCollapseTo24Hours(t *testing.T) {
    baseURL, store := startTestServerWithHistory(t)
    seedNetworkHistoryDays(t, store, "node-a", 366)

    resp := httpGetJSON(t, baseURL+"/api/v1/public/nodes/node-a/history?range=1y")
    got := decodeHistoryResponse(t, resp)

    if !coversRecentDays(got, 366) {
        t.Fatal("expected 366-day window, not recent 24h only")
    }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server -run TestPublicNodeHistoryOneYearDoesNotCollapseTo24Hours -count=1`
Expected: FAIL

- [ ] **Step 3: 调整前台 history state，避免 `1D` 缓存污染 `1Y`**

建议把缓存结构从：

```js
state.testHistory: Map<nodeId, historyMap>
```

升级为：

```js
state.testHistoryByRange: Map<nodeId, Map<rangeKey, historyMap>>
```

并在渲染时明确取：

```js
const historyMap = getHistoryForNodeRange(nodeId, activeRange);
```

- [ ] **Step 4: 刷新页面后重新验证 1W / 1M / 1Y 取数**

手工命令 / 测试约束：
- 清空浏览器 localStorage
- 再次请求 `1W / 1M / 1Y`
- 仍能从服务端取到正确窗口

- [ ] **Step 5: 运行测试确认通过**

Run: `go test ./internal/server -run 'TestPublicNodeHistory.*' -count=1`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add internal/server/web/assets/monitor.js internal/server/public_history_test.go internal/server/test_history_trim_test.go
git commit -m "fix: load full history windows beyond 24h"
```

---

## Task 9：将离线统计接入 AI 上下文

**Files:**
- Modify: `internal/server/ai.go`
- Add: `internal/server/ai_offline_summary_test.go`
- Modify: `internal/server/ai_context_test.go`

- [ ] **Step 1: 写失败测试，覆盖 AI 上下文中的离线统计摘要**

```go
func TestAIContextIncludesOfflineSummary(t *testing.T) {
    ctx := buildAIContextFromFixtures(t, aiFixtureWithOfflineEvents())

    if ctx.OfflineSummary.TotalCount != 3 {
        t.Fatalf("want 3 offline events, got %d", ctx.OfflineSummary.TotalCount)
    }
    if ctx.OfflineSummary.LongestDurationSec != 4200 {
        t.Fatalf("want longest 4200, got %d", ctx.OfflineSummary.LongestDurationSec)
    }
}
```

- [ ] **Step 2: 运行测试，确认当前实现失败**

Run: `go test ./internal/server -run 'TestAIContextIncludesOfflineSummary|TestAIContext' -count=1`
Expected: FAIL

- [ ] **Step 3: 在 AI 上下文中增加 offline summary 字段**

建议摘要结构：

```go
type aiOfflineSummary struct {
    TotalCount            int                `json:"total_count"`
    Last30dCount          int                `json:"last_30d_count"`
    LongestDurationSec    int64              `json:"longest_duration_sec"`
    AvgDurationSec        float64            `json:"avg_duration_sec"`
    LastOfflineRecoveredAt int64             `json:"last_offline_recovered_at,omitempty"`
    RecentSessions        []aiOfflineSession `json:"recent_sessions,omitempty"`
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/server -run 'TestAIContextIncludesOfflineSummary|TestAIContext' -count=1`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/server/ai.go internal/server/ai_offline_summary_test.go internal/server/ai_context_test.go
git commit -m "feat: add offline history summary to ai context"
```

---

## Task 10：文档、示例与最终验证

**Files:**
- Modify: `README.md`
- Modify: `agent-example.yml`
- Modify: `docs/superpowers/specs/2026-04-09-agent-tsdb-node-identity-design.md`（仅在实现发现必要偏差时）

- [ ] **Step 1: 更新 README 中的节点 ID 与历史查询说明**

至少补充：
- `node id` 默认在 `~/.cybermonitor-node-id`
- Docker 无卷时使用宿主机指纹稳定 UUID
- 若使用 home 挂载，可继续复用 home 文件
- 公共前台支持 `1D / 1W / 1M / 1Y`
- 离线统计会永久保留并用于 AI 查询

- [ ] **Step 2: 更新 `agent-example.yml` 注释**

示例中注明：
- `CM_NODE_ID` 仍可显式指定
- 不指定时将走新默认逻辑
- 如需持久化 home，可自行挂载 `/home/cm`

- [ ] **Step 3: 运行完整验证命令**

```bash
go test ./internal/agent ./internal/updater ./internal/server ./internal/server/history -count=1
```

如果前端新增测试命令，也要一起执行。

Expected: PASS

- [ ] **Step 4: 记录手工回放结果**

至少验证以下 4 个场景并记录结果：
1. 裸机升级，旧节点 ID 不变。
2. Docker 无显式 ID、无卷重建，节点 ID 稳定。
3. 服务端下发 Docker 更新，节点仍映射到原节点。
4. 前台 `1D / 1W / 1M / 1Y` 都能看到对应真实历史窗口。

- [ ] **Step 5: 提交**

```bash
git add README.md agent-example.yml
git commit -m "docs: document node identity and history behavior"
```

---

## 本地审阅结论（代替 subagent review）

由于当前会话未显式授权使用 subagent，本计划通过本地自审完成 review，重点确认了以下事项：

1. 任务顺序遵循“先身份、再 TSDB、最后前台与 AI”，避免耦合失控。
2. 所有关键行为变化均先写失败测试，再实现，再验证通过。
3. 删除节点历史时明确要求按 `node_id` 精确删除，防止误删其他节点。
4. 前台时间范围读取被列为硬验收项，避免出现“按钮能切，实际还是最近 24H”的假修复。

---

## 执行提示

推荐严格按任务顺序执行，不要跨任务提前实现：

1. 先把身份稳定性与兼容性做实。
2. 再落 history manager 与 TSDB。
3. 再接前台取数与 AI 摘要。
4. 每个任务结束后运行对应测试并提交。

