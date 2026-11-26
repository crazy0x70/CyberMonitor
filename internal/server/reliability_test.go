package server

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	settings, err := initSettings(Config{JWTSecret: "test-jwt-secret"})
	if err != nil {
		t.Fatalf("initSettings failed: %v", err)
	}
	return &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        settings,
		alerted:         make(map[string]AlertedState),
		offlineSessions: make(map[string]OfflineSessionState),
		alertStates:     make(map[string]RuleAlertState),
		ruleSamples:     make(map[string][]ruleSample),
		loginAttempts:   make(map[string]*loginAttempt),
		configRefresh:   make(map[string]struct{}),
		startedAt:       time.Now().Add(-2 * time.Hour),
	}
}

func TestOfflineAlertRecoveryAfterRetrySuccess(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	nodeID := "node-alpha"
	store.settings.AlertOfflineSec = 60
	store.settings.AlertRules = []AlertRule{builtinOfflineAlertRule(60)}
	store.settings.NotifyChannels = []NotifyChannel{{
		ID:      "ch-feishu",
		Type:    notifyChannelTypeFeishu,
		Name:    "Feishu",
		Enabled: true,
		Secrets: map[string]string{"webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/test"},
	}}
	store.profiles[nodeID] = &NodeProfile{
		Alias:        "Alpha",
		AlertEnabled: boolPointer(true),
	}
	store.nodes[nodeID] = NodeState{
		Stats:    metrics.NodeStats{NodeID: nodeID, NodeName: "alpha", OS: "linux"},
		LastSeen: now.Add(-120 * time.Second),
	}

	// 1. Trigger offline alert.
	_, offlineEvents, _, _ := store.CollectAlertEvents(now)
	if len(offlineEvents) != 1 {
		t.Fatalf("expected 1 offline event, got %d", len(offlineEvents))
	}

	// 2. First delivery attempt fails on all channels -> RetryCount = 1, Delivered empty.
	store.RecordAlertDelivery(offlineEvents, map[string]bool{"ch-feishu": false}, true)
	if state := store.alerted[nodeID]; state.RetryCount != 1 || len(state.Delivered) != 0 {
		t.Fatalf("unexpected alerted state after failed attempt: %+v", state)
	}

	// 3. Retry triggers after backoff and succeeds on all channels.
	retryAt := store.alerted[nodeID].NextRetryAt.Add(time.Second)
	_, retryEvents, _, _ := store.CollectAlertEvents(retryAt)
	if len(retryEvents) != 1 {
		t.Fatalf("expected 1 retry offline event, got %d", len(retryEvents))
	}
	store.RecordAlertDelivery(retryEvents, map[string]bool{"ch-feishu": true}, true)
	if state := store.alerted[nodeID]; state.RetryCount != 0 || !state.Delivered["ch-feishu"] {
		t.Fatalf("expected Delivered recorded and RetryCount reset after retry success, got %+v", state)
	}

	// 4. Node recovers -> recovery notification must be emitted (not skipped).
	recoverAt := retryAt.Add(10 * time.Second)
	store.nodes[nodeID] = NodeState{
		Stats:    metrics.NodeStats{NodeID: nodeID, NodeName: "alpha", OS: "linux"},
		LastSeen: recoverAt,
	}
	_, _, recoveredEvents, skippedEvents := store.CollectAlertEvents(recoverAt)
	if len(recoveredEvents) != 1 {
		t.Fatalf("expected 1 recovery event, got %d (skipped=%d)", len(recoveredEvents), len(skippedEvents))
	}
	if len(skippedEvents) != 0 {
		t.Fatalf("expected 0 skipped recovery events, got %d", len(skippedEvents))
	}
}

func TestHiddenNodePreservedAcrossRestartAndConfigImport(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	nodeID := "hidden-node"
	store.settings.Groups = []string{"Prod"}
	store.settings.GroupTree = buildGroupTree([]string{"Prod"})
	store.profiles[nodeID] = &NodeProfile{
		ServerID:        "srv-stable-01",
		Alias:           "Secret Node",
		Groups:          []string{"Prod"},
		HideFromDisplay: true,
		HideFromCR:      true,
		HideFromAll:     true,
		AlertEnabled:    boolPointer(true),
		TrafficCounter: &TrafficCounter{
			CycleStart: now.Add(-24 * time.Hour).Unix(),
			LastSent:   1000,
			LastRecv:   2000,
			AccSent:    50000,
			AccRecv:    80000,
		},
	}
	store.nodes[nodeID] = NodeState{
		Stats:    metrics.NodeStats{NodeID: nodeID, NodeName: "secret"},
		LastSeen: now,
	}

	// 1. Verify persistence normalization (restart path) does NOT unhide the node.
	dataPath := filepath.Join(t.TempDir(), "state.json")
	if err := savePersistedData(dataPath, store.snapshotPersistedLocked()); err != nil {
		t.Fatalf("savePersistedData failed: %v", err)
	}
	loaded, ok, err := loadPersistedData(dataPath)
	if err != nil || !ok {
		t.Fatalf("loadPersistedData failed: ok=%v err=%v", ok, err)
	}
	loadedProfile := loaded.Profiles[nodeID]
	if loadedProfile == nil || !loadedProfile.HideFromDisplay || !loadedProfile.HideFromCR || !loadedProfile.HideFromAll {
		t.Fatalf("expected hidden flags preserved after reload, got %+v", loadedProfile)
	}

	// 2. Verify ExportConfig -> ImportConfig preserves hidden flags, ServerID, and TrafficCounter.
	exported := store.ExportConfig()
	if _, err := store.ImportConfig(exported); err != nil {
		t.Fatalf("ImportConfig failed: %v", err)
	}
	importedProfile := store.profiles[nodeID]
	if importedProfile == nil {
		t.Fatalf("missing profile after import")
	}
	if !importedProfile.HideFromDisplay || !importedProfile.HideFromCR || !importedProfile.HideFromAll {
		t.Fatalf("expected hidden flags preserved after import, got %+v", importedProfile)
	}
	if importedProfile.ServerID != "srv-stable-01" {
		t.Fatalf("expected ServerID preserved as srv-stable-01, got %q", importedProfile.ServerID)
	}
	if importedProfile.TrafficCounter == nil || importedProfile.TrafficCounter.AccSent != 50000 || importedProfile.TrafficCounter.AccRecv != 80000 {
		t.Fatalf("expected TrafficCounter preserved after import, got %+v", importedProfile.TrafficCounter)
	}
	if publicNodes := store.Snapshot(); len(publicNodes) != 0 {
		t.Fatalf("expected hidden node excluded from public Snapshot(), got %d nodes", len(publicNodes))
	}
}

func TestThresholdFiringStateClearedOnMuteExcludeAndDelete(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	nodeID := "node-hot"
	ruleID := "r_cpu_high"
	store.settings.AlertRules = []AlertRule{
		builtinOfflineAlertRule(300),
		{
			ID:            ruleID,
			Name:          "High CPU",
			Enabled:       true,
			Metric:        alertMetricCPU,
			Op:            alertOpGT,
			Threshold:     80,
			DurationSec:   0,
			Ratio:         0.7,
			Scope:         AlertScope{Mode: alertScopeAll},
			NotifyRecover: true,
			Repeat:        alertRepeatOnce,
		},
	}
	store.profiles[nodeID] = &NodeProfile{
		ServerID:     "srv-hot-1",
		Alias:        "Hot",
		AlertEnabled: boolPointer(true),
	}
	store.nodes[nodeID] = NodeState{
		Stats:    metrics.NodeStats{NodeID: nodeID, NodeName: "hot", CPU: metrics.CPUInfo{UsagePercent: 95}},
		LastSeen: now,
	}

	// Trigger FIRING state.
	batches := store.CollectRuleEvents(now, RuleEvalCadence{})
	if len(batches) != 1 || store.alertStatusCounts().Firing != 1 {
		t.Fatalf("expected 1 firing alert, batches=%d firing=%d", len(batches), store.alertStatusCounts().Firing)
	}

	// Case A: Excluding node from rule scope clears FIRING state on next evaluation.
	store.settings.AlertRules[1].Scope.Exclude = []string{nodeID}
	store.CollectRuleEvents(now.Add(time.Second), RuleEvalCadence{})
	if store.alertStatusCounts().Firing != 0 {
		t.Fatalf("expected firing count 0 after excluding node from rule scope, got %d", store.alertStatusCounts().Firing)
	}

	// Re-trigger FIRING state.
	store.settings.AlertRules[1].Scope.Exclude = nil
	store.CollectRuleEvents(now.Add(2*time.Second), RuleEvalCadence{})
	if store.alertStatusCounts().Firing != 1 {
		t.Fatalf("expected firing count 1 after re-including node, got %d", store.alertStatusCounts().Firing)
	}

	// Case B: Disabling alerts on node via UpdateProfile immediately clears FIRING state.
	if _, ok, err := store.UpdateProfile(nodeID, NodeProfileUpdate{AlertEnabled: boolPointer(false)}); err != nil || !ok {
		t.Fatalf("UpdateProfile failed: ok=%v err=%v", ok, err)
	}
	if store.alertStatusCounts().Firing != 0 {
		t.Fatalf("expected firing count 0 after muting node, got %d", store.alertStatusCounts().Firing)
	}

	// Re-enable and re-trigger, then verify DeleteNode clears alertStates.
	if _, ok, err := store.UpdateProfile(nodeID, NodeProfileUpdate{AlertEnabled: boolPointer(true)}); err != nil || !ok {
		t.Fatalf("UpdateProfile re-enable failed: ok=%v err=%v", ok, err)
	}
	store.CollectRuleEvents(now.Add(3*time.Second), RuleEvalCadence{})
	if store.alertStatusCounts().Firing != 1 {
		t.Fatalf("expected firing count 1 before delete, got %d", store.alertStatusCounts().Firing)
	}
	if _, err := store.DeleteNode(nodeID); err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}
	if store.alertStatusCounts().Firing != 0 || len(store.alertStates) != 0 {
		t.Fatalf("expected alertStates cleared after DeleteNode, got firing=%d len=%d", store.alertStatusCounts().Firing, len(store.alertStates))
	}
}

func TestUpdateSettingsValidationDoesNotLeakProfileMutations(t *testing.T) {
	store := newTestStore(t)
	store.settings.Groups = []string{"GroupA", "GroupB"}
	store.settings.GroupTree = buildGroupTree([]string{"GroupA", "GroupB"})
	store.profiles["node-1"] = &NodeProfile{
		Groups: []string{"GroupA"},
		Group:  "GroupA",
	}

	invalidDays := 99
	moves := []GroupMove{{From: "GroupA", To: "GroupB"}}
	_, err := store.UpdateSettings(SettingsUpdate{
		GroupMoves:          &moves,
		ResourceHistoryDays: &invalidDays,
	})
	if err == nil {
		t.Fatalf("expected error for invalid resource_history_days")
	}
	if got := store.profiles["node-1"].Groups; len(got) != 1 || got[0] != "GroupA" {
		t.Fatalf("expected profile groups unchanged after validation failure, got %v", got)
	}
}

func TestResolveAIProviderSelectionForModelsAllowsEmptyModel(t *testing.T) {
	settings := defaultAISettings()
	override := &AIProviderConfig{
		BaseURL: "https://api.example.com/v1",
		APIKey:  "sk-test-123",
		Model:   "",
	}
	if _, err := resolveAIProviderSelectionForModels(settings, aiProviderOpenAICompatible, override); err != nil {
		t.Fatalf("expected model listing selection to succeed without model, got %v", err)
	}
	if _, err := resolveAIProviderSelection(settings, aiProviderOpenAICompatible, override); err == nil {
		t.Fatalf("expected regular AI selection to reject empty model on openai_compatible")
	}
}

func TestAlertCalendarDaysUntilAcrossDST(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("timezone America/New_York unavailable: %v", err)
	}
	// 2026-03-08 is US spring-forward DST (23-hour day).
	now := time.Date(2026, 3, 5, 9, 0, 0, 0, loc)
	expireAt := time.Date(2026, 3, 12, 0, 0, 0, 0, loc).Unix()
	if got := alertCalendarDaysUntil(now, expireAt); got != 7 {
		t.Fatalf("expected 7 calendar days across DST spring-forward, got %d", got)
	}
}

func TestTrafficCounterIgnoresTransientZeroSample(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	profile := &NodeProfile{
		TrafficLimitBytes: 1024 * 1024,
		TrafficLimitType:  "sum",
		TrafficResetDay:   1,
	}
	// Initial baseline.
	store.applyTrafficCounterLocked("n1", profile, metrics.NodeStats{
		Network: metrics.NetworkIO{BytesSent: 100000, BytesRecv: 200000},
	}, now)
	// Transient 0/0 read failure sample must be ignored.
	store.applyTrafficCounterLocked("n1", profile, metrics.NodeStats{
		Network: metrics.NetworkIO{BytesSent: 0, BytesRecv: 0},
	}, now.Add(time.Second))
	if profile.TrafficCounter.LastSent != 100000 || profile.TrafficCounter.LastRecv != 200000 {
		t.Fatalf("expected LastSent/LastRecv preserved on transient 0/0 sample, got %+v", profile.TrafficCounter)
	}
	// Next healthy sample adds only real delta (1000 / 2000).
	store.applyTrafficCounterLocked("n1", profile, metrics.NodeStats{
		Network: metrics.NetworkIO{BytesSent: 101000, BytesRecv: 202000},
	}, now.Add(2*time.Second))
	if profile.TrafficCounter.AccSent != 1000 || profile.TrafficCounter.AccRecv != 2000 {
		t.Fatalf("expected AccSent=1000 AccRecv=2000, got %+v", profile.TrafficCounter)
	}
}

func TestSystemStatusMonitorReusesProcessInstance(t *testing.T) {
	m := newSystemStatusMonitor()
	m.sample()
	first := m.selfProc
	if first == nil {
		t.Fatalf("expected selfProc initialized after first sample")
	}
	m.sample()
	if m.selfProc != first {
		t.Fatalf("expected selfProc reused across samples")
	}
}

func TestProbesOverviewRawAccuracyAndPipeName(t *testing.T) {
	dataDir := t.TempDir()
	mgr, err := history.OpenManager(dataDir, 7)
	if err != nil {
		t.Fatalf("OpenManager failed: %v", err)
	}
	defer mgr.Close()

	store := newTestStore(t)
	store.historyManager = mgr
	nodeID := "node-probe"
	base := time.Now().UTC().Truncate(time.Minute).Add(-10 * time.Minute)
	lat := 12.5
	// Write 20 samples spaced 2s apart (all within a single 87s 24h downsample bucket):
	// 19 failures + 1 success => exact availability = 5.0%, exact samples = 20.
	for i := 0; i < 20; i++ {
		ts := base.Add(time.Duration(i*2) * time.Second)
		res := metrics.NetworkTestResult{
			Name:       "US | Cloudflare",
			Type:       "tcp",
			Host:       "1.1.1.1",
			Port:       443,
			Status:     "timeout",
			PacketLoss: 100,
			CheckedAt:  ts.Unix(),
		}
		if i == 10 {
			res.Status = "ok"
			res.LatencyMs = &lat
			res.PacketLoss = 0
		}
		if err := mgr.AppendNetworkBatch(nodeID, []metrics.NetworkTestResult{res}, ts); err != nil {
			t.Fatalf("AppendNetworkBatch failed: %v", err)
		}
	}

	rawStats, err := store.QueryNodeProbeOverviewStats(context.Background(), nodeID, base.Add(-23*time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryNodeProbeOverviewStats failed: %v", err)
	}
	targets := aggregateProbeTargetOverviewStats(map[string]map[string]*history.NetworkOverviewStats{
		nodeID: rawStats,
	})
	if len(targets) != 1 {
		t.Fatalf("expected 1 target (including '|' in name), got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Samples != 20 {
		t.Fatalf("expected 20 raw samples, got %d", got.Samples)
	}
	if math.Abs(got.AvailabilityPct-5.0) > 0.01 {
		t.Fatalf("expected 5.0%% availability, got %.2f%%", got.AvailabilityPct)
	}
	if got.P95LatencyMs == nil || math.Abs(*got.P95LatencyMs-12.5) > 0.01 {
		t.Fatalf("expected P95=12.5ms, got %v", got.P95LatencyMs)
	}
}

func TestVerifyEmbeddedWebAssets(t *testing.T) {
	if err := verifyEmbeddedWebAssets(); err != nil {
		t.Fatalf("verifyEmbeddedWebAssets failed: %v", err)
	}
}

func TestNotificationMessagesFormatting(t *testing.T) {
	ts := time.Date(2026, 11, 26, 16, 45, 12, 0, time.Local).Unix()
	offlineSingle := buildAlertMessage("Crazy0x70's Monitor", []AlertEvent{
		{Display: "BuyVM LasVegas", OfflineSec: 300, LastSeen: ts},
	})
	title, body := splitNotifyTitleBody(offlineSingle)
	if title != "【Crazy0x70's Monitor】🔴 节点离线 · BuyVM LasVegas" {
		t.Fatalf("unexpected offline single title: %q", title)
	}
	if !strings.Contains(body, "已离线：5分钟") || !strings.Contains(body, "最后在线：2026-11-26 16:45:12") {
		t.Fatalf("unexpected offline single body: %q", body)
	}

	recoverySingle := buildRecoveryMessage("Crazy0x70's Monitor", []AlertEvent{
		{Display: "BuyVM LasVegas", OfflineSec: 360, LastSeen: ts + 360},
	})
	title, body = splitNotifyTitleBody(recoverySingle)
	if title != "【Crazy0x70's Monitor】🟢 节点恢复 · BuyVM LasVegas" {
		t.Fatalf("unexpected recovery single title: %q", title)
	}
	if !strings.Contains(body, "中断时长：6分钟") || !strings.Contains(body, "恢复时间：2026-11-26 16:51:12") {
		t.Fatalf("unexpected recovery single body: %q", body)
	}

	offlineMulti := buildAlertMessage("CyberMonitor", []AlertEvent{
		{Display: "NodeA", OfflineSec: 300, LastSeen: ts},
		{Display: "NodeB", OfflineSec: 120, LastSeen: ts},
	})
	title, body = splitNotifyTitleBody(offlineMulti)
	if title != "【CyberMonitor】🔴 节点离线（2 台）" {
		t.Fatalf("unexpected offline multi title: %q", title)
	}
	if !strings.Contains(body, "• NodeA · 已离线 5分钟") || !strings.Contains(body, "• NodeB · 已离线 2分钟") {
		t.Fatalf("unexpected offline multi body: %q", body)
	}

	expiryMsg := buildRuleNoticeMessage(RuleNoticeBatch{
		SiteTitle: "CyberMonitor",
		Rule:      AlertRule{Name: "节点到期", Metric: alertMetricExpiry},
	}, []RuleAlertEvent{
		{Display: "BuyVM LasVegas", Days: 3, ExpireDate: "2026-12-01"},
	})
	title, body = splitNotifyTitleBody(expiryMsg)
	if title != "【CyberMonitor】⏳ 到期提醒 · BuyVM LasVegas" || body != "剩余时间：3 天（2026-12-01 到期）" {
		t.Fatalf("unexpected expiry message: title=%q body=%q", title, body)
	}

	trafficMsg := buildRuleNoticeMessage(RuleNoticeBatch{
		SiteTitle: "CyberMonitor",
		Rule:      AlertRule{Name: "流量配额", Metric: alertMetricTrafficQuota},
	}, []RuleAlertEvent{
		{Display: "BuyVM LasVegas", Value: 85.0, UsedBytes: 850_000_000_000, QuotaBytes: 1_000_000_000_000},
	})
	title, body = splitNotifyTitleBody(trafficMsg)
	if title != "【CyberMonitor】📶 流量提醒 · BuyVM LasVegas" || body != "本月已用：85.0%（850 GB / 1.0 TB）" {
		t.Fatalf("unexpected traffic message: title=%q body=%q", title, body)
	}
}



