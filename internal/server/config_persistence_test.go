package server

import (
	"path/filepath"
	"reflect"
	"testing"
)

func loadPersistedSettingsForTest(t *testing.T, dataDir string) Settings {
	t.Helper()

	payload, loaded, err := loadPersistedData(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatalf("load persisted data: %v", err)
	}
	if !loaded {
		t.Fatal("expected persisted data to exist")
	}
	return payload.Settings
}

func loadPersistedTestHistoryForTest(t *testing.T, dataDir string) TestHistoryData {
	t.Helper()

	payload, _, _, err := loadTestHistoryData(filepath.Join(dataDir, testHistoryFileName))
	if err != nil {
		t.Fatalf("load persisted test history: %v", err)
	}
	return payload
}

func TestMergeSettingsBackfillsMissingValuesWithoutOverwritingExisting(t *testing.T) {
	t.Parallel()

	fallback := initSettings(Config{
		AdminPath:  "/fallback-admin",
		AdminUser:  "fallback-user",
		AdminPass:  "fallback-pass",
		JWTSecret:  "fallback-jwt",
		AgentToken: "fallback-agent",
	})
	existing := Settings{
		AdminPath:           "/existing-admin",
		AdminUser:           "existing-user",
		AdminPass:           "existing-pass-hash",
		AlertTelegramToken:  "123456:token",
		AlertTelegramUserID: 9527,
		AISettings:          AISettings{},
	}

	merged := mergeSettings(existing, fallback)

	if merged.AdminPath != existing.AdminPath {
		t.Fatalf("expected admin path to stay %q, got %q", existing.AdminPath, merged.AdminPath)
	}
	if merged.AdminUser != existing.AdminUser {
		t.Fatalf("expected admin user to stay %q, got %q", existing.AdminUser, merged.AdminUser)
	}
	if merged.AdminPass != existing.AdminPass {
		t.Fatalf("expected admin pass to stay unchanged, got %q", merged.AdminPass)
	}
	if merged.AuthToken != fallback.AuthToken {
		t.Fatalf("expected auth token to be backfilled from fallback, got %q", merged.AuthToken)
	}
	if merged.AgentToken != fallback.AgentToken {
		t.Fatalf("expected agent token to be backfilled from fallback, got %q", merged.AgentToken)
	}
	if merged.SiteTitle != defaultSiteTitle {
		t.Fatalf("expected default site title %q, got %q", defaultSiteTitle, merged.SiteTitle)
	}
	if merged.HomeTitle != defaultHomeTitle {
		t.Fatalf("expected default home title %q, got %q", defaultHomeTitle, merged.HomeTitle)
	}
	if merged.HomeSubtitle != defaultHomeSub {
		t.Fatalf("expected default home subtitle %q, got %q", defaultHomeSub, merged.HomeSubtitle)
	}
	if merged.AlertOfflineSec != defaultAlertOfflineSec {
		t.Fatalf("expected default offline seconds %d, got %d", defaultAlertOfflineSec, merged.AlertOfflineSec)
	}
	if !reflect.DeepEqual(merged.AlertTelegramUserIDs, []int64{9527}) {
		t.Fatalf("expected legacy telegram user id to migrate, got %+v", merged.AlertTelegramUserIDs)
	}
	if merged.AlertTelegramUserID != 0 {
		t.Fatalf("expected legacy telegram user id field to be cleared, got %d", merged.AlertTelegramUserID)
	}
	if merged.AISettings.OpenAI.Model != defaultOpenAIModel {
		t.Fatalf("expected AI defaults to be merged, got %+v", merged.AISettings)
	}
}

func TestMergeSettingsMigratesLegacyAuthTokenToAgentToken(t *testing.T) {
	t.Parallel()

	fallback := initSettings(Config{
		JWTSecret: "new-jwt-secret",
	})
	existing := Settings{
		AdminPath:  "/legacy-admin",
		AdminUser:  "legacy-user",
		AdminPass:  "legacy-pass-hash",
		TokenSalt:  "legacy-salt",
		AuthToken:  "legacy-shared-token",
		AgentToken: "",
	}

	merged := mergeSettings(existing, fallback)

	if merged.AgentToken != "legacy-shared-token" {
		t.Fatalf("expected legacy auth token to migrate into agent token, got %q", merged.AgentToken)
	}
	if merged.AuthToken != "new-jwt-secret" {
		t.Fatalf("expected auth token to switch to fallback jwt secret, got %q", merged.AuthToken)
	}
}

func TestRunPreservesPersistedSettingsOnRestart(t *testing.T) {
	dataDir := t.TempDir()
	cfg := Config{
		Addr:       reserveTCPAddr(t),
		DataDir:    dataDir,
		AdminPath:  "/new-admin",
		AdminUser:  "new-user",
		AdminPass:  "new-pass",
		JWTSecret:  "new-jwt",
		AgentToken: "new-agent",
	}

	settings := initSettings(Config{
		AdminPath:  "/persist-admin",
		AdminUser:  "persist-user",
		AdminPass:  "persist-pass",
		JWTSecret:  "persist-jwt",
		AgentToken: "persist-agent",
	})
	settings.AgentEndpoint = "https://agents.persisted.example"
	settings.SiteTitle = "Persisted Site"
	settings.HomeTitle = "Persisted Home"
	settings.HomeSubtitle = "Persisted Subtitle"
	settings.AlertOfflineSec = 900
	settings.LoginFailLimit = 8
	settings.LoginFailWindowSec = 600
	settings.LoginLockSec = 300
	settings.Groups = []string{"prod", "prod/db"}
	settings.GroupTree = buildGroupTree(settings.Groups)
	settings.TestCatalog = []TestCatalogItem{
		{ID: "tcp-main", Name: "Main TCP", Type: "tcp", Host: "127.0.0.1", Port: 443},
	}

	if err := savePersistedData(filepath.Join(dataDir, "state.json"), PersistedData{
		Settings: settings,
		Profiles: map[string]*NodeProfile{},
		Nodes:    map[string]NodeState{},
	}); err != nil {
		t.Fatalf("save persisted data: %v", err)
	}

	startTestServer(t, cfg)

	persisted := loadPersistedSettingsForTest(t, dataDir)
	if persisted.AdminPath != settings.AdminPath {
		t.Fatalf("expected admin path %q to be preserved, got %q", settings.AdminPath, persisted.AdminPath)
	}
	if persisted.AdminUser != settings.AdminUser {
		t.Fatalf("expected admin user %q to be preserved, got %q", settings.AdminUser, persisted.AdminUser)
	}
	if persisted.AdminPass != settings.AdminPass {
		t.Fatalf("expected admin pass hash to stay unchanged")
	}
	if persisted.TokenSalt != settings.TokenSalt {
		t.Fatalf("expected token salt %q to be preserved, got %q", settings.TokenSalt, persisted.TokenSalt)
	}
	if persisted.AuthToken != settings.AuthToken {
		t.Fatalf("expected auth token %q to be preserved, got %q", settings.AuthToken, persisted.AuthToken)
	}
	if persisted.AgentToken != settings.AgentToken {
		t.Fatalf("expected agent token %q to be preserved, got %q", settings.AgentToken, persisted.AgentToken)
	}
	if persisted.AgentEndpoint != settings.AgentEndpoint {
		t.Fatalf("expected agent endpoint %q to be preserved, got %q", settings.AgentEndpoint, persisted.AgentEndpoint)
	}
	if persisted.SiteTitle != settings.SiteTitle {
		t.Fatalf("expected site title %q to be preserved, got %q", settings.SiteTitle, persisted.SiteTitle)
	}
	if persisted.HomeTitle != settings.HomeTitle {
		t.Fatalf("expected home title %q to be preserved, got %q", settings.HomeTitle, persisted.HomeTitle)
	}
	if persisted.HomeSubtitle != settings.HomeSubtitle {
		t.Fatalf("expected home subtitle %q to be preserved, got %q", settings.HomeSubtitle, persisted.HomeSubtitle)
	}
	if persisted.AlertOfflineSec != settings.AlertOfflineSec {
		t.Fatalf("expected offline seconds %d to be preserved, got %d", settings.AlertOfflineSec, persisted.AlertOfflineSec)
	}
	if persisted.LoginFailLimit != settings.LoginFailLimit {
		t.Fatalf("expected login fail limit %d to be preserved, got %d", settings.LoginFailLimit, persisted.LoginFailLimit)
	}
	if persisted.LoginFailWindowSec != settings.LoginFailWindowSec {
		t.Fatalf("expected login fail window %d to be preserved, got %d", settings.LoginFailWindowSec, persisted.LoginFailWindowSec)
	}
	if persisted.LoginLockSec != settings.LoginLockSec {
		t.Fatalf("expected login lock seconds %d to be preserved, got %d", settings.LoginLockSec, persisted.LoginLockSec)
	}
	if persisted.AISettings.OpenAI.Model != settings.AISettings.OpenAI.Model {
		t.Fatalf("expected AI settings to be preserved, got %+v", persisted.AISettings)
	}
}

func TestRunPreservesPersistedTestHistoryOnRestart(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cfg := Config{
		Addr:      reserveTCPAddr(t),
		DataDir:   dataDir,
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "admin123",
	}

	settings := initSettings(cfg)
	if err := savePersistedData(filepath.Join(dataDir, "state.json"), PersistedData{
		Settings: settings,
		Profiles: map[string]*NodeProfile{},
		Nodes:    map[string]NodeState{},
	}); err != nil {
		t.Fatalf("save persisted data: %v", err)
	}

	latencyA := 12.5
	latencyB := 28.8
	lossA := 0.0
	lossB := 2.5
	history := TestHistoryData{
		Version:   testHistoryVersion,
		UpdatedAt: 1_777_000_123,
		Nodes: map[string]map[string]*TestHistoryEntry{
			"node-a": {
				"icmp|1.1.1.1|0|Cloudflare": {
					Latency:        []*float64{&latencyA, &latencyB},
					Loss:           []*float64{&lossA, &lossB},
					Times:          []int64{1_777_000_000, 1_777_000_030},
					LastAt:         1_777_000_030,
					MinIntervalSec: 30,
					AvgIntervalSec: 30,
				},
			},
		},
	}
	if err := saveTestHistoryData(filepath.Join(dataDir, testHistoryFileName), history); err != nil {
		t.Fatalf("save test history: %v", err)
	}

	startTestServer(t, cfg)

	persisted := loadPersistedTestHistoryForTest(t, dataDir)
	entry := persisted.Nodes["node-a"]["icmp|1.1.1.1|0|Cloudflare"]
	if entry == nil {
		t.Fatal("expected persisted test history entry to survive restart")
	}
	if len(entry.Times) != 2 || entry.Times[0] != 1_777_000_000 || entry.Times[1] != 1_777_000_030 {
		t.Fatalf("expected test history timestamps to be preserved, got %+v", entry.Times)
	}
	if entry.LastAt != 1_777_000_030 {
		t.Fatalf("expected last_at to be preserved, got %d", entry.LastAt)
	}
	if entry.MinIntervalSec != 30 {
		t.Fatalf("expected min interval to be preserved, got %d", entry.MinIntervalSec)
	}
	if entry.AvgIntervalSec != 30 {
		t.Fatalf("expected average interval to be preserved, got %v", entry.AvgIntervalSec)
	}
	if len(entry.Latency) != 2 || entry.Latency[0] == nil || entry.Latency[1] == nil {
		t.Fatalf("expected latency samples to be preserved, got %+v", entry.Latency)
	}
	if *entry.Latency[0] != latencyA || *entry.Latency[1] != latencyB {
		t.Fatalf("expected latency values to be preserved, got %+v", entry.Latency)
	}
}

func TestImportConfigKeepsCurrentAgentTokenWhenPayloadLeavesItBlank(t *testing.T) {
	t.Parallel()

	settings := initSettings(Config{
		AdminPath:  "/cm-admin",
		AdminUser:  "admin",
		AdminPass:  "admin123",
		AgentToken: "persist-agent-token",
	})
	store := &Store{
		settings: settings,
		profiles: map[string]*NodeProfile{},
		nodes:    map[string]NodeState{},
	}

	payload := store.ExportConfig()
	if payload.Settings.AgentToken != "" {
		t.Fatalf("expected exported config to redact agent token, got %q", payload.Settings.AgentToken)
	}
	payload.Settings.SiteTitle = "Imported Site"

	view, reauthRequired, err := store.ImportConfig(payload)
	if err != nil {
		t.Fatalf("import config: %v", err)
	}
	if reauthRequired {
		t.Fatal("expected import to keep current login session when admin user is unchanged")
	}
	if view.SiteTitle != "Imported Site" {
		t.Fatalf("expected imported site title to apply, got %q", view.SiteTitle)
	}
	if view.AgentToken != "persist-agent-token" {
		t.Fatalf("expected current agent token to be preserved, got %q", view.AgentToken)
	}
	if store.settings.AgentToken != "persist-agent-token" {
		t.Fatalf("expected store agent token to stay unchanged, got %q", store.settings.AgentToken)
	}
}
