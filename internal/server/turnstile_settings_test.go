package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestUpdateSettingsRequiresTurnstileKeysInPairs(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{
			AdminPath: "/cm-admin",
			AdminUser: "admin",
			AdminPass: "admin123",
		}),
		profiles: map[string]*NodeProfile{},
		nodes:    map[string]NodeState{},
	}

	siteKeyOnly := "0x4AAAAA-site"
	if _, err := store.UpdateSettings(SettingsUpdate{
		TurnstileSiteKey: &siteKeyOnly,
	}); err == nil || !strings.Contains(err.Error(), "需要同时配置") {
		t.Fatalf("expected pair validation error, got %v", err)
	}

	siteKey := "0x4AAAAA-site"
	secretKey := "0x4AAAAA-secret"
	view, err := store.UpdateSettings(SettingsUpdate{
		TurnstileSiteKey:   &siteKey,
		TurnstileSecretKey: &secretKey,
	})
	if err != nil {
		t.Fatalf("update settings with full turnstile config: %v", err)
	}
	if view.TurnstileSiteKey != siteKey || view.TurnstileSecretKey != secretKey {
		t.Fatalf("unexpected turnstile settings view: %+v", view)
	}

	empty := ""
	view, err = store.UpdateSettings(SettingsUpdate{
		TurnstileSiteKey:   &empty,
		TurnstileSecretKey: &empty,
	})
	if err != nil {
		t.Fatalf("clear turnstile config: %v", err)
	}
	if view.TurnstileSiteKey != "" || view.TurnstileSecretKey != "" {
		t.Fatalf("expected empty turnstile config after clear, got %+v", view)
	}
}

func TestUpdateSettingsAllowsUpdatingAgentToken(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{
			AdminPath:  "/cm-admin",
			AdminUser:  "admin",
			AdminPass:  "admin123",
			AgentToken: "old-token",
		}),
		profiles: map[string]*NodeProfile{},
		nodes:    map[string]NodeState{},
	}

	nextToken := "new-agent-token"
	view, err := store.UpdateSettings(SettingsUpdate{
		AgentToken: &nextToken,
	})
	if err != nil {
		t.Fatalf("update agent token: %v", err)
	}
	if view.AgentToken != nextToken {
		t.Fatalf("expected updated agent token %q, got %q", nextToken, view.AgentToken)
	}
	if store.settings.AgentToken != nextToken {
		t.Fatalf("store settings agent token not updated, got %q", store.settings.AgentToken)
	}
}

func TestLoginConfigRouteOnlyExposesPublicTurnstileState(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "admin123",
		DataDir:   t.TempDir(),
	}

	settings := initSettings(cfg)
	settings.TurnstileSiteKey = "0x4AAAAA-site"
	settings.TurnstileSecretKey = "0x4AAAAA-secret"
	if err := savePersistedData(cfg.DataDir+"/state.json", PersistedData{
		Settings: settings,
		Profiles: map[string]*NodeProfile{},
		Nodes:    map[string]NodeState{},
	}); err != nil {
		t.Fatalf("save persisted data: %v", err)
	}

	baseURL, _ := startTestServer(t, cfg)
	resp, err := http.Get(baseURL + "/api/v1/login/config")
	if err != nil {
		t.Fatalf("get login config: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read login config body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected login config 200, got %d: %s", resp.StatusCode, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode login config body: %v", err)
	}
	if payload["turnstile_enabled"] != true {
		t.Fatalf("expected turnstile_enabled=true, got %+v", payload)
	}
	if payload["turnstile_site_key"] != "0x4AAAAA-site" {
		t.Fatalf("expected public site key, got %+v", payload)
	}
	if _, ok := payload["turnstile_secret_key"]; ok {
		t.Fatalf("login config should not expose secret key: %+v", payload)
	}
}

func TestLoginRejectsMissingTurnstileTokenWhenConfigured(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "admin123",
		DataDir:   t.TempDir(),
	}

	settings := initSettings(cfg)
	settings.TurnstileSiteKey = "0x4AAAAA-site"
	settings.TurnstileSecretKey = "0x4AAAAA-secret"
	if err := savePersistedData(cfg.DataDir+"/state.json", PersistedData{
		Settings: settings,
		Profiles: map[string]*NodeProfile{},
		Nodes:    map[string]NodeState{},
	}); err != nil {
		t.Fatalf("save persisted data: %v", err)
	}

	baseURL, _ := startTestServer(t, cfg)
	resp, err := http.Post(
		baseURL+"/api/v1/login",
		"application/json",
		bytes.NewBufferString(`{"username":"admin","password":"admin123"}`),
	)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read login response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected login 401 without turnstile token, got %d: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "请先完成人机验证") {
		t.Fatalf("expected turnstile validation message, got %s", string(body))
	}
}
