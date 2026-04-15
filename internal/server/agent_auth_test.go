package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"cyber_monitor/internal/agentrpc"
)

func TestAgentRegisterIssuesDedicatedNodeToken(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/agent/register?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create register request: %v", err)
	}
	req.Header.Set("X-AGENT-TOKEN", "bootstrap-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected register 200, got %d: %s", resp.StatusCode, string(raw))
	}
	var payload struct {
		NodeID     string `json:"node_id"`
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode register payload: %v", err)
	}
	if payload.NodeID != "node-123" {
		t.Fatalf("expected node_id node-123, got %q", payload.NodeID)
	}
	if payload.AgentToken == "" || payload.AgentToken == "bootstrap-token" {
		t.Fatalf("expected dedicated node token, got %q", payload.AgentToken)
	}
}

func TestLegacyAgentConfigAcceptsBootstrapTokenWithLegacySchema(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	bootstrapReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/config?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create bootstrap config request: %v", err)
	}
	bootstrapReq.Header.Set("X-AGENT-TOKEN", "bootstrap-token")
	bootstrapResp, err := http.DefaultClient.Do(bootstrapReq)
	if err != nil {
		t.Fatalf("get config with bootstrap token: %v", err)
	}
	defer bootstrapResp.Body.Close()
	if bootstrapResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(bootstrapResp.Body)
		t.Fatalf("expected bootstrap token config success for legacy agent, got %d: %s", bootstrapResp.StatusCode, string(raw))
	}
	var legacyPayload struct {
		Alias           string           `json:"alias"`
		Group           string           `json:"group"`
		Tests           []map[string]any `json:"tests"`
		TestIntervalSec int              `json:"test_interval_sec"`
	}
	decoder := json.NewDecoder(bootstrapResp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacyPayload); err != nil {
		t.Fatalf("expected legacy schema to decode without unknown fields, got %v", err)
	}
}

func TestAgentConfigReturnsDedicatedTokenWhenCapabilitiesDeclared(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	bootstrapReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/config?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create bootstrap config request: %v", err)
	}
	bootstrapReq.Header.Set("X-AGENT-TOKEN", "bootstrap-token")
	bootstrapReq.Header.Set(agentrpc.AgentCapabilitiesHeader, agentrpc.AgentCapabilityDedicatedToken+","+agentrpc.AgentCapabilityRemoteUpdate)
	bootstrapResp, err := http.DefaultClient.Do(bootstrapReq)
	if err != nil {
		t.Fatalf("get config with bootstrap token: %v", err)
	}
	defer bootstrapResp.Body.Close()
	if bootstrapResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(bootstrapResp.Body)
		t.Fatalf("expected capability-aware config success, got %d: %s", bootstrapResp.StatusCode, string(raw))
	}
	var bootstrapPayload struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(bootstrapResp.Body).Decode(&bootstrapPayload); err != nil {
		t.Fatalf("decode bootstrap config payload: %v", err)
	}
	if bootstrapPayload.AgentToken == "" || bootstrapPayload.AgentToken == "bootstrap-token" {
		t.Fatalf("expected config to return dedicated node token, got %q", bootstrapPayload.AgentToken)
	}
	nodeReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/config?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create node config request: %v", err)
	}
	nodeReq.Header.Set("X-AGENT-TOKEN", bootstrapPayload.AgentToken)
	nodeReq.Header.Set(agentrpc.AgentCapabilitiesHeader, agentrpc.AgentCapabilityDedicatedToken+","+agentrpc.AgentCapabilityRemoteUpdate)
	nodeResp, err := http.DefaultClient.Do(nodeReq)
	if err != nil {
		t.Fatalf("get config with node token: %v", err)
	}
	defer nodeResp.Body.Close()
	if nodeResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(nodeResp.Body)
		t.Fatalf("expected node token config success, got %d: %s", nodeResp.StatusCode, string(raw))
	}
}

func TestIngestRejectsDedicatedNodeMismatch(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	registerReq, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/agent/register?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create register request: %v", err)
	}
	registerReq.Header.Set("X-AGENT-TOKEN", "bootstrap-token")
	registerResp, err := http.DefaultClient.Do(registerReq)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	defer registerResp.Body.Close()

	var registerPayload struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerPayload); err != nil {
		t.Fatalf("decode register payload: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"node_id":   "other-node",
		"node_name": "other-node",
		"hostname":  "other-node",
		"os":        "linux",
		"arch":      "amd64",
		"timestamp": 1710000000,
		"cpu":       map[string]any{"usage_percent": 1},
		"memory":    map[string]any{"total": 1, "used": 1, "free": 0, "used_percent": 100},
		"disk":      []map[string]any{},
		"disk_io":   map[string]any{},
		"network":   map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal ingest payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create ingest request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AGENT-TOKEN", registerPayload.AgentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected mismatched node token to be rejected, got %d: %s", resp.StatusCode, string(raw))
	}
}

func TestDedicatedTokenConfigStillReturnsExtendedSchemaWithoutCapabilitiesHeader(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{
			AdminUser:  "admin",
			AdminPass:  "pass",
			AgentToken: "bootstrap-token",
		}),
		profiles: map[string]*NodeProfile{},
		nodes:    map[string]NodeState{},
	}
	dedicatedToken := store.ensureAgentAuthToken("node-123")
	store.QueueAgentUpdate("node-123", AgentUpdateInstruction{
		Version:     "1.2.3",
		DownloadURL: "https://example.com/agent",
		ChecksumURL: "https://example.com/SHA256SUMS",
	})

	api := newAgentAPI(store, nil, &Config{AgentToken: "bootstrap-token"})
	config, apiErr := api.config("node-123", dedicatedToken)
	if apiErr != nil {
		t.Fatalf("expected dedicated token config success, got %v", apiErr)
	}

	payload, err := json.Marshal(httpAgentConfigResponse(config, "", store.validateAgentAuthToken("node-123", dedicatedToken)))
	if err != nil {
		t.Fatalf("marshal config payload: %v", err)
	}

	var extended AgentConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&extended); err != nil {
		t.Fatalf("expected dedicated token request to keep extended schema, got %v", err)
	}
	if extended.AgentToken != dedicatedToken {
		t.Fatalf("expected dedicated token %q, got %q", dedicatedToken, extended.AgentToken)
	}
	if extended.Update == nil || extended.Update.Version != "1.2.3" {
		t.Fatalf("expected pending update instruction, got %+v", extended.Update)
	}
}

func TestLegacyBootstrapTokenCanIngestWithoutManualRegistration(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	body, err := json.Marshal(map[string]any{
		"node_id":   "legacy-node",
		"node_name": "legacy-node",
		"hostname":  "legacy-host",
		"os":        "linux",
		"arch":      "amd64",
		"timestamp": 1710000000,
		"cpu":       map[string]any{"usage_percent": 1},
		"memory":    map[string]any{"total": 1, "used": 1, "free": 0, "used_percent": 100},
		"disk":      []map[string]any{},
		"disk_io":   map[string]any{},
		"network":   map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal ingest payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create ingest request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AGENT-TOKEN", "bootstrap-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post legacy ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected legacy bootstrap ingest to succeed, got %d: %s", resp.StatusCode, string(raw))
	}
}
