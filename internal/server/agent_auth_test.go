package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
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

func TestAgentConfigRejectsBootstrapTokenAfterRegistration(t *testing.T) {
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
	if registerPayload.AgentToken == "" {
		t.Fatal("expected dedicated node token")
	}

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
	if bootstrapResp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(bootstrapResp.Body)
		t.Fatalf("expected bootstrap token to be rejected, got %d: %s", bootstrapResp.StatusCode, string(raw))
	}

	nodeReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/agent/config?node_id=node-123", nil)
	if err != nil {
		t.Fatalf("create node config request: %v", err)
	}
	nodeReq.Header.Set("X-AGENT-TOKEN", registerPayload.AgentToken)
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
