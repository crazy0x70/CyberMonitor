package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"
)

type RemoteConfig struct {
	Alias           string                      `json:"alias"`
	Group           string                      `json:"group"`
	AgentToken      string                      `json:"agent_token,omitempty"`
	Tests           []metrics.NetworkTestConfig `json:"tests"`
	TestIntervalSec int                         `json:"test_interval_sec"`
	Update          *RemoteUpdateInstruction    `json:"update,omitempty"`
}

type RemoteUpdateInstruction struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	ChecksumURL string `json:"checksum_url,omitempty"`
	RequestedAt int64  `json:"requested_at,omitempty"`
}

const maxAgentAPIErrorBodyBytes = 4096

type agentAPIStatusError struct {
	statusCode int
	operation  string
	message    string
}

func (e *agentAPIStatusError) Error() string {
	if e == nil {
		return ""
	}
	statusText := fmt.Sprintf("status %d", e.statusCode)
	operation := strings.TrimSpace(e.operation)
	message := strings.TrimSpace(e.message)
	if message == "" || message == statusText {
		if operation == "" {
			return statusText
		}
		return operation + " " + statusText
	}
	if operation == "" {
		return statusText + ": " + message
	}
	return operation + " " + statusText + ": " + message
}

type runtimeConfig struct {
	mu                      sync.RWMutex
	alias                   string
	group                   string
	tests                   []metrics.NetworkTestConfig
	interval                time.Duration
	update                  *RemoteUpdateInstruction
	allowPrivateRemoteTests bool
}

func newRuntimeConfig(cfg Config) *runtimeConfig {
	interval := cfg.TestInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &runtimeConfig{
		alias:                   cfg.NodeAlias,
		group:                   cfg.NodeGroup,
		tests:                   cfg.NetTests,
		interval:                interval,
		allowPrivateRemoteTests: cfg.AllowPrivateRemoteTests,
	}
}

func (r *runtimeConfig) Update(remote RemoteConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.alias = remote.Alias
	r.group = remote.Group
	if remote.TestIntervalSec > 0 {
		r.interval = time.Duration(remote.TestIntervalSec) * time.Second
	}
	if remote.Tests != nil {
		r.tests = markRemoteNetworkTests(remote.Tests, !r.allowPrivateRemoteTests)
	}
	r.update = cloneRemoteUpdateInstruction(remote.Update)
}

func (r *runtimeConfig) Snapshot() (string, string, []metrics.NetworkTestConfig, time.Duration, *RemoteUpdateInstruction) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copyTests := make([]metrics.NetworkTestConfig, len(r.tests))
	copy(copyTests, r.tests)
	return r.alias, r.group, copyTests, r.interval, cloneRemoteUpdateInstruction(r.update)
}

func cloneRemoteUpdateInstruction(value *RemoteUpdateInstruction) *RemoteUpdateInstruction {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func markRemoteNetworkTests(tests []metrics.NetworkTestConfig, publicOnly bool) []metrics.NetworkTestConfig {
	if len(tests) == 0 {
		return tests
	}
	marked := make([]metrics.NetworkTestConfig, len(tests))
	copy(marked, tests)
	for i := range marked {
		marked[i].PublicOnly = publicOnly
	}
	return marked
}

func remoteUpdateCapableForConfig(cfg Config) bool {
	return !cfg.DisableUpdate && remoteUpdateControlPlaneSecure(cfg.ServerURL)
}

func agentCapabilitiesForConfig(cfg Config) []string {
	capabilities := []string{agentrpc.AgentCapabilityDedicatedToken}
	if remoteUpdateCapableForConfig(cfg) {
		capabilities = append(capabilities, agentrpc.AgentCapabilityRemoteUpdate)
	}
	return capabilities
}

func agentCapabilitiesHeader(capabilities []string) string {
	normalized := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		capability = strings.TrimSpace(capability)
		if capability != "" {
			normalized = append(normalized, capability)
		}
	}
	return strings.Join(normalized, ",")
}

func fetchRemoteConfig(ctx context.Context, client *http.Client, endpoint, nodeID, token string, capabilities []string) (RemoteConfig, error) {
	if nodeID == "" {
		return RemoteConfig{}, fmt.Errorf("node id required")
	}
	urlValue, err := url.Parse(endpoint)
	if err != nil {
		return RemoteConfig{}, err
	}
	q := urlValue.Query()
	q.Set("node_id", nodeID)
	urlValue.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlValue.String(), nil)
	if err != nil {
		return RemoteConfig{}, err
	}
	if token != "" {
		req.Header.Set("X-AGENT-TOKEN", token)
	}
	if header := agentCapabilitiesHeader(capabilities); header != "" {
		req.Header.Set(agentrpc.AgentCapabilitiesHeader, header)
	}

	var payload RemoteConfig
	if err := performAgentJSONRequest(client, req, "config", "config response has trailing data", &payload); err != nil {
		return RemoteConfig{}, err
	}
	return payload, nil
}

func performAgentJSONRequest(
	client *http.Client,
	req *http.Request,
	statusLabel string,
	trailingMessage string,
	target any,
) error {
	if client == nil {
		return fmt.Errorf("http client required")
	}
	if req == nil {
		return fmt.Errorf("http request required")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readAgentAPIStatusError(resp, statusLabel)
	}
	return decodeStrictAgentJSON(resp.Body, target, trailingMessage)
}

func newAgentJSONRequest(
	ctx context.Context,
	method string,
	endpoint string,
	payload any,
	token string,
) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-AGENT-TOKEN", token)
	}
	return req, nil
}

func performAgentStatusRequest(client *http.Client, req *http.Request, operation string) error {
	if client == nil {
		return fmt.Errorf("http client required")
	}
	if req == nil {
		return fmt.Errorf("http request required")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readAgentAPIStatusError(resp, operation)
	}
	return nil
}

func readAgentAPIErrorMessage(resp *http.Response, fallback string) string {
	message := strings.TrimSpace(fallback)
	if resp == nil {
		if message != "" {
			return message
		}
		return "request failed"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAgentAPIErrorBodyBytes))
	if text := strings.TrimSpace(string(body)); text != "" {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(text), &payload); err == nil {
			if message := strings.TrimSpace(payload.Error); message != "" {
				return message
			}
		}
		return text
	}
	if message != "" {
		return message
	}
	return fmt.Sprintf("status %d", resp.StatusCode)
}

func readAgentAPIStatusError(resp *http.Response, operation string) error {
	operation = strings.TrimSpace(operation)
	if resp == nil {
		if operation == "" {
			return fmt.Errorf("request failed")
		}
		return fmt.Errorf("%s request failed", operation)
	}
	statusText := fmt.Sprintf("status %d", resp.StatusCode)
	return &agentAPIStatusError{
		statusCode: resp.StatusCode,
		operation:  operation,
		message:    readAgentAPIErrorMessage(resp, statusText),
	}
}

func decodeStrictAgentJSON(body io.Reader, target any, trailingMessage string) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New(strings.TrimSpace(trailingMessage))
		}
		return err
	}
	return nil
}
