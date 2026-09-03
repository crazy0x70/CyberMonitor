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
	allowPrivateRemoteTests bool
}

func newRuntimeConfig(cfg Config) *runtimeConfig {
	interval := cfg.TestInterval
	if interval <= 0 {
		interval = DefaultTestInterval
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

	// 空值不覆盖：新节点注册后服务端尚无 alias/group，首次 sync 发生在
	// 首次上报之前，无条件覆盖会把 -node-alias/-node-group 种子值清掉，
	// 服务端（以首次上报为种子）就永远收不到它们。
	if remote.Alias != "" {
		r.alias = remote.Alias
	}
	if remote.Group != "" {
		r.group = remote.Group
	}
	if remote.TestIntervalSec > 0 {
		r.interval = time.Duration(remote.TestIntervalSec) * time.Second
	}
	if remote.Tests != nil {
		r.tests = markRemoteNetworkTests(remote.Tests, !r.allowPrivateRemoteTests)
	}
}

func (r *runtimeConfig) Snapshot() (string, string, []metrics.NetworkTestConfig, time.Duration) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copyTests := make([]metrics.NetworkTestConfig, len(r.tests))
	copy(copyTests, r.tests)
	return r.alias, r.group, copyTests, r.interval
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
	if err := performAgentRequest(client, req, "config", func(body io.Reader) error {
		return decodeStrictAgentJSON(body, &payload, "config response has trailing data")
	}); err != nil {
		return RemoteConfig{}, err
	}
	return payload, nil
}

// performAgentRequest issues an agent API request and turns >=300 responses
// into agentAPIStatusError. A non-nil decode callback receives the response
// body (e.g. the strict-JSON decoder); nil means the body is ignored.
func performAgentRequest(
	client *http.Client,
	req *http.Request,
	statusLabel string,
	decode func(io.Reader) error,
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
	if decode == nil {
		return nil
	}
	return decode(resp.Body)
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
