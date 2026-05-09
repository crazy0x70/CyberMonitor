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
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	ChecksumURL string `json:"checksum_url,omitempty"`
	RequestedAt int64  `json:"requested_at,omitempty"`
}

const maxAgentAPIErrorBodyBytes = 4096

type runtimeConfig struct {
	mu       sync.RWMutex
	alias    string
	group    string
	tests    []metrics.NetworkTestConfig
	interval time.Duration
	update   *RemoteUpdateInstruction
}

func newRuntimeConfig(cfg Config) *runtimeConfig {
	interval := cfg.TestInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &runtimeConfig{
		alias:    cfg.NodeAlias,
		group:    cfg.NodeGroup,
		tests:    cfg.NetTests,
		interval: interval,
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
		r.tests = remote.Tests
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

func fetchRemoteConfig(ctx context.Context, client *http.Client, endpoint, nodeID, token string) (RemoteConfig, error) {
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
	req.Header.Set(agentrpc.AgentCapabilitiesHeader, agentrpc.AgentCapabilityDedicatedToken+","+agentrpc.AgentCapabilityRemoteUpdate)

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

func performAgentStatusRequest(client *http.Client, req *http.Request, action string) error {
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
		return readAgentAPIActionError(resp, action)
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
		return text
	}
	if message != "" {
		return message
	}
	return fmt.Sprintf("status %d", resp.StatusCode)
}

func readAgentAPIStatusError(resp *http.Response, label string) error {
	trimmedLabel := strings.TrimSpace(label)
	if resp == nil {
		if trimmedLabel == "" {
			return fmt.Errorf("request failed")
		}
		return fmt.Errorf("%s request failed", trimmedLabel)
	}
	statusText := fmt.Sprintf("status %d", resp.StatusCode)
	message := readAgentAPIErrorMessage(resp, statusText)
	if message == statusText {
		if trimmedLabel == "" {
			return fmt.Errorf("%s", statusText)
		}
		return fmt.Errorf("%s %s", trimmedLabel, statusText)
	}
	if trimmedLabel == "" {
		return fmt.Errorf("%s", message)
	}
	return fmt.Errorf("%s %s: %s", trimmedLabel, statusText, message)
}

func readAgentAPIActionError(resp *http.Response, action string) error {
	trimmedAction := strings.TrimSpace(action)
	message := readAgentAPIErrorMessage(resp, "")
	if trimmedAction == "" {
		return fmt.Errorf("%s", message)
	}
	return fmt.Errorf("%s: %s", trimmedAction, message)
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
