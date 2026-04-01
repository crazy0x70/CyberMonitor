package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
)

type RemoteConfig struct {
	Alias           string                      `json:"alias"`
	Group           string                      `json:"group"`
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

	resp, err := client.Do(req)
	if err != nil {
		return RemoteConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			return RemoteConfig{}, fmt.Errorf("config status %d", resp.StatusCode)
		}
		return RemoteConfig{}, fmt.Errorf("config status %d: %s", resp.StatusCode, message)
	}

	var payload RemoteConfig
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return RemoteConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return RemoteConfig{}, fmt.Errorf("config response has trailing data")
		}
		return RemoteConfig{}, err
	}
	return payload, nil
}
