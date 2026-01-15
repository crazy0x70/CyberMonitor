package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
)

type RemoteConfig struct {
	Alias           string                      `json:"alias"`
	Group           string                      `json:"group"`
	Tests           []metrics.NetworkTestConfig `json:"tests"`
	TestIntervalSec int                         `json:"test_interval_sec"`
}

type runtimeConfig struct {
	mu       sync.RWMutex
	alias    string
	group    string
	tests    []metrics.NetworkTestConfig
	interval time.Duration
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
		r.tests = remote.Tests
	}
}

func (r *runtimeConfig) Snapshot() (string, string, []metrics.NetworkTestConfig, time.Duration) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copyTests := make([]metrics.NetworkTestConfig, len(r.tests))
	copy(copyTests, r.tests)
	return r.alias, r.group, copyTests, r.interval
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
		return RemoteConfig{}, fmt.Errorf("config status %d", resp.StatusCode)
	}

	var payload RemoteConfig
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return RemoteConfig{}, err
	}
	return payload, nil
}
