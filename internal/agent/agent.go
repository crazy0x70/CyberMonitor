package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

type Config struct {
	ServerURL    string
	Interval     time.Duration
	NodeID       string
	NodeName     string
	NodeAlias    string
	NodeGroup    string
	AgentToken   string
	AgentVersion string
	HostRoot     string
	NetTests     []metrics.NetworkTestConfig
	TestInterval time.Duration
	NetIfaces    []string
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("server url is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}

	configureHostEnv(cfg.HostRoot)

	client := &http.Client{Timeout: 6 * time.Second}
	collector := metrics.NewCollector(cfg.NodeID, cfg.NodeName, cfg.HostRoot, cfg.NetIfaces)
	endpoint := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/ingest"
	configEndpoint := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/agent/config"

	runtimeCfg := newRuntimeConfig(cfg)
	testCache := make(map[string]cachedTest)

	fetchConfig := func() {
		remote, err := fetchRemoteConfig(ctx, client, configEndpoint, cfg.NodeID, cfg.AgentToken)
		if err != nil {
			return
		}
		runtimeCfg.Update(remote)
	}

	sendOnce := func() {
		sample, err := collector.Collect()
		if err != nil {
			log.Printf("采集失败: %v", err)
			return
		}
		if sample.NodeID == "" {
			sample.NodeID = sample.Hostname
		}
		if sample.NodeName == "" {
			sample.NodeName = sample.Hostname
		}
		if cfg.AgentVersion != "" {
			sample.AgentVersion = cfg.AgentVersion
		}
		alias, group, tests, interval := runtimeCfg.Snapshot()
		if alias != "" {
			sample.NodeAlias = alias
		}
		if group != "" {
			sample.NodeGroup = group
		}
		if len(tests) > 0 {
			sample.NetworkTests = runNetworkTestsWithCache(ctx, tests, interval, testCache)
		}

		payload, err := json.Marshal(sample)
		if err != nil {
			log.Printf("编码失败: %v", err)
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			log.Printf("请求创建失败: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.AgentToken != "" {
			req.Header.Set("X-AGENT-TOKEN", cfg.AgentToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("上报失败: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("上报失败: 状态码 %d", resp.StatusCode)
		}
	}

	fetchConfig()
	sendOnce()
	ticker := time.NewTicker(cfg.Interval)
	configTicker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer configTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sendOnce()
		case <-configTicker.C:
			fetchConfig()
		}
	}
}

type cachedTest struct {
	lastRun time.Time
	result  metrics.NetworkTestResult
}

func runNetworkTestsWithCache(
	ctx context.Context,
	configs []metrics.NetworkTestConfig,
	defaultInterval time.Duration,
	cache map[string]cachedTest,
) []metrics.NetworkTestResult {
	if len(configs) == 0 {
		return nil
	}
	if defaultInterval <= 0 {
		defaultInterval = 5 * time.Second
	}

	now := time.Now()
	dueConfigs := make([]metrics.NetworkTestConfig, 0, len(configs))
	dueKeys := make([]string, 0, len(configs))
	validKeys := make(map[string]struct{}, len(configs))

	for _, cfg := range configs {
		key := testKey(cfg)
		if key == "" {
			continue
		}
		validKeys[key] = struct{}{}
		interval := time.Duration(cfg.IntervalSec) * time.Second
		if strings.ToLower(cfg.Type) == "icmp" {
			interval = time.Second
		} else if interval < 0 {
			interval = defaultInterval
		}
		if cached, ok := cache[key]; !ok || now.Sub(cached.lastRun) >= interval {
			dueConfigs = append(dueConfigs, cfg)
			dueKeys = append(dueKeys, key)
		}
	}

	if len(dueConfigs) > 0 {
		results := RunNetworkTests(ctx, dueConfigs)
		for i, result := range results {
			if i >= len(dueKeys) {
				break
			}
			cache[dueKeys[i]] = cachedTest{
				lastRun: time.Unix(result.CheckedAt, 0),
				result:  result,
			}
		}
	}

	for key := range cache {
		if _, ok := validKeys[key]; !ok {
			delete(cache, key)
		}
	}

	ordered := make([]metrics.NetworkTestResult, 0, len(configs))
	for _, cfg := range configs {
		key := testKey(cfg)
		if key == "" {
			continue
		}
		if cached, ok := cache[key]; ok {
			ordered = append(ordered, cached.result)
		}
	}
	return ordered
}

func testKey(cfg metrics.NetworkTestConfig) string {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%s|%s|%d|%s", cfg.Type, host, cfg.Port, cfg.Name))
}

func configureHostEnv(hostRoot string) {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		return
	}
	if _, exists := os.LookupEnv("HOST_PROC"); !exists {
		setEnvIfDir("HOST_PROC", filepath.Join(root, "proc"))
	}
	if _, exists := os.LookupEnv("HOST_SYS"); !exists {
		setEnvIfDir("HOST_SYS", filepath.Join(root, "sys"))
	}
	if _, exists := os.LookupEnv("HOST_ETC"); !exists {
		setEnvIfDir("HOST_ETC", filepath.Join(root, "etc"))
	}
}

func setEnvIfDir(key, path string) {
	if isDir(path) {
		_ = os.Setenv(key, path)
	}
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
