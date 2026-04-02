package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"
)

type Config struct {
	ServerURL     string
	Interval      time.Duration
	NodeID        string
	NodeName      string
	NodeAlias     string
	NodeGroup     string
	AgentToken    string
	AgentVersion  string
	HostRoot      string
	NetTests      []metrics.NetworkTestConfig
	TestInterval  time.Duration
	NetIfaces     []string
	DisableUpdate bool
	TokenFile     string
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
	registerEndpoint := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/agent/register"
	updateReportEndpoint := strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/agent/update/report"

	runtimeCfg := newRuntimeConfig(cfg)
	testCache := make(map[string]cachedTest)
	dockerManagedUpdate := updater.CanDockerManagedUpdate()
	agentToken := strings.TrimSpace(cfg.AgentToken)
	if cfg.TokenFile != "" {
		if persisted, err := loadPersistedAgentToken(cfg.TokenFile); err == nil && persisted != "" {
			agentToken = persisted
		} else if err != nil && !os.IsNotExist(err) {
			log.Printf("读取 Agent 凭据文件失败: %v", err)
		}
	}

	if cfg.AgentToken != "" && agentToken == strings.TrimSpace(cfg.AgentToken) {
		if issuedToken, err := registerNodeToken(ctx, client, registerEndpoint, cfg.NodeID, cfg.AgentToken); err == nil && issuedToken != "" {
			agentToken = issuedToken
			if cfg.TokenFile != "" {
				if err := persistAgentToken(cfg.TokenFile, issuedToken); err != nil {
					log.Printf("持久化 Agent 专属凭据失败: %v", err)
				}
			}
		} else if err != nil && !strings.Contains(err.Error(), "register status 401") {
			log.Printf("节点注册未成功，继续尝试使用当前 Agent Token: %v", err)
		}
	}

	fetchConfig := func() {
		remote, err := fetchRemoteConfig(ctx, client, configEndpoint, cfg.NodeID, agentToken)
		if err != nil {
			log.Printf("拉取远程配置失败: %v", err)
			return
		}
		if nextToken := strings.TrimSpace(remote.AgentToken); nextToken != "" && nextToken != agentToken {
			agentToken = nextToken
			if cfg.TokenFile != "" {
				if err := persistAgentToken(cfg.TokenFile, nextToken); err != nil {
					log.Printf("持久化 Agent 专属凭据失败: %v", err)
				}
			}
		}
		runtimeCfg.Update(remote)
		runtimeCfgConfig := cfg
		runtimeCfgConfig.AgentToken = agentToken
		if err := maybeApplyRemoteUpdate(ctx, client, updateReportEndpoint, runtimeCfgConfig, remote.Update); err != nil {
			log.Printf("执行远程更新失败: %v", err)
		}
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
		sample.DeployMode = string(updater.DetectDeployMode())
		sample.DockerManagedUpdate = dockerManagedUpdate
		sample.AgentUpdateDisabled = cfg.DisableUpdate
		alias, group, tests, interval, _ := runtimeCfg.Snapshot()
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
		if agentToken != "" {
			req.Header.Set("X-AGENT-TOKEN", agentToken)
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

func maybeApplyRemoteUpdate(
	ctx context.Context,
	client *http.Client,
	reportEndpoint string,
	cfg Config,
	update *RemoteUpdateInstruction,
) error {
	if update == nil {
		return nil
	}
	targetVersion := strings.TrimSpace(update.Version)
	if targetVersion == "" {
		return nil
	}
	currentVersion := strings.TrimSpace(cfg.AgentVersion)
	if currentVersion == targetVersion {
		return postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "succeeded", targetVersion, "Agent 已运行目标版本")
	}
	if cfg.DisableUpdate {
		return postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "failed", targetVersion, "当前 Agent 已禁用远程更新")
	}
	if updater.CanDockerManagedUpdate() {
		dockerUpdater, err := updater.NewDockerManagedUpdater()
		if err != nil {
			return postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "failed", targetVersion, err.Error())
		}
		if err := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "updating", targetVersion, "正在拉取新镜像并准备重建 Agent 容器"); err != nil {
			return err
		}
		targetImage := updater.ResolveDockerTargetImage(dockerUpdater.CurrentImage(), targetVersion)
		if err := dockerUpdater.LaunchSelfContainerUpdate(ctx, targetImage); err != nil {
			reportErr := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "failed", targetVersion, err.Error())
			if reportErr != nil {
				return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
			}
			return err
		}
		if err := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "restarting", targetVersion, "Docker 更新任务已启动，Agent 容器即将重建"); err != nil {
			log.Printf("上报 Agent Docker 重建状态失败: %v", err)
		}
		return nil
	}
	if !updater.CanSelfUpdate() {
		return postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "failed", targetVersion, resolveUnsupportedUpdateMessage())
	}
	if err := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "updating", targetVersion, "正在下载并替换 Agent 二进制"); err != nil {
		return err
	}
	clientUpdater := updater.NewClient(updater.DefaultRepo, updater.KindAgent, currentVersion)
	if err := clientUpdater.ApplyAsset(ctx, update.DownloadURL, update.ChecksumURL); err != nil {
		reportErr := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "failed", targetVersion, err.Error())
		if reportErr != nil {
			return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
		}
		return err
	}
	if err := postAgentUpdateReport(ctx, client, reportEndpoint, cfg.NodeID, cfg.AgentToken, "restarting", targetVersion, "更新包已写入，Agent 正在重启"); err != nil {
		log.Printf("上报 Agent 重启状态失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	return updater.RestartSelf()
}

func resolveUnsupportedUpdateMessage() string {
	message := strings.TrimSpace(updater.DefaultUnsupportedUpdateMessage())
	if message != "" {
		return message
	}
	return "当前平台暂不支持 Agent 自更新"
}

func postAgentUpdateReport(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	nodeID string,
	token string,
	state string,
	version string,
	message string,
) error {
	payload, err := json.Marshal(map[string]string{
		"node_id": nodeID,
		"state":   state,
		"version": version,
		"message": message,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-AGENT-TOKEN", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		text := strings.TrimSpace(string(body))
		if text == "" {
			text = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return fmt.Errorf("update report failed: %s", text)
	}
	return nil
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
