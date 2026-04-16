package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

type dockerManagedUpdater interface {
	CurrentImage() string
	LaunchSelfContainerUpdate(context.Context, string, string) error
}

var (
	canDockerManagedUpdate  = updater.CanDockerManagedUpdate
	newDockerManagedUpdater = func(ctx context.Context) (dockerManagedUpdater, error) {
		return updater.NewDockerManagedUpdaterContext(ctx)
	}
	dockerManagedInitTimeout   = 10 * time.Second
	dockerManagedHelperTimeout = 2 * time.Minute
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

	transportOptions grpcTransportOptions
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
	transport := newControlPlaneTransport(cfg, client)
	defer transport.Close()
	runner := newAgentRunner(cfg, transport, metrics.NewCollector(cfg.NodeID, cfg.NodeName, cfg.HostRoot, cfg.NetIfaces))
	runner.bootstrapToken(ctx)
	runner.syncRemoteConfig(ctx)
	runner.collectAndReport(ctx)
	ticker := time.NewTicker(cfg.Interval)
	configTicker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer configTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			runner.collectAndReport(ctx)
		case <-configTicker.C:
			runner.syncRemoteConfig(ctx)
		}
	}
}

type updateReporter func(context.Context, string, string, string) error

func maybeApplyRemoteUpdate(
	ctx context.Context,
	report updateReporter,
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
	if currentVersion == "" {
		currentVersion = "unknown"
	}
	log.Printf("收到远程更新指令: 当前版本=%s，目标版本=%s", currentVersion, targetVersion)
	if currentVersion == targetVersion {
		log.Printf("跳过远程更新: Agent 已运行目标版本 %s", targetVersion)
		return report(ctx, "succeeded", targetVersion, "Agent 已运行目标版本")
	}
	if cfg.DisableUpdate {
		log.Printf("拒绝远程更新: 当前 Agent 已禁用远程更新，目标版本=%s", targetVersion)
		return report(ctx, "failed", targetVersion, "当前 Agent 已禁用远程更新")
	}
	if canDockerManagedUpdate() {
		log.Printf("检测到 Docker 托管更新能力，正在初始化 Docker updater")
		dockerInitCtx, cancelDockerInit := context.WithTimeout(ctx, dockerManagedInitTimeout)
		dockerUpdater, err := newDockerManagedUpdater(dockerInitCtx)
		cancelDockerInit()
		if err != nil {
			err = wrapDockerManagedUpdateError("初始化 Docker updater", err)
			log.Printf("%v", err)
			return report(ctx, "failed", targetVersion, err.Error())
		}
		log.Printf("开始执行 Docker 托管更新: 当前版本=%s，目标版本=%s", currentVersion, targetVersion)
		if err := report(ctx, "updating", targetVersion, "正在拉取新镜像并准备重建 Agent 容器"); err != nil {
			return err
		}
		targetImage := updater.ResolveDockerTargetImage(dockerUpdater.CurrentImage(), targetVersion)
		dockerLaunchCtx, cancelDockerLaunch := context.WithTimeout(ctx, dockerManagedHelperTimeout)
		err = dockerUpdater.LaunchSelfContainerUpdate(dockerLaunchCtx, targetImage, cfg.NodeID)
		cancelDockerLaunch()
		if err != nil {
			err = wrapDockerManagedUpdateError("执行 Docker 更新 helper", err)
			log.Printf("%v", err)
			reportErr := report(ctx, "failed", targetVersion, err.Error())
			if reportErr != nil {
				return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
			}
			return err
		}
		if err := report(ctx, "restarting", targetVersion, "Docker 更新任务已启动，Agent 容器即将重建"); err != nil {
			log.Printf("上报 Agent Docker 重建状态失败: %v", err)
		}
		log.Printf("Docker 更新任务已启动: 目标镜像=%s", targetImage)
		return nil
	}
	if !updater.CanSelfUpdate() {
		log.Printf("拒绝远程更新: 当前部署模式不支持 Agent 自更新，目标版本=%s", targetVersion)
		return report(ctx, "failed", targetVersion, resolveUnsupportedUpdateMessage())
	}
	log.Printf("开始下载并替换 Agent 二进制: 当前版本=%s，目标版本=%s，下载地址=%s", currentVersion, targetVersion, strings.TrimSpace(update.DownloadURL))
	if err := report(ctx, "updating", targetVersion, "正在下载并替换 Agent 二进制"); err != nil {
		return err
	}
	clientUpdater := updater.NewClient(updater.DefaultRepo, updater.KindAgent, currentVersion)
	if err := clientUpdater.ApplyAsset(ctx, update.DownloadURL, update.ChecksumURL); err != nil {
		reportErr := report(ctx, "failed", targetVersion, err.Error())
		if reportErr != nil {
			return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
		}
		return err
	}
	log.Printf("Agent 更新包写入完成，准备重启到版本 %s", targetVersion)
	if err := report(ctx, "restarting", targetVersion, "更新包已写入，Agent 正在重启"); err != nil {
		log.Printf("上报 Agent 重启状态失败: %v", err)
	}
	return updater.RestartSelf()
}

func wrapDockerManagedUpdateError(step string, err error) error {
	step = strings.TrimSpace(step)
	if err == nil {
		if step == "" {
			return fmt.Errorf("Docker 更新失败")
		}
		return fmt.Errorf("%s失败", step)
	}
	if step == "" {
		step = "Docker 更新"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		hint := "请检查容器内访问 docker.sock 与 Docker 守护进程响应"
		if strings.Contains(step, "helper") {
			hint = "请检查镜像拉取、helper 日志与 Docker 重建权限"
		}
		return fmt.Errorf("%s超时，%s: %w", step, hint, err)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s被取消: %w", step, err)
	default:
		return fmt.Errorf("%s失败: %w", step, err)
	}
}

func isTerminalUpdateState(state string) bool {
	return state == "succeeded" || state == "failed"
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
) ([]metrics.NetworkTestResult, bool) {
	return runNetworkTestsWithCacheAt(ctx, configs, defaultInterval, cache, time.Now, RunNetworkTests)
}

func runNetworkTestsWithCacheAt(
	ctx context.Context,
	configs []metrics.NetworkTestConfig,
	defaultInterval time.Duration,
	cache map[string]cachedTest,
	now func() time.Time,
	runner func(context.Context, []metrics.NetworkTestConfig) []metrics.NetworkTestResult,
) ([]metrics.NetworkTestResult, bool) {
	if len(configs) == 0 {
		if len(cache) == 0 {
			return nil, false
		}
		clear(cache)
		return []metrics.NetworkTestResult{}, true
	}
	if defaultInterval <= 0 {
		defaultInterval = 5 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	if runner == nil {
		runner = RunNetworkTests
	}

	changed := false
	currentTime := now()
	dueConfigs := make([]metrics.NetworkTestConfig, 0, len(configs))
	dueKeys := make([]string, 0, len(configs))
	validKeys := make(map[string]struct{}, len(configs))
	queuedKeys := make(map[string]struct{}, len(configs))

	for _, cfg := range configs {
		key := testKey(cfg)
		if key == "" {
			continue
		}
		validKeys[key] = struct{}{}
		interval := defaultInterval
		if cfg.IntervalSec > 0 {
			interval = time.Duration(cfg.IntervalSec) * time.Second
		}
		if _, duplicated := queuedKeys[key]; duplicated {
			continue
		}
		if cached, ok := cache[key]; !ok || currentTime.Sub(cached.lastRun) >= interval {
			dueConfigs = append(dueConfigs, cfg)
			dueKeys = append(dueKeys, key)
			queuedKeys[key] = struct{}{}
		}
	}

	if len(dueConfigs) > 0 {
		results := runner(ctx, dueConfigs)
		for i, result := range results {
			if i >= len(dueKeys) {
				break
			}
			cache[dueKeys[i]] = cachedTest{
				lastRun: time.Unix(result.CheckedAt, 0),
				result:  result,
			}
		}
		changed = true
	}

	for key := range cache {
		if _, ok := validKeys[key]; !ok {
			delete(cache, key)
			changed = true
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
	return ordered, changed
}

func testKey(cfg metrics.NetworkTestConfig) string {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%s|%s|%d|%s", cfg.Type, host, cfg.Port, cfg.Name))
}

func networkTestConfigSignature(configs []metrics.NetworkTestConfig) string {
	if len(configs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(configs))
	for _, cfg := range configs {
		keys = append(keys, testKey(cfg))
	}
	return strings.Join(keys, ",")
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
