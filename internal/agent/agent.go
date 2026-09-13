package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"
)

// DefaultTestInterval 是网络测试间隔未配置时的默认值。
const DefaultTestInterval = 5 * time.Second

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
	dockerManagedLaunchTimeout = 10 * time.Minute
)

// updateReportTimeout 与控制面 http.Client 的 Timeout 保持一致，避免更
// 短的 per-request ctx 静默压过客户端超时。
const updateReportTimeout = 10 * time.Second

type Config struct {
	ServerURL               string
	Interval                time.Duration
	NodeID                  string
	NodeName                string
	NodeAlias               string
	NodeGroup               string
	AgentToken              string
	AgentVersion            string
	HostRoot                string
	NetTests                []metrics.NetworkTestConfig
	TestInterval            time.Duration
	NetIfaces               []string
	DisableUpdate           bool
	AllowPrivateRemoteTests bool
	TokenFile               string
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("server url is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}

	configureHostEnv(cfg.HostRoot)

	client := &http.Client{Timeout: 10 * time.Second}
	transport := newControlPlaneTransportWithOptions(cfg, client, grpcTransportOptions{})
	defer transport.Close()
	runner := newAgentRunner(cfg, transport, metrics.NewCollector(cfg.NodeID, cfg.NodeName, cfg.HostRoot, cfg.NetIfaces))
	runRecovered("节点注册", func() { runner.bootstrapToken(ctx) })
	runRecovered("配置同步", func() { runner.syncRemoteConfig(ctx) })
	runRecovered("采集上报", func() { runner.collectAndReport(ctx) })
	ticker := time.NewTicker(cfg.Interval)
	configTicker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer configTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 有限等待覆盖"最终状态报告（10s Background 预算）"路径，
			// 避免服务端更新记录停留在 updating，随后才经 defer
			// transport.Close() 关闭控制面；超长更新（Docker 托管 10min
			// 预算）不在等待范围，其后续上报落入 Close 后属既有限制。
			waitForGoroutines(&runner.updateWG, agentShutdownWait)
			return ctx.Err()
		case <-ticker.C:
			runRecovered("采集上报", func() { runner.collectAndReport(ctx) })
		case <-configTicker.C:
			runRecovered("配置同步", func() { runner.syncRemoteConfig(ctx) })
		}
	}
}

// agentShutdownWait 覆盖二进制自更新的最终状态报告：报告全程由
// updateReportTimeout 的 ctx 约束（gRPC 拨号/调用与 HTTP 回退均为其子
// context），但报告可能吃满预算，等待在其之上留余量；仍小于 Windows
// 服务包装的 gracefulStopTimeout=20s。
const agentShutdownWait = updateReportTimeout + 5*time.Second

// runRecovered 隔离单次 tick 的 panic：采集/注册路径任何未预期 panic 不
// 得终止 agent 进程（崩溃即监控数据中断），记录堆栈后继续。
func runRecovered(label string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("%s panic 已恢复: %v\n%s", label, rec, debug.Stack())
		}
	}()
	fn()
}

func waitForGoroutines(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

type updateReporter func(context.Context, string, string, string, string) error

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
	if updater.VersionsEqual(currentVersion, targetVersion) {
		log.Printf("跳过远程更新: Agent 已运行目标版本 %s", targetVersion)
		return reportUpdateState(report, update, "succeeded", targetVersion, "Agent 已运行目标版本")
	}
	if !updater.HasVersionUpdate(currentVersion, targetVersion) {
		log.Printf("拒绝远程更新: 目标版本不是可验证的新版本，当前版本=%s，目标版本=%s", currentVersion, targetVersion)
		return reportUpdateState(report, update, "failed", targetVersion, "拒绝非升级版本或无法验证的目标版本")
	}
	if cfg.DisableUpdate {
		log.Printf("拒绝远程更新: 当前 Agent 已禁用远程更新，目标版本=%s", targetVersion)
		return reportUpdateState(report, update, "failed", targetVersion, "当前 Agent 已禁用远程更新")
	}
	if !remoteUpdateControlPlaneSecure(cfg.ServerURL) {
		log.Printf("拒绝远程更新: Agent 控制面未使用 HTTPS，目标版本=%s", targetVersion)
		return reportUpdateState(report, update, "failed", targetVersion, "控制面未使用 HTTPS，拒绝远程更新")
	}
	if canDockerManagedUpdate() {
		return applyDockerManagedUpdate(ctx, report, cfg, update, currentVersion, targetVersion)
	}
	return applyBinarySelfUpdate(ctx, report, update, currentVersion, targetVersion)
}

func applyDockerManagedUpdate(
	ctx context.Context,
	report updateReporter,
	cfg Config,
	update *RemoteUpdateInstruction,
	currentVersion, targetVersion string,
) error {
	log.Printf("检测到 Docker 托管更新能力，正在初始化 Docker updater")
	dockerInitCtx, cancelDockerInit := context.WithTimeout(ctx, dockerManagedInitTimeout)
	dockerUpdater, err := newDockerManagedUpdater(dockerInitCtx)
	cancelDockerInit()
	if err != nil {
		err = wrapDockerManagedUpdateError("初始化 Docker updater", err)
		log.Printf("%v", err)
		return reportUpdateState(report, update, "failed", targetVersion, err.Error())
	}
	targetImage, err := updater.ResolveDockerTargetImage(dockerUpdater.CurrentImage(), targetVersion)
	if err != nil {
		err = wrapDockerManagedUpdateError("解析 Docker 目标镜像", err)
		log.Printf("%v", err)
		return reportUpdateState(report, update, "failed", targetVersion, err.Error())
	}
	log.Printf("开始执行 Docker 托管更新: 当前版本=%s，目标版本=%s", currentVersion, targetVersion)
	if err := reportUpdateState(report, update, "updating", targetVersion, "正在拉取新镜像并准备重建 Agent 容器"); err != nil {
		return err
	}
	dockerLaunchCtx, cancelDockerLaunch := context.WithTimeout(context.Background(), dockerManagedLaunchTimeout)
	err = dockerUpdater.LaunchSelfContainerUpdate(dockerLaunchCtx, targetImage, cfg.NodeID)
	cancelDockerLaunch()
	if err != nil {
		err = wrapDockerManagedUpdateError("执行 Docker 更新 helper", err)
		log.Printf("%v", err)
		reportErr := reportUpdateState(report, update, "failed", targetVersion, err.Error())
		if reportErr != nil {
			return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
		}
		return err
	}
	if err := reportUpdateState(report, update, "restarting", targetVersion, "Docker 更新任务已启动，Agent 容器即将重建"); err != nil {
		log.Printf("上报 Agent Docker 重建状态失败: %v", err)
	}
	log.Printf("Docker 更新任务已启动: 目标镜像=%s", targetImage)
	return nil
}

func applyBinarySelfUpdate(
	ctx context.Context,
	report updateReporter,
	update *RemoteUpdateInstruction,
	currentVersion, targetVersion string,
) error {
	if !updater.CanSelfUpdate() {
		log.Printf("拒绝远程更新: 当前部署模式不支持 Agent 自更新，目标版本=%s", targetVersion)
		return reportUpdateState(report, update, "failed", targetVersion, resolveUnsupportedUpdateMessage())
	}
	log.Printf("开始下载并替换 Agent 二进制: 当前版本=%s，目标版本=%s，下载地址=%s", currentVersion, targetVersion, strings.TrimSpace(update.DownloadURL))
	if err := reportUpdateState(report, update, "updating", targetVersion, "正在下载并替换 Agent 二进制"); err != nil {
		return err
	}
	clientUpdater := updater.NewClient(updater.DefaultRepo, updater.KindAgent, currentVersion)
	if err := clientUpdater.ApplyReleaseAsset(ctx, targetVersion, update.DownloadURL, update.ChecksumURL); err != nil {
		reportErr := reportUpdateState(report, update, "failed", targetVersion, err.Error())
		if reportErr != nil {
			return fmt.Errorf("%v；上报失败状态时又出错: %w", err, reportErr)
		}
		return err
	}
	log.Printf("Agent 更新包写入完成，准备重启到版本 %s", targetVersion)
	if err := reportUpdateState(report, update, "restarting", targetVersion, "更新包已写入，Agent 正在重启"); err != nil {
		log.Printf("上报 Agent 重启状态失败: %v", err)
	}
	return updater.RestartSelf()
}

func remoteUpdateControlPlaneSecure(serverURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https") && strings.TrimSpace(parsed.Host) != ""
}

func reportUpdateState(report updateReporter, update *RemoteUpdateInstruction, state, version, message string) error {
	if report == nil {
		return nil
	}
	reportCtx, cancel := context.WithTimeout(context.Background(), updateReportTimeout)
	defer cancel()
	updateID := ""
	if update != nil {
		updateID = strings.TrimSpace(update.ID)
	}
	return report(reportCtx, updateID, state, version, message)
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
	updateID string,
	state string,
	version string,
	message string,
) error {
	req, err := newAgentJSONRequest(ctx, http.MethodPost, endpoint, map[string]string{
		"node_id":   nodeID,
		"update_id": updateID,
		"state":     state,
		"version":   version,
		"message":   message,
	}, token)
	if err != nil {
		return err
	}
	return performAgentRequest(client, req, "update report", nil)
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
	forceFullResult bool,
) ([]metrics.NetworkTestResult, bool) {
	return runNetworkTestsWithCacheAt(ctx, configs, defaultInterval, cache, time.Now, RunNetworkTests, forceFullResult)
}

func runNetworkTestsWithCacheAt(
	ctx context.Context,
	configs []metrics.NetworkTestConfig,
	defaultInterval time.Duration,
	cache map[string]cachedTest,
	now func() time.Time,
	runner func(context.Context, []metrics.NetworkTestConfig) []metrics.NetworkTestResult,
	forceFullResult bool,
) ([]metrics.NetworkTestResult, bool) {
	if len(configs) == 0 {
		return handleEmptyConfigs(cache)
	}
	if defaultInterval <= 0 {
		defaultInterval = DefaultTestInterval
	}
	if now == nil {
		now = time.Now
	}
	if runner == nil {
		runner = RunNetworkTests
	}

	currentTime := now()
	// key 单遍预计算：findDue/buildOrdered/签名此前每 tick 各算一遍
	//（Sprintf+ToLower ×3×测试数），配置只在远端下发时变化。
	keys := make([]string, len(configs))
	for i, cfg := range configs {
		keys[i] = testKey(cfg)
	}
	dueConfigs, dueKeys, validKeys := findDueTests(configs, keys, cache, currentTime, defaultInterval)
	// 单轮批量上限：探测同步阻塞上报主循环，批次过大会把上报停摆拉长到
	// 分钟级（大目录全量到期时），节点可能被服务端判离线。截断前按
	// "最久未运行优先"稳定排序（从未运行最优先），防止高频间隔项恒 due
	// 垄断批次饿死后续项；未选中项顺延下一 tick，缓存零污染。
	if len(dueConfigs) > maxNetTestWorkers {
		order := make([]int, len(dueConfigs))
		for i := range order {
			order[i] = i
		}
		lastRunAt := func(i int) time.Time {
			if cached, ok := cache[dueKeys[i]]; ok {
				return cached.lastRun
			}
			return time.Time{}
		}
		sort.SliceStable(order, func(a, b int) bool {
			return lastRunAt(order[a]).Before(lastRunAt(order[b]))
		})
		trimmedConfigs := make([]metrics.NetworkTestConfig, 0, maxNetTestWorkers)
		trimmedKeys := make([]string, 0, maxNetTestWorkers)
		for _, i := range order[:maxNetTestWorkers] {
			trimmedConfigs = append(trimmedConfigs, dueConfigs[i])
			trimmedKeys = append(trimmedKeys, dueKeys[i])
		}
		dueConfigs, dueKeys = trimmedConfigs, trimmedKeys
	}

	changed := false
	if len(dueConfigs) > 0 {
		updateCacheWithResults(cache, dueKeys, runner(ctx, dueConfigs))
		changed = true
	}

	if cleanupStaleCache(cache, validKeys) {
		changed = true
	}

	if !changed {
		if !forceFullResult {
			// 常态 tick（无到期测试、无缓存清理）：结果与上一轮完全一致，
			// 跳过全量结果切片的构建与拷贝。调用方声明配置已变化时除外
			//（顺序变化的签名命中而缓存全未到期时 changed 仍为 false，
			// 但消费方需要全量结果随 NetworkTestsChanged 一起上报）。
			return nil, false
		}
		return buildOrderedResults(configs, keys, cache), false
	}
	return buildOrderedResults(configs, keys, cache), changed
}

func handleEmptyConfigs(cache map[string]cachedTest) ([]metrics.NetworkTestResult, bool) {
	if len(cache) == 0 {
		return nil, false
	}
	clear(cache)
	return []metrics.NetworkTestResult{}, true
}

func findDueTests(
	configs []metrics.NetworkTestConfig,
	keys []string,
	cache map[string]cachedTest,
	currentTime time.Time,
	defaultInterval time.Duration,
) ([]metrics.NetworkTestConfig, []string, map[string]struct{}) {
	dueConfigs := make([]metrics.NetworkTestConfig, 0, len(configs))
	dueKeys := make([]string, 0, len(configs))
	validKeys := make(map[string]struct{}, len(configs))
	queuedKeys := make(map[string]struct{}, len(configs))

	for i, cfg := range configs {
		key := keys[i]
		if key == "" {
			continue
		}
		validKeys[key] = struct{}{}

		if _, duplicated := queuedKeys[key]; duplicated {
			continue
		}

		interval := defaultInterval
		if cfg.IntervalSec > 0 {
			interval = time.Duration(cfg.IntervalSec) * time.Second
		}

		if cached, ok := cache[key]; !ok || currentTime.Sub(cached.lastRun) >= interval {
			dueConfigs = append(dueConfigs, cfg)
			dueKeys = append(dueKeys, key)
			queuedKeys[key] = struct{}{}
		}
	}
	return dueConfigs, dueKeys, validKeys
}

func updateCacheWithResults(cache map[string]cachedTest, keys []string, results []metrics.NetworkTestResult) {
	for i, result := range results {
		if i >= len(keys) {
			break
		}
		cache[keys[i]] = cachedTest{
			lastRun: time.Unix(result.CheckedAt, 0),
			result:  result,
		}
	}
}

func cleanupStaleCache(cache map[string]cachedTest, validKeys map[string]struct{}) bool {
	changed := false
	for key := range cache {
		if _, ok := validKeys[key]; !ok {
			delete(cache, key)
			changed = true
		}
	}
	return changed
}

func buildOrderedResults(configs []metrics.NetworkTestConfig, keys []string, cache map[string]cachedTest) []metrics.NetworkTestResult {
	ordered := make([]metrics.NetworkTestResult, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for i := range configs {
		key := keys[i]
		if key == "" {
			continue
		}
		// findDueTests 对重复 key 只探测一次，这里同样去重：服务端下发
		// 重复项时上报结果不得出现双份。
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
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
	return strings.ToLower(fmt.Sprintf("%s|%s|%d|%s|public=%t|interval=%d", cfg.Type, host, cfg.Port, cfg.Name, cfg.PublicOnly, cfg.IntervalSec))
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
