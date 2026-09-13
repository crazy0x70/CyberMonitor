package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type agentRunner struct {
	cfg                 Config
	transport           agentControlPlane
	collector           *metrics.Collector
	runtimeCfg          *runtimeConfig
	testCache           map[string]cachedTest
	lastTestConfigSig   string
	agentToken          string
	agentTokenDurable   bool
	nextRegisterAttempt time.Time
	updates             remoteUpdateTracker
	// updateWG 跟踪后台更新 goroutine：优雅退出时有限等待其收尾，
	// 让最终状态上报完成，避免服务端更新记录停留在 updating。
	updateWG sync.WaitGroup
	// 控制面错误去重日志状态（logControlPlaneError 专用）。
	errMu    sync.Mutex
	errState map[string]errorLogState
}

type errorLogState struct {
	key       string
	lastLogAt time.Time
}

// remoteUpdateTracker 收拢远程更新的全部状态。更新应用在独立 goroutine
// 中执行（docker 托管更新可阻塞 10 分钟、二进制自更新需下载完整发布包，
// 同步执行会让上报停摆、节点被误判离线），因此读写都经锁串行。
type remoteUpdateTracker struct {
	mu                  sync.Mutex
	running             bool
	lastUpdateReportID  string
	lastUpdateState     string
	lastUpdateVersion   string
	lastUpdateSignature string
	lastUpdateAppliedAt time.Time
}

const (
	remoteUpdateDuplicateSuppressWindow = 2 * time.Minute
	agentTokenRegisterRetryInterval     = 30 * time.Second
	// 控制面持续失败时同类错误的重提周期：默认 1s 采样间隔下服务端
	// 宕机/token 永久失效不再每秒刷屏（8 万+ 条/天）。
	repeatedErrorLogInterval = 5 * time.Minute
)

// logControlPlaneError 对控制面失败做去重日志：同一错误按
// repeatedErrorLogInterval 重提，错误变化立即打印，恢复成功打印一条
// 恢复日志。err 为 nil 表示该来源恢复。
func (r *agentRunner) logControlPlaneError(source, errKey string, err error) {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	state := r.errState[source]
	if err == nil {
		if state.key != "" {
			log.Printf("%s已恢复", source)
		}
		delete(r.errState, source)
		return
	}
	now := time.Now()
	if state.key == errKey && now.Before(state.lastLogAt.Add(repeatedErrorLogInterval)) {
		return
	}
	log.Printf("%s: %v", source, err)
	r.errState[source] = errorLogState{key: errKey, lastLogAt: now}
}

// beginApply 决定是否启动一次更新应用：抑制窗内的重复指令、以及尚在
// 执行中的更新均返回 false；新签名时清空旧的报告去重状态。
func (t *remoteUpdateTracker) beginApply(signature string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return false
	}
	if signature != "" && signature == t.lastUpdateSignature && !t.lastUpdateAppliedAt.IsZero() &&
		now.Before(t.lastUpdateAppliedAt.Add(remoteUpdateDuplicateSuppressWindow)) {
		return false
	}
	if signature != t.lastUpdateSignature {
		t.lastUpdateState = ""
		t.lastUpdateVersion = ""
		t.lastUpdateReportID = ""
	}
	t.running = true
	return true
}

// endApply 在应用结束时记录签名与时间。成功与失败都进入抑制窗：失败
// （坏下载 URL、只读文件系统等）不再陷入每 30s 一次的整包重下载循环。
func (t *remoteUpdateTracker) endApply(signature string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastUpdateSignature = signature
	t.lastUpdateAppliedAt = now
	t.running = false
}

// reset 清理服务端撤回指令后的跟踪状态。抑制窗仍活跃时保留签名与
// 时间戳：窗口内的同指令重推由 beginApply 拦截，endApply 的时间戳是
// 唯一退避来源，清掉会把重推变成全新指令立即放行；窗口已过期则照常
// 清理。
func (t *remoteUpdateTracker) reset(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastUpdateReportID = ""
	t.lastUpdateState = ""
	t.lastUpdateVersion = ""
	if t.lastUpdateAppliedAt.IsZero() || !now.Before(t.lastUpdateAppliedAt.Add(remoteUpdateDuplicateSuppressWindow)) {
		t.lastUpdateSignature = ""
		t.lastUpdateAppliedAt = time.Time{}
	}
}

func (t *remoteUpdateTracker) skipDuplicateReport(updateID, state, version string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return updateID == t.lastUpdateReportID && state == t.lastUpdateState && version == t.lastUpdateVersion
}

func (t *remoteUpdateTracker) recordReport(updateID, state, version string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastUpdateReportID = updateID
	t.lastUpdateState = state
	t.lastUpdateVersion = version
}

var remoteUpdateNow = time.Now

func newAgentRunner(cfg Config, transport agentControlPlane, collector *metrics.Collector) *agentRunner {
	return &agentRunner{
		cfg:        cfg,
		transport:  transport,
		collector:  collector,
		runtimeCfg: newRuntimeConfig(cfg),
		testCache:  make(map[string]cachedTest),
		agentToken: strings.TrimSpace(cfg.AgentToken),
		errState:   make(map[string]errorLogState),
	}
}

func (r *agentRunner) bootstrapToken(ctx context.Context) {
	bootstrapToken := strings.TrimSpace(r.cfg.AgentToken)

	if err := r.restorePersistedAgentToken(); err != nil {
		log.Printf("读取 Agent 凭据文件失败: %v", err)
	}

	if bootstrapToken == "" || r.agentToken != bootstrapToken {
		return
	}

	r.registerAgentToken(ctx, "节点注册")
}

func (r *agentRunner) syncRemoteConfig(ctx context.Context) {
	remote, err := callWithTokenRefresh(r, ctx, func(ctx context.Context) (RemoteConfig, error) {
		return r.transport.FetchConfig(ctx, r.cfg.NodeID, r.agentToken)
	})
	if err != nil {
		r.logControlPlaneError("拉取远程配置失败", err.Error(), err)
		return
	}
	r.logControlPlaneError("拉取远程配置失败", "", nil)

	r.applyRemoteConfig(ctx, remote)
}

// callWithTokenRefresh 执行一次控制面调用；当调用因 Agent Token 失效
// （401/Unauthenticated）失败时，先重新注册换取新 Token，再原样重试一次。
func callWithTokenRefresh[T any](
	r *agentRunner,
	ctx context.Context,
	call func(context.Context) (T, error),
) (T, error) {
	result, err := call(ctx)
	if err == nil {
		return result, nil
	}
	if !isUnauthorizedStatusError(err) || !r.registerAgentToken(ctx, "Agent Token 失效后重新注册") {
		return result, err
	}
	return call(ctx)
}

func (r *agentRunner) registerAgentToken(ctx context.Context, label string) bool {
	bootstrapToken := strings.TrimSpace(r.cfg.AgentToken)
	if bootstrapToken == "" {
		return false
	}
	now := time.Now()
	if !r.nextRegisterAttempt.IsZero() && now.Before(r.nextRegisterAttempt) {
		return false
	}
	r.nextRegisterAttempt = now.Add(agentTokenRegisterRetryInterval)
	issuedToken, err := r.transport.RegisterNodeToken(ctx, r.cfg.NodeID, bootstrapToken)
	if err == nil && strings.TrimSpace(issuedToken) != "" {
		r.nextRegisterAttempt = time.Time{}
		if err := r.updateAgentToken(issuedToken); err != nil {
			log.Printf("持久化 Agent 专属凭据失败: %v", err)
		}
		return true
	}
	if err != nil {
		action := strings.TrimSpace(label)
		if action == "" {
			action = "节点注册"
		}
		log.Printf("%s失败，继续尝试使用当前 Agent Token: %v", action, err)
	}
	return false
}

func (r *agentRunner) applyRemoteConfig(ctx context.Context, remote RemoteConfig) {
	r.runtimeCfg.Update(remote)
	if err := r.updateAgentToken(resolveRemoteAgentToken(r.agentToken, remote)); err != nil {
		log.Printf("持久化 Agent 专属凭据失败: %v", err)
	}
	if remote.Update == nil {
		r.updates.reset(remoteUpdateNow())
		return
	}
	if !r.agentTokenDurable {
		r.logControlPlaneError("拒绝执行远程更新", "token-not-durable",
			fmt.Errorf("Agent 专属凭据尚未可靠写入 %s", strings.TrimSpace(r.cfg.TokenFile)))
		return
	}
	r.logControlPlaneError("拒绝执行远程更新", "", nil)
	signature := remoteUpdateInstructionSignature(remote.Update)
	if !r.updates.beginApply(signature, remoteUpdateNow()) {
		return
	}
	// 更新应用放到独立 goroutine：期间采集上报照常进行，节点不会因为
	// 下载/拉镜像长时间无数据而被误判离线。报告使用 spawn 时的 token
	// 快照且不触发重新注册——主循环可能并发轮换 token，后台路径不得
	// 触碰 runner 的注册状态；token 失效则本次报告失败，抑制窗后重试。
	update := *remote.Update
	reportToken := r.agentToken
	r.updateWG.Add(1)
	go func() {
		defer r.updateWG.Done()
		// endApply 挂 defer：panic 等任何退出路径都必须释放 running，
		// 否则后续更新指令被 beginApply 永久忽略且无诊断日志。闭包形式
		// 让时间戳在调用时求值（抑制窗从更新结束起算，而非启动时刻）。
		// 执行顺序（LIFO）：recover → endApply → Done。
		defer func() { r.updates.endApply(signature, remoteUpdateNow()) }()
		defer func() {
			// 更新 goroutine 可能正处于二进制替换流程，panic 不得杀死
			// 进程，记录后随 endApply 收尾。
			if rec := recover(); rec != nil {
				log.Printf("执行远程更新 panic 已恢复: %v", rec)
			}
		}()
		if err := maybeApplyRemoteUpdate(ctx, func(ctx context.Context, updateID, state, version, message string) error {
			return r.reportUpdateWithToken(ctx, reportToken, updateID, state, version, message)
		}, r.cfg, &update); err != nil {
			log.Printf("执行远程更新失败: %v", err)
		}
	}()
}

func remoteUpdateInstructionSignature(update *RemoteUpdateInstruction) string {
	if update == nil {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(update.ID),
		strings.TrimSpace(update.Version),
		strings.TrimSpace(update.DownloadURL),
		strings.TrimSpace(update.ChecksumURL),
		fmt.Sprint(update.RequestedAt),
	}, "\x00")
}

// reportUpdateWithToken 供后台更新 goroutine 上报更新状态：token 由
// 调用方快照给定，401 时不重新注册，避免与主循环并发修改 runner 的
// 注册状态；token 失效的报告随抑制窗重试自愈。
func (r *agentRunner) reportUpdateWithToken(
	ctx context.Context,
	token, updateID, state, version, message string,
) error {
	updateID = strings.TrimSpace(updateID)
	terminalState := isTerminalUpdateState(state)
	if terminalState && r.updates.skipDuplicateReport(updateID, state, version) {
		return nil
	}
	err := r.transport.ReportUpdate(ctx, r.cfg.NodeID, token, updateID, state, version, message)
	if err != nil {
		return err
	}
	if terminalState {
		r.updates.recordReport(updateID, state, version)
	}
	return nil
}

func (r *agentRunner) collectAndReport(ctx context.Context) {
	sample := r.collector.Collect()
	if sample.NodeID == "" {
		sample.NodeID = sample.Hostname
	}
	if sample.NodeName == "" {
		sample.NodeName = sample.Hostname
	}
	if r.cfg.AgentVersion != "" {
		sample.AgentVersion = r.cfg.AgentVersion
	}
	sample.DeployMode = string(updater.DetectDeployMode())
	sample.DockerManagedUpdate = canDockerManagedUpdate()
	annotateAgentUpdateCapability(&sample, r.cfg)

	alias, group, tests, interval := r.runtimeCfg.Snapshot()
	if alias != "" {
		sample.NodeAlias = alias
	}
	if group != "" {
		sample.NodeGroup = group
	}
	configChanged := false
	if configSig := networkTestConfigSignature(tests); configSig != r.lastTestConfigSig {
		r.lastTestConfigSig = configSig
		configChanged = true
	}
	if testsSnapshot, resultsChanged := runNetworkTestsWithCache(ctx, tests, interval, r.testCache, configChanged); configChanged || resultsChanged {
		sample.NetworkTestsChanged = true
		sample.NetworkTests = testsSnapshot
	}

	if err := r.reportStats(ctx, sample); err != nil {
		r.logControlPlaneError("上报失败", err.Error(), err)
		return
	}
	r.logControlPlaneError("上报失败", "", nil)
}

func annotateAgentUpdateCapability(sample *metrics.NodeStats, cfg Config) {
	if sample == nil {
		return
	}
	sample.AgentUpdateDisabled = cfg.DisableUpdate
	sample.AgentUpdateInsecure = !remoteUpdateControlPlaneSecure(cfg.ServerURL)
	sample.AgentRemoteUpdate = remoteUpdateCapableForConfig(cfg)
}

func (r *agentRunner) reportStats(ctx context.Context, sample metrics.NodeStats) error {
	refreshConfig, err := callWithTokenRefresh(r, ctx, func(ctx context.Context) (bool, error) {
		return r.transport.ReportStats(ctx, sample, r.agentToken)
	})
	if err != nil {
		return err
	}
	if refreshConfig {
		r.syncRemoteConfig(ctx)
	}
	return nil
}

func (r *agentRunner) restorePersistedAgentToken() error {
	if r.cfg.TokenFile == "" {
		return nil
	}
	persisted, err := loadPersistedAgentToken(r.cfg.TokenFile)
	switch {
	case err == nil && persisted != "":
		r.agentToken = persisted
		r.agentTokenDurable = true
		return nil
	case os.IsNotExist(err), errors.Is(err, os.ErrInvalid):
		// 空/全空白 token 文件与不存在同义：走重新注册路径。
		r.agentTokenDurable = false
		return nil
	default:
		r.agentTokenDurable = false
		return err
	}
}

func (r *agentRunner) updateAgentToken(next string) error {
	trimmed := strings.TrimSpace(next)
	if trimmed == "" {
		return nil
	}
	changed := trimmed != r.agentToken
	r.agentToken = trimmed
	if strings.TrimSpace(r.cfg.TokenFile) == "" {
		r.agentTokenDurable = false
		return nil
	}
	if !changed && r.agentTokenDurable {
		return nil
	}
	if err := persistAgentToken(r.cfg.TokenFile, trimmed); err != nil {
		r.agentTokenDurable = false
		return err
	}
	r.agentTokenDurable = true
	return nil
}

func resolveRemoteAgentToken(current string, remote RemoteConfig) string {
	if issuedToken := strings.TrimSpace(remote.AgentToken); issuedToken != "" {
		return issuedToken
	}
	return current
}

func isUnauthorizedStatusError(err error) bool {
	if err == nil {
		return false
	}
	if status.Code(err) == codes.Unauthenticated {
		return true
	}
	var apiErr *agentAPIStatusError
	return errors.As(err, &apiErr) && apiErr.statusCode == http.StatusUnauthorized
}
