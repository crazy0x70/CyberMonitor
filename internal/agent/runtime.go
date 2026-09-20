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
	updateWG            sync.WaitGroup
	errMu               sync.Mutex
	errState            map[string]errorLogState
}

type errorLogState struct {
	key       string
	lastLogAt time.Time
}

type remoteUpdateTracker struct {
	mu                  sync.Mutex
	running             bool
	lastUpdateReportID  string
	lastUpdateState     string
	lastUpdateVersion   string
	lastUpdateSignature string
	lastUpdateAppliedAt time.Time
	consecutiveFailures int
	lastRunFailed       bool
}

const (
	remoteUpdateDuplicateSuppressWindow = 2 * time.Minute
	remoteUpdateFailureMaxBackoff       = time.Hour
	agentTokenRegisterRetryInterval     = 30 * time.Second
	repeatedErrorLogInterval            = 5 * time.Minute
)

func updateFailureBackoff(consecutiveFailures int) time.Duration {
	backoff := remoteUpdateDuplicateSuppressWindow
	for i := 1; i < consecutiveFailures && backoff < remoteUpdateFailureMaxBackoff; i++ {
		backoff *= 2
	}
	if backoff > remoteUpdateFailureMaxBackoff {
		backoff = remoteUpdateFailureMaxBackoff
	}
	return backoff
}

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

func (t *remoteUpdateTracker) beginApply(signature string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return false
	}
	if signature != "" && signature == t.lastUpdateSignature && !t.lastUpdateAppliedAt.IsZero() &&
		now.Before(t.lastUpdateAppliedAt.Add(t.effectiveSuppressWindowLocked())) {
		return false
	}
	if signature != t.lastUpdateSignature {
		t.lastUpdateState = ""
		t.lastUpdateVersion = ""
		t.lastUpdateReportID = ""
		t.consecutiveFailures = 0
		t.lastRunFailed = false
	}
	t.running = true
	return true
}

func (t *remoteUpdateTracker) effectiveSuppressWindowLocked() time.Duration {
	if t.lastRunFailed {
		return updateFailureBackoff(t.consecutiveFailures)
	}
	return remoteUpdateDuplicateSuppressWindow
}

func (t *remoteUpdateTracker) endApply(signature string, now time.Time, failed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastUpdateSignature = signature
	t.lastUpdateAppliedAt = now
	t.running = false
	if failed {
		t.consecutiveFailures++
	} else {
		t.consecutiveFailures = 0
	}
	t.lastRunFailed = failed
}

func (t *remoteUpdateTracker) reset(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastUpdateReportID = ""
	t.lastUpdateState = ""
	t.lastUpdateVersion = ""
	if t.lastUpdateAppliedAt.IsZero() || !now.Before(t.lastUpdateAppliedAt.Add(t.effectiveSuppressWindowLocked())) {
		t.lastUpdateSignature = ""
		t.lastUpdateAppliedAt = time.Time{}
		t.consecutiveFailures = 0
		t.lastRunFailed = false
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
	update := *remote.Update
	reportToken := r.agentToken
	r.updateWG.Add(1)
	go func() {
		failed := false
		defer r.updateWG.Done()
		defer func() { r.updates.endApply(signature, remoteUpdateNow(), failed) }()
		defer func() {
			if rec := recover(); rec != nil {
				failed = true
				log.Printf("执行远程更新 panic 已恢复: %v", rec)
			}
		}()
		if err := maybeApplyRemoteUpdate(ctx, func(ctx context.Context, updateID, state, version, message string) error {
			if state == "failed" {
				failed = true
			}
			return r.reportUpdateWithToken(ctx, reportToken, updateID, state, version, message)
		}, r.cfg, &update); err != nil {
			failed = true
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
