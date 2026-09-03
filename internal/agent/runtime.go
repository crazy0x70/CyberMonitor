package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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
	lastUpdateReportID  string
	lastUpdateState     string
	lastUpdateVersion   string
	lastUpdateSignature string
	lastUpdateAppliedAt time.Time
}

const (
	remoteUpdateDuplicateSuppressWindow = 2 * time.Minute
	agentTokenRegisterRetryInterval     = 30 * time.Second
)

var remoteUpdateNow = time.Now

func newAgentRunner(cfg Config, transport agentControlPlane, collector *metrics.Collector) *agentRunner {
	return &agentRunner{
		cfg:        cfg,
		transport:  transport,
		collector:  collector,
		runtimeCfg: newRuntimeConfig(cfg),
		testCache:  make(map[string]cachedTest),
		agentToken: strings.TrimSpace(cfg.AgentToken),
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
		log.Printf("拉取远程配置失败: %v", err)
		return
	}

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
		r.lastUpdateState = ""
		r.lastUpdateVersion = ""
		r.lastUpdateReportID = ""
		r.lastUpdateSignature = ""
		r.lastUpdateAppliedAt = time.Time{}
		return
	}
	if !r.agentTokenDurable {
		log.Printf("拒绝执行远程更新: Agent 专属凭据尚未可靠写入 %s", strings.TrimSpace(r.cfg.TokenFile))
		return
	}
	signature := remoteUpdateInstructionSignature(remote.Update)
	now := remoteUpdateNow()
	if r.shouldSuppressRemoteUpdate(signature, now) {
		return
	}
	if signature != r.lastUpdateSignature {
		r.lastUpdateState = ""
		r.lastUpdateVersion = ""
		r.lastUpdateReportID = ""
	}
	if err := maybeApplyRemoteUpdate(ctx, r.reportRemoteUpdate, r.cfg, remote.Update); err != nil {
		log.Printf("执行远程更新失败: %v", err)
		return
	}
	r.lastUpdateSignature = signature
	r.lastUpdateAppliedAt = now
}

func (r *agentRunner) shouldSuppressRemoteUpdate(signature string, now time.Time) bool {
	if signature == "" || signature != r.lastUpdateSignature || r.lastUpdateAppliedAt.IsZero() {
		return false
	}
	return now.Before(r.lastUpdateAppliedAt.Add(remoteUpdateDuplicateSuppressWindow))
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

func (r *agentRunner) reportRemoteUpdate(ctx context.Context, updateID, state, version, message string) error {
	updateID = strings.TrimSpace(updateID)
	terminalState := isTerminalUpdateState(state)
	if terminalState && r.lastUpdateReportID == updateID && r.lastUpdateState == state && r.lastUpdateVersion == version {
		return nil
	}
	_, err := callWithTokenRefresh(r, ctx, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, r.transport.ReportUpdate(ctx, r.cfg.NodeID, r.agentToken, updateID, state, version, message)
	})
	if err != nil {
		return err
	}
	if terminalState {
		r.lastUpdateReportID = updateID
		r.lastUpdateState = state
		r.lastUpdateVersion = version
	}
	return nil
}

func (r *agentRunner) collectAndReport(ctx context.Context) {
	sample, err := r.collector.Collect()
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
	if testsSnapshot, resultsChanged := runNetworkTestsWithCache(ctx, tests, interval, r.testCache); configChanged || resultsChanged {
		sample.NetworkTestsChanged = true
		sample.NetworkTests = testsSnapshot
	}

	if err := r.reportStats(ctx, sample); err != nil {
		log.Printf("上报失败: %v", err)
	}
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
	case err == nil, os.IsNotExist(err):
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
