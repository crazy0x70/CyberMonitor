package agent

import (
	"context"
	"log"
	"os"
	"strings"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"
)

type agentRunner struct {
	cfg                 Config
	transport           agentControlPlane
	collector           *metrics.Collector
	runtimeCfg          *runtimeConfig
	testCache           map[string]cachedTest
	dockerManagedUpdate bool
	agentToken          string
}

func newAgentRunner(cfg Config, transport agentControlPlane, collector *metrics.Collector) *agentRunner {
	return &agentRunner{
		cfg:                 cfg,
		transport:           transport,
		collector:           collector,
		runtimeCfg:          newRuntimeConfig(cfg),
		testCache:           make(map[string]cachedTest),
		dockerManagedUpdate: updater.CanDockerManagedUpdate(),
		agentToken:          strings.TrimSpace(cfg.AgentToken),
	}
}

func (r *agentRunner) bootstrapToken(ctx context.Context) {
	if r.cfg.TokenFile != "" {
		if persisted, err := loadPersistedAgentToken(r.cfg.TokenFile); err == nil && persisted != "" {
			r.agentToken = persisted
		} else if err != nil && !os.IsNotExist(err) {
			log.Printf("读取 Agent 凭据文件失败: %v", err)
		}
	}

	if r.cfg.AgentToken == "" || r.agentToken != strings.TrimSpace(r.cfg.AgentToken) {
		return
	}

	issuedToken, err := r.transport.RegisterNodeToken(ctx, r.cfg.NodeID, r.cfg.AgentToken)
	if err == nil && issuedToken != "" {
		r.agentToken = issuedToken
		if r.cfg.TokenFile != "" {
			if err := persistAgentToken(r.cfg.TokenFile, issuedToken); err != nil {
				log.Printf("持久化 Agent 专属凭据失败: %v", err)
			}
		}
		return
	}
	if err != nil && !strings.Contains(err.Error(), "register status 401") {
		log.Printf("节点注册未成功，继续尝试使用当前 Agent Token: %v", err)
	}
}

func (r *agentRunner) syncRemoteConfig(ctx context.Context) {
	remote, err := r.transport.FetchConfig(ctx, r.cfg.NodeID, r.agentToken)
	if err != nil {
		log.Printf("拉取远程配置失败: %v", err)
		return
	}

	nextToken, updateCfg, persistErr := applyRemoteConfig(r.cfg, r.runtimeCfg, r.agentToken, remote)
	r.agentToken = nextToken
	if persistErr != nil {
		log.Printf("持久化 Agent 专属凭据失败: %v", persistErr)
	}
	if err := maybeApplyRemoteUpdate(ctx, r.transport, updateCfg, remote.Update); err != nil {
		log.Printf("执行远程更新失败: %v", err)
	}
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
	sample.DockerManagedUpdate = r.dockerManagedUpdate
	sample.AgentUpdateDisabled = r.cfg.DisableUpdate

	alias, group, tests, interval, _ := r.runtimeCfg.Snapshot()
	if alias != "" {
		sample.NodeAlias = alias
	}
	if group != "" {
		sample.NodeGroup = group
	}
	if len(tests) > 0 {
		sample.NetworkTests = runNetworkTestsWithCache(ctx, tests, interval, r.testCache)
	}

	if err := r.transport.ReportStats(ctx, sample, r.agentToken); err != nil {
		log.Printf("上报失败: %v", err)
	}
}

func applyRemoteConfig(cfg Config, runtimeCfg *runtimeConfig, agentToken string, remote RemoteConfig) (string, Config, error) {
	nextToken := agentToken
	if issuedToken := strings.TrimSpace(remote.AgentToken); issuedToken != "" && issuedToken != nextToken {
		nextToken = issuedToken
	}
	runtimeCfg.Update(remote)

	updateCfg := cfg
	updateCfg.AgentToken = nextToken
	if cfg.TokenFile == "" || nextToken == agentToken {
		return nextToken, updateCfg, nil
	}
	return nextToken, updateCfg, persistAgentToken(cfg.TokenFile, nextToken)
}
