package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cyber_monitor/internal/agent"
	"cyber_monitor/internal/cmdutil"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "输出版本信息")
	serverURL := flag.String("server-url", cmdutil.EnvOrDefault("CM_SERVER_URL", ""), "管理端地址")
	interval := flag.Duration("interval", cmdutil.EnvDuration("CM_INTERVAL", time.Second), "采样间隔")
	nodeID := flag.String("node-id", cmdutil.EnvOrDefault("CM_NODE_ID", ""), "节点 ID")
	nodeName := flag.String("node-name", cmdutil.EnvOrDefault("CM_NODE_NAME", ""), "节点名称")
	nodeAlias := flag.String("node-alias", cmdutil.EnvOrDefault("CM_NODE_ALIAS", ""), "节点显示名称")
	nodeGroup := flag.String("node-group", cmdutil.EnvOrDefault("CM_NODE_GROUP", ""), "节点分组")
	agentToken := flag.String("agent-token", cmdutil.EnvOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	netIface := flag.String("net-iface", cmdutil.EnvOrDefault("CM_NET_IFACE", ""), "采集指定网卡(逗号分隔)")
	netTestsRaw := flag.String("net-tests", cmdutil.EnvOrDefault("CM_NET_TESTS", ""), "网络测试目标列表")
	testInterval := flag.Duration("test-interval", cmdutil.EnvDuration("CM_TEST_INTERVAL", 5*time.Second), "网络测试间隔")
	hostRoot := flag.String("host-root", cmdutil.EnvOrDefault("CM_HOST_ROOT", "/host"), "宿主机挂载根目录")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if *serverURL == "" {
		log.Fatal("必须指定管理端地址: -server-url 或 CM_SERVER_URL")
	}

	hostname := cmdutil.DefaultHostname()
	if *nodeID == "" {
		*nodeID = hostname
	}
	if *nodeName == "" {
		*nodeName = hostname
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := agent.Config{
		ServerURL:    *serverURL,
		Interval:     *interval,
		NodeID:       *nodeID,
		NodeName:     *nodeName,
		NodeAlias:    *nodeAlias,
		NodeGroup:    *nodeGroup,
		AgentToken:   *agentToken,
		AgentVersion: Version,
		HostRoot:     *hostRoot,
		NetTests:     agent.ParseNetTests(*netTestsRaw),
		TestInterval: *testInterval,
		NetIfaces:    cmdutil.ParseCommaList(*netIface),
	}
	if handled, err := maybeRunAsService(cfg); handled {
		if err != nil {
			log.Fatalf("Agent 服务启动失败: %v", err)
		}
		return
	}
	if err := agent.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Agent 运行失败: %v", err)
	}
}

func printVersion() {
	fmt.Printf("CyberMonitor Agent %s (commit %s, build %s)\n", Version, Commit, BuildTime)
}
