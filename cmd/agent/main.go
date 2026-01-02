package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cyber_monitor/internal/agent"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "输出版本信息")
	serverURL := flag.String("server-url", envOrDefault("CM_SERVER_URL", ""), "管理端地址")
	interval := flag.Duration("interval", envDuration("CM_INTERVAL", time.Second), "采样间隔")
	nodeID := flag.String("node-id", envOrDefault("CM_NODE_ID", ""), "节点 ID")
	nodeName := flag.String("node-name", envOrDefault("CM_NODE_NAME", ""), "节点名称")
	nodeAlias := flag.String("node-alias", envOrDefault("CM_NODE_ALIAS", ""), "节点显示名称")
	nodeGroup := flag.String("node-group", envOrDefault("CM_NODE_GROUP", ""), "节点分组")
	agentToken := flag.String("agent-token", envOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	netIface := flag.String("net-iface", envOrDefault("CM_NET_IFACE", ""), "采集指定网卡(逗号分隔)")
	netTestsRaw := flag.String("net-tests", envOrDefault("CM_NET_TESTS", ""), "网络测试目标列表")
	testInterval := flag.Duration("test-interval", envDuration("CM_TEST_INTERVAL", 5*time.Second), "网络测试间隔")
	hostRoot := flag.String("host-root", envOrDefault("CM_HOST_ROOT", "/host"), "宿主机挂载根目录")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if *serverURL == "" {
		log.Fatal("必须指定管理端地址: -server-url 或 CM_SERVER_URL")
	}

	hostname := defaultHostname()
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
		NetIfaces:    parseList(*netIface),
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

func envOrDefault(key, def string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	return value
}

func envDuration(key string, def time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return def
	}
	return duration
}

func parseList(raw string) []string {
	parts := strings.Split(raw, ",")
	list := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		list = append(list, value)
	}
	return list
}

func defaultHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "node"
	}
	return hostname
}

func printVersion() {
	fmt.Printf("CyberMonitor Agent %s (commit %s, build %s)\n", Version, Commit, BuildTime)
}
