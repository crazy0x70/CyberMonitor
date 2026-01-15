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
	"cyber_monitor/internal/server"
)

var (
	Version     = "dev"
	Commit      = "none"
	BuildTime   = "unknown"
	DefaultMode = "server"
)

func main() {
	showVersion := flag.Bool("version", false, "输出版本信息")
	resetPassword := flag.Bool("reset-password", false, "重置管理员密码")
	mode := flag.String("mode", envOrDefault("CM_MODE", DefaultMode), "server 或 agent")

	listen := flag.String("listen", envOrDefault("CM_LISTEN", ":25012"), "管理端监听地址")
	adminUser := flag.String("admin-user", envOrDefault("CM_ADMIN_USER", ""), "管理端用户名")
	adminPass := flag.String("admin-pass", envOrDefault("CM_ADMIN_PASS", ""), "管理端密码")
	adminPath := flag.String("admin-path", envOrDefault("CM_ADMIN_PATH", ""), "管理后台路径")
	jwtSecret := flag.String("jwt-secret", envOrDefault("CM_JWT_SECRET", ""), "JWT 密钥")
	agentToken := flag.String("agent-token", envOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	dataDir := flag.String("data-dir", envOrDefault("CM_DATA_DIR", "/data"), "数据目录")

	serverURL := flag.String("server-url", envOrDefault("CM_SERVER_URL", ""), "管理端地址(Agent 使用)")
	interval := flag.Duration("interval", envDuration("CM_INTERVAL", time.Second), "采样间隔")
	nodeID := flag.String("node-id", envOrDefault("CM_NODE_ID", ""), "节点 ID")
	nodeName := flag.String("node-name", envOrDefault("CM_NODE_NAME", ""), "节点名称")
	nodeAlias := flag.String("node-alias", envOrDefault("CM_NODE_ALIAS", ""), "节点显示名称")
	nodeGroup := flag.String("node-group", envOrDefault("CM_NODE_GROUP", ""), "节点分组")
	netIface := flag.String("net-iface", envOrDefault("CM_NET_IFACE", ""), "采集指定网卡(逗号分隔)")
	netTestsRaw := flag.String("net-tests", envOrDefault("CM_NET_TESTS", ""), "网络测试目标列表")
	testInterval := flag.Duration("test-interval", envDuration("CM_TEST_INTERVAL", 5*time.Second), "网络测试间隔")
	hostRoot := flag.String("host-root", envOrDefault("CM_HOST_ROOT", "/host"), "宿主机挂载根目录")

	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if *resetPassword {
		result, err := server.ResetAdminPassword(*dataDir)
		if err != nil {
			log.Fatalf("重置密码失败: %v", err)
		}
		fmt.Printf("管理员账号: %s\n管理员新密码: %s\n管理后台路径: %s\n", result.AdminUser, result.AdminPass, result.AdminPath)
		return
	}

	*listen = normalizeListen(*listen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch strings.ToLower(*mode) {
	case "server":
		cfg := server.Config{
			Addr:       *listen,
			AdminUser:  *adminUser,
			AdminPass:  *adminPass,
			AdminPath:  *adminPath,
			JWTSecret:  *jwtSecret,
			AgentToken: *agentToken,
			DataDir:    *dataDir,
			Commit:     Commit,
		}
		if err := server.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("服务启动失败: %v", err)
		}
	case "agent":
		hostname := defaultHostname()
		if *nodeID == "" {
			*nodeID = hostname
		}
		if *nodeName == "" {
			*nodeName = hostname
		}
		cfg := agent.Config{
			ServerURL:    *serverURL,
			Interval:     *interval,
			NodeID:       *nodeID,
			NodeName:     *nodeName,
			NodeAlias:    *nodeAlias,
			NodeGroup:    *nodeGroup,
			AgentToken:   *agentToken,
			HostRoot:     *hostRoot,
			NetTests:     agent.ParseNetTests(*netTestsRaw),
			TestInterval: *testInterval,
			NetIfaces:    parseList(*netIface),
		}
		if err := agent.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("Agent 运行失败: %v", err)
		}
	default:
		log.Fatalf("未知模式: %s", *mode)
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
	fmt.Printf("CyberMonitor %s (commit %s, build %s)\n", Version, Commit, BuildTime)
}

func normalizeListen(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, ":") || strings.Contains(trimmed, ":") {
		return trimmed
	}
	return ":" + trimmed
}
