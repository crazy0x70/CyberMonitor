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
	"cyber_monitor/internal/cmdutil"
	"cyber_monitor/internal/server"
	"cyber_monitor/internal/updater"
)

var (
	Version     = "dev"
	Commit      = "none"
	BuildTime   = "unknown"
	DefaultMode = "server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "docker-recreate-helper" {
		if err := updater.RunDockerRecreateHelper(context.Background()); err != nil {
			log.Fatalf("Docker helper 执行失败: %v", err)
		}
		return
	}

	showVersion := flag.Bool("version", false, "输出版本信息")
	resetPassword := flag.Bool("reset-password", false, "重置管理员密码")
	mode := flag.String("mode", cmdutil.EnvOrDefault("CM_MODE", DefaultMode), "server 或 agent")

	listen := flag.String("listen", cmdutil.EnvOrDefault("CM_LISTEN", ":25012"), "管理端监听地址")
	publicListen := flag.String("public-listen", cmdutil.EnvOrDefault("CM_PUBLIC_LISTEN", ""), "展示页监听端口(可选，直接填写端口号；留空则与管理端一致)")
	adminUser := flag.String("admin-user", cmdutil.EnvOrDefault("CM_ADMIN_USER", ""), "管理端用户名")
	adminPass := flag.String("admin-pass", cmdutil.EnvOrDefault("CM_ADMIN_PASS", ""), "管理端密码")
	adminPath := flag.String("admin-path", cmdutil.EnvOrDefault("CM_ADMIN_PATH", ""), "管理后台路径")
	jwtSecret := flag.String("jwt-secret", cmdutil.EnvOrDefault("CM_JWT_SECRET", ""), "JWT 密钥")
	agentToken := flag.String("agent-token", cmdutil.EnvOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	dataDir := flag.String("data-dir", cmdutil.EnvOrDefault("CM_DATA_DIR", cmdutil.DefaultDataDir()), "数据目录")

	serverURL := flag.String("server-url", cmdutil.EnvOrDefault("CM_SERVER_URL", ""), "管理端地址(Agent 使用)")
	interval := flag.Duration("interval", cmdutil.EnvDuration("CM_INTERVAL", time.Second), "采样间隔")
	nodeID := flag.String("node-id", cmdutil.EnvOrDefault("CM_NODE_ID", ""), "节点 ID")
	nodeName := flag.String("node-name", cmdutil.EnvOrDefault("CM_NODE_NAME", ""), "节点名称")
	nodeAlias := flag.String("node-alias", cmdutil.EnvOrDefault("CM_NODE_ALIAS", ""), "节点显示名称")
	nodeGroup := flag.String("node-group", cmdutil.EnvOrDefault("CM_NODE_GROUP", ""), "节点分组")
	nodeIDFile := flag.String("node-id-file", cmdutil.EnvOrDefault("CM_NODE_ID_FILE", ""), "节点 ID 持久化文件")
	agentTokenFile := flag.String("agent-token-file", cmdutil.EnvOrDefault("CM_AGENT_TOKEN_FILE", ""), "Agent 专属凭据持久化文件")
	netIface := flag.String("net-iface", cmdutil.EnvOrDefault("CM_NET_IFACE", ""), "采集指定网卡(逗号分隔)")
	netTestsRaw := flag.String("net-tests", cmdutil.EnvOrDefault("CM_NET_TESTS", ""), "网络测试目标列表")
	testInterval := flag.Duration("test-interval", cmdutil.EnvDuration("CM_TEST_INTERVAL", 5*time.Second), "网络测试间隔")
	hostRoot := flag.String("host-root", cmdutil.EnvOrDefault("CM_HOST_ROOT", "/host"), "宿主机挂载根目录")

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

	*listen = cmdutil.NormalizeListen(*listen)
	*publicListen = cmdutil.NormalizeListen(*publicListen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch strings.ToLower(*mode) {
	case "server":
		cfg := server.Config{
			Addr:       *listen,
			PublicAddr: *publicListen,
			AdminUser:  *adminUser,
			AdminPass:  *adminPass,
			AdminPath:  *adminPath,
			JWTSecret:  *jwtSecret,
			AgentToken: *agentToken,
			DataDir:    *dataDir,
			Version:    Version,
			Commit:     Commit,
		}
		if err := server.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("服务启动失败: %v", err)
		}
	case "agent":
		resolvedNodeIDFile, err := agent.ResolveStateFilePath(*nodeIDFile, agent.DefaultNodeIDFileName())
		if err != nil {
			log.Fatalf("解析节点 ID 文件失败: %v", err)
		}
		resolvedNodeID, err := agent.ResolveOrCreateNodeID(*nodeID, resolvedNodeIDFile)
		if err != nil {
			log.Fatalf("初始化节点 ID 失败: %v", err)
		}
		*nodeID = resolvedNodeID
		hostname := cmdutil.DefaultHostname()
		if *nodeName == "" {
			*nodeName = hostname
		}
		resolvedTokenFile, err := agent.ResolveStateFilePath(*agentTokenFile, agent.DefaultAgentTokenFileName())
		if err != nil {
			log.Fatalf("解析 Agent 凭据文件失败: %v", err)
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
			NetIfaces:    cmdutil.ParseCommaList(*netIface),
			TokenFile:    resolvedTokenFile,
		}
		if err := agent.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("Agent 运行失败: %v", err)
		}
	default:
		log.Fatalf("未知模式: %s", *mode)
	}
}

func printVersion() {
	fmt.Printf("CyberMonitor %s (commit %s, build %s)\n", Version, Commit, BuildTime)
}
