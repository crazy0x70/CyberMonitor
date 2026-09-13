package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"cyber_monitor/internal/cmdutil"
	"cyber_monitor/internal/server"
	"cyber_monitor/internal/updater"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func resolvedVersion() string {
	return cmdutil.EnvOrDefault("CM_VERSION", Version)
}

func resolvedCommit() string {
	return cmdutil.EnvOrDefault("CM_COMMIT", Commit)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "docker-recreate-helper" {
		if err := updater.RunDockerRecreateHelper(context.Background()); err != nil {
			log.Fatalf("Docker helper 执行失败: %v", err)
		}
		return
	}

	showVersion := flag.Bool("version", false, "输出版本信息")
	resetPassword := flag.Bool("reset-password", false, "重置管理员密码")
	listen := flag.String("listen", cmdutil.EnvOrDefault("CM_LISTEN", ":25012"), "管理端监听地址")
	publicListen := flag.String("public-listen", cmdutil.EnvOrDefault("CM_PUBLIC_LISTEN", ""), "展示页监听端口(可选，直接填写端口号；留空则与管理端一致)")
	adminUser := flag.String("admin-user", cmdutil.EnvOrDefault("CM_ADMIN_USER", ""), "管理端用户名")
	adminPass := flag.String("admin-pass", cmdutil.EnvOrDefault("CM_ADMIN_PASS", ""), "管理端密码")
	adminPath := flag.String("admin-path", cmdutil.EnvOrDefault("CM_ADMIN_PATH", ""), "管理后台路径")
	jwtSecret := flag.String("jwt-secret", cmdutil.EnvOrDefault("CM_JWT_SECRET", ""), "JWT 密钥")
	agentToken := flag.String("agent-token", cmdutil.EnvOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	dataDir := flag.String("data-dir", cmdutil.EnvOrDefault("CM_DATA_DIR", cmdutil.DefaultDataDir()), "数据目录")
	trustProxyHeaders := flag.Bool("trust-proxy-headers", cmdutil.EnvBool("CM_TRUST_PROXY_HEADERS", false), "信任反向代理设置的 X-Forwarded-* 头")
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
	// 在任何 I/O 与凭据生成之前校验，失败时点名 flag，避免全量初始化
	// 完成后才在 net.Listen 处报出不指明来源的错误。
	for _, item := range []struct{ name, value string }{
		{"listen", *listen},
		{"public-listen", *publicListen},
	} {
		if item.value == "" {
			continue
		}
		_, port, err := net.SplitHostPort(item.value)
		if err != nil {
			log.Fatalf("-%s 值 %q 不是合法监听地址: %v", item.name, item.value, err)
		}
		if port != "" {
			// SplitHostPort 把端口当不透明字符串，服务名不可解析（如 ":abc"）
			// 要靠 LookupPort 才能前置拦截。
			if _, err := net.LookupPort("tcp", port); err != nil {
				log.Fatalf("-%s 值 %q 端口 %q 不是合法端口: %v", item.name, item.value, port, err)
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 关闭链在途（HTTP drain、history Close 可达 30s）时第二次信号会被
	// NotifyContext 忽略：对齐 agent 侧，二次信号直接强退。
	forced := make(chan os.Signal, 2)
	signal.Notify(forced, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(forced)
	go func() {
		signals := 0
		for range forced {
			signals++
			if signals >= 2 {
				log.Fatalf("再次收到退出信号，强制终止")
			}
		}
	}()

	cfg := server.Config{
		Addr:                *listen,
		PublicAddr:          *publicListen,
		AdminUser:           *adminUser,
		AdminPass:           *adminPass,
		AdminPath:           *adminPath,
		JWTSecret:           *jwtSecret,
		AgentToken:          *agentToken,
		DataDir:             *dataDir,
		Version:             resolvedVersion(),
		Commit:              resolvedCommit(),
		TrustedProxyHeaders: *trustProxyHeaders,
	}
	if err := server.Run(ctx, cfg); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

func printVersion() {
	fmt.Printf("CyberMonitor Server %s (commit %s, build %s)\n", resolvedVersion(), resolvedCommit(), BuildTime)
}
