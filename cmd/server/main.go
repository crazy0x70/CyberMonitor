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

	"cyber_monitor/internal/server"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "输出版本信息")
	resetPassword := flag.Bool("reset-password", false, "重置管理员密码")
	listen := flag.String("listen", envOrDefault("CM_LISTEN", ":25012"), "管理端监听地址")
	publicListen := flag.String("public-listen", envOrDefault("CM_PUBLIC_LISTEN", ""), "展示页监听端口(可选，直接填写端口号；留空则与管理端一致)")
	adminUser := flag.String("admin-user", envOrDefault("CM_ADMIN_USER", ""), "管理端用户名")
	adminPass := flag.String("admin-pass", envOrDefault("CM_ADMIN_PASS", ""), "管理端密码")
	adminPath := flag.String("admin-path", envOrDefault("CM_ADMIN_PATH", ""), "管理后台路径")
	jwtSecret := flag.String("jwt-secret", envOrDefault("CM_JWT_SECRET", ""), "JWT 密钥")
	agentToken := flag.String("agent-token", envOrDefault("CM_AGENT_TOKEN", ""), "Agent Token")
	dataDir := flag.String("data-dir", envOrDefault("CM_DATA_DIR", "/data"), "数据目录")
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
	*publicListen = normalizeListen(*publicListen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{
		Addr:       *listen,
		PublicAddr: *publicListen,
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
}

func envOrDefault(key, def string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	return value
}

func printVersion() {
	fmt.Printf("CyberMonitor Server %s (commit %s, build %s)\n", Version, Commit, BuildTime)
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
