package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

const (
	defaultGRPCFallbackBackoff = 30 * time.Second
	maxGRPCFallbackBackoff     = 10 * time.Minute
	defaultGRPCDialTimeout     = 4 * time.Second
	defaultGRPCCallTimeout     = 4 * time.Second
)

type grpcTransportOptions struct {
	fallbackBackoff time.Duration
	dialTimeout     time.Duration
	callTimeout     time.Duration
}

func defaultGRPCTransportOptions() grpcTransportOptions {
	return grpcTransportOptions{
		fallbackBackoff: defaultGRPCFallbackBackoff,
		dialTimeout:     defaultGRPCDialTimeout,
		callTimeout:     defaultGRPCCallTimeout,
	}
}

func (o grpcTransportOptions) normalized() grpcTransportOptions {
	defaults := defaultGRPCTransportOptions()
	if o.fallbackBackoff <= 0 {
		o.fallbackBackoff = defaults.fallbackBackoff
	}
	if o.dialTimeout <= 0 {
		o.dialTimeout = defaults.dialTimeout
	}
	if o.callTimeout <= 0 {
		o.callTimeout = defaults.callTimeout
	}
	return o
}

// nextGRPCBackoff 计算下一次 gRPC 失败后的回退时长：从 base 起按 2 倍
// 指数增长，封顶 maxGRPCFallbackBackoff。current 为 0 表示当前无连续
// 失败，直接返回 base。首次 gRPC 成功会将 current 归零，退避重新从
// base 开始，避免瞬断后恢复过慢。
func nextGRPCBackoff(base, current time.Duration) time.Duration {
	if base <= 0 {
		base = defaultGRPCFallbackBackoff
	}
	next := base
	if current > 0 {
		next = current * 2
	}
	if next <= 0 || next > maxGRPCFallbackBackoff {
		return maxGRPCFallbackBackoff
	}
	return next
}

type agentControlPlane interface {
	RegisterNodeToken(context.Context, string, string) (string, error)
	FetchConfig(context.Context, string, string) (RemoteConfig, error)
	ReportStats(context.Context, metrics.NodeStats, string) (bool, error)
	ReportUpdate(context.Context, string, string, string, string, string, string) error
	Close() error
}

type controlPlaneTransport struct {
	http *httpControlPlane
	grpc *grpcControlPlane
	opts grpcTransportOptions

	mu                  sync.Mutex
	grpcBackoffUntil    time.Time
	grpcBackoffDuration time.Duration
	lastMode            string
}

type httpControlPlane struct {
	client           *http.Client
	configEndpoint   string
	registerEndpoint string
	statsEndpoint    string
	updateEndpoint   string
	capabilities     []string
}

type grpcControlPlane struct {
	target       string
	secure       bool
	opts         grpcTransportOptions
	capabilities []string
	dialContext  func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error)

	mu      sync.Mutex
	conn    *grpc.ClientConn
	client  agentrpc.AgentServiceClient
	dialErr error
}

func newControlPlaneTransportWithOptions(cfg Config, client *http.Client, options grpcTransportOptions) agentControlPlane {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	options = options.normalized()
	capabilities := agentCapabilitiesForConfig(cfg)
	return &controlPlaneTransport{
		http: &httpControlPlane{
			client:           client,
			statsEndpoint:    baseURL + "/api/v1/ingest",
			configEndpoint:   baseURL + "/api/v1/agent/config",
			registerEndpoint: baseURL + "/api/v1/agent/register",
			updateEndpoint:   baseURL + "/api/v1/agent/update/report",
			capabilities:     capabilities,
		},
		grpc: newGRPCControlPlane(baseURL, options, capabilities),
		opts: options,
	}
}

func newGRPCControlPlane(serverURL string, options grpcTransportOptions, capabilities []string) *grpcControlPlane {
	target, secure, err := parseGRPCTarget(serverURL)
	if err != nil || target == "" {
		return nil
	}
	return &grpcControlPlane{
		target:       target,
		secure:       secure,
		opts:         options,
		capabilities: append([]string(nil), capabilities...),
		dialContext:  grpc.DialContext,
	}
}

func parseGRPCTarget(serverURL string) (string, bool, error) {
	trimmed := strings.TrimSpace(serverURL)
	if trimmed == "" {
		return "", false, nil
	}
	if !strings.Contains(trimmed, "://") {
		return trimmed, false, nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false, err
	}
	target := strings.TrimSpace(parsed.Host)
	if target == "" {
		return "", false, fmt.Errorf("grpc target missing host")
	}
	if parsed.Port() == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			target = net.JoinHostPort(parsed.Hostname(), "443")
		case "http":
			target = net.JoinHostPort(parsed.Hostname(), "80")
		}
	}
	return target, strings.EqualFold(parsed.Scheme, "https"), nil
}

func (t *controlPlaneTransport) RegisterNodeToken(ctx context.Context, nodeID, bootstrapToken string) (string, error) {
	return callWithFallback(
		t,
		ctx,
		func(callCtx context.Context, grpcPlane *grpcControlPlane) (string, error) {
			return grpcPlane.RegisterNodeToken(callCtx, nodeID, bootstrapToken)
		},
		func(callCtx context.Context, httpPlane *httpControlPlane) (string, error) {
			return httpPlane.RegisterNodeToken(callCtx, nodeID, bootstrapToken)
		},
	)
}

func (t *controlPlaneTransport) FetchConfig(ctx context.Context, nodeID, token string) (RemoteConfig, error) {
	return callWithFallback(
		t,
		ctx,
		func(callCtx context.Context, grpcPlane *grpcControlPlane) (RemoteConfig, error) {
			return grpcPlane.FetchConfig(callCtx, nodeID, token)
		},
		func(callCtx context.Context, httpPlane *httpControlPlane) (RemoteConfig, error) {
			return httpPlane.FetchConfig(callCtx, nodeID, token)
		},
	)
}

func (t *controlPlaneTransport) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) (bool, error) {
	return callWithFallback(
		t,
		ctx,
		func(callCtx context.Context, grpcPlane *grpcControlPlane) (bool, error) {
			return grpcPlane.ReportStats(callCtx, stats, token)
		},
		func(callCtx context.Context, httpPlane *httpControlPlane) (bool, error) {
			return httpPlane.ReportStats(callCtx, stats, token)
		},
	)
}

func (t *controlPlaneTransport) ReportUpdate(ctx context.Context, nodeID, token, updateID, state, version, message string) error {
	_, err := callWithFallback(
		t,
		ctx,
		func(callCtx context.Context, grpcPlane *grpcControlPlane) (struct{}, error) {
			return struct{}{}, grpcPlane.ReportUpdate(callCtx, nodeID, token, updateID, state, version, message)
		},
		func(callCtx context.Context, httpPlane *httpControlPlane) (struct{}, error) {
			return struct{}{}, httpPlane.ReportUpdate(callCtx, nodeID, token, updateID, state, version, message)
		},
	)
	return err
}

func (t *controlPlaneTransport) Close() error {
	if t.grpc == nil {
		return nil
	}
	return t.grpc.Close()
}

func (t *controlPlaneTransport) canUseGRPC() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Now().After(t.grpcBackoffUntil)
}

func (t *controlPlaneTransport) disableGRPCTemporarily(err error) {
	t.mu.Lock()
	now := time.Now()
	var next time.Duration
	if now.Before(t.grpcBackoffUntil) {
		// 并发失败（config ticker/上报/更新报告同时命中）：已在退避窗口内
		// 只延长窗口、不推进档位，一次故障事件不重复计连续失败。
		t.grpcBackoffUntil = now.Add(t.grpcBackoffDuration)
		next = t.grpcBackoffDuration
	} else {
		next = nextGRPCBackoff(t.opts.fallbackBackoff, t.grpcBackoffDuration)
		t.grpcBackoffDuration = next
		t.grpcBackoffUntil = now.Add(next)
	}
	t.lastMode = "http"
	t.mu.Unlock()
	target, state := t.grpc.connectionStatus()
	log.Printf("gRPC 控制链路不可用，已回退 HTTP 并退避 %s: target=%s state=%s err=%v", next, target, state, err)
	_ = t.grpc.Close()
}

func callWithFallback[T any](
	t *controlPlaneTransport,
	ctx context.Context,
	grpcCall func(context.Context, *grpcControlPlane) (T, error),
	httpCall func(context.Context, *httpControlPlane) (T, error),
) (T, error) {
	var zero T
	if t.grpc != nil && t.canUseGRPC() {
		result, err := grpcCall(ctx, t.grpc)
		if err == nil {
			t.noteMode("grpc")
			return result, nil
		}
		if !shouldFallbackToHTTP(err) {
			return zero, err
		}
		if st, ok := status.FromError(err); ok && st.Code() == codes.DeadlineExceeded && t.grpc.connReady() {
			// callTimeout 包住的是服务端处理全程：健康连接上的
			// DeadlineExceeded 是应用层慢而非传输故障，透传错误给调用方，
			// 不拆连接、不退避、不做 HTTP 重放（重放同样慢且放大负载）。
			return zero, err
		}
		t.disableGRPCTemporarily(err)
	}

	result, err := httpCall(ctx, t.http)
	if err == nil {
		t.noteMode("http")
	}
	return result, err
}

func (t *controlPlaneTransport) noteMode(mode string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if mode == "grpc" {
		if t.lastMode == "http" {
			log.Printf("gRPC 控制链路已恢复")
		}
		// 首次 gRPC 成功即重置连续失败计数，退避从 base 重新开始。
		t.grpcBackoffDuration = 0
	}
	t.lastMode = mode
}

func (h *httpControlPlane) RegisterNodeToken(ctx context.Context, nodeID, bootstrapToken string) (string, error) {
	return registerNodeToken(ctx, h.client, h.registerEndpoint, nodeID, bootstrapToken)
}

func (h *httpControlPlane) FetchConfig(ctx context.Context, nodeID, token string) (RemoteConfig, error) {
	return fetchRemoteConfig(ctx, h.client, h.configEndpoint, nodeID, token, h.capabilities)
}

func (h *httpControlPlane) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) (bool, error) {
	req, err := newAgentJSONRequest(ctx, http.MethodPost, h.statsEndpoint, stats, token)
	if err != nil {
		return false, err
	}
	var result struct {
		// 服务端 ingest 响应为 {"status":"ok","refresh_config":...}；
		// 字段名需与服务端 key 对齐才能取到 refresh_config。
		Status        string `json:"status"`
		RefreshConfig bool   `json:"refresh_config"`
	}
	if err := performAgentRequest(h.client, req, "ingest", func(body io.Reader) error {
		return decodeAgentResponseJSON(body, &result, "ingest response has trailing data")
	}); err != nil {
		return false, err
	}
	return result.RefreshConfig, nil
}

func (h *httpControlPlane) ReportUpdate(ctx context.Context, nodeID, token, updateID, state, version, message string) error {
	return postAgentUpdateReport(ctx, h.client, h.updateEndpoint, nodeID, token, updateID, state, version, message)
}

func (g *grpcControlPlane) RegisterNodeToken(ctx context.Context, nodeID, bootstrapToken string) (string, error) {
	// 与 HTTP 路径的 registerNodeToken 预检对齐：空 nodeID/token 不发请求。
	if strings.TrimSpace(nodeID) == "" {
		return "", fmt.Errorf("node id required")
	}
	if strings.TrimSpace(bootstrapToken) == "" {
		return "", fmt.Errorf("bootstrap token required")
	}
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	resp, err := client.Register(callCtx, &agentrpc.RegisterRequest{
		NodeID:         nodeID,
		BootstrapToken: bootstrapToken,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.AgentToken), nil
}

func (g *grpcControlPlane) FetchConfig(ctx context.Context, nodeID, token string) (RemoteConfig, error) {
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return RemoteConfig{}, err
	}
	defer cancel()
	resp, err := client.GetConfig(callCtx, &agentrpc.ConfigRequest{
		NodeID:       nodeID,
		AgentToken:   token,
		Capabilities: append([]string(nil), g.capabilities...),
	})
	if err != nil {
		return RemoteConfig{}, err
	}
	return RemoteConfig{
		Alias:           resp.Alias,
		Group:           resp.Group,
		AgentToken:      resp.AgentToken,
		Tests:           resp.Tests,
		TestIntervalSec: resp.TestIntervalSec,
		Update:          fromRPCUpdateInstruction(resp.Update),
	}, nil
}

func (g *grpcControlPlane) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) (bool, error) {
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	resp, err := client.ReportStats(callCtx, &agentrpc.ReportStatsRequest{
		AgentToken: token,
		Stats:      stats,
	})
	if err != nil {
		return false, err
	}
	return resp.RefreshConfig, nil
}

func (g *grpcControlPlane) ReportUpdate(ctx context.Context, nodeID, token, updateID, state, version, message string) error {
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = client.ReportUpdate(callCtx, &agentrpc.ReportUpdateRequest{
		NodeID:     nodeID,
		AgentToken: token,
		UpdateID:   updateID,
		State:      state,
		Version:    version,
		Message:    message,
	})
	return err
}

func (g *grpcControlPlane) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var err error
	if g.conn != nil {
		err = g.conn.Close()
		g.conn = nil
		g.client = nil
	}
	// 清除 dial 失败状态：瞬时失败不得永久杀死 gRPC 传输，
	// HTTP 回退退避恢复后必须能够重拨。
	g.dialErr = nil
	return err
}

func (g *grpcControlPlane) connectionStatus() (string, string) {
	g.mu.Lock()
	conn := g.conn
	target := g.target
	g.mu.Unlock()
	if conn == nil {
		return target, "not_initialized"
	}
	return target, conn.GetState().String()
}

// connReady 报告底层连接是否处于 Ready（用于区分应用层慢与传输故障）。
func (g *grpcControlPlane) connReady() bool {
	g.mu.Lock()
	conn := g.conn
	g.mu.Unlock()
	return conn != nil && conn.GetState() == connectivity.Ready
}

func (g *grpcControlPlane) prepareCall(ctx context.Context) (agentrpc.AgentServiceClient, context.Context, context.CancelFunc, error) {
	client, err := g.clientConn(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	g.mu.Lock()
	conn := g.conn
	g.mu.Unlock()
	if conn == nil {
		return nil, nil, nil, status.Error(codes.Unavailable, "grpc transport not ready")
	}
	state := conn.GetState()
	if state == connectivity.Shutdown {
		_ = g.Close()
		return nil, nil, nil, status.Error(codes.Unavailable, "grpc transport shutdown")
	}
	if state == connectivity.Idle {
		conn.Connect()
	}
	callCtx, cancel := context.WithTimeout(ctx, g.opts.callTimeout)
	return client, callCtx, cancel, nil
}

// clientConn 在锁内完成 dial 与状态读写：远程更新 goroutine 与主上报循环
// 会并发使用同一 transport，历史上依赖"单 goroutine"假设的 dialOnce 重置
// 模式构成数据竞态。dial 失败记入 dialErr 并保持到 Close 清除（与原
// dialOnce 语义一致：瞬时失败不会永久杀死 gRPC 传输，Close 后可重拨）。
func (g *grpcControlPlane) clientConn(ctx context.Context) (agentrpc.AgentServiceClient, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client != nil {
		return g.client, nil
	}
	if g.dialErr != nil {
		// 包装成 Unavailable 让 shouldFallbackToHTTP 命中，否则裸 dial 错误
		// 不会回退 HTTP。
		return nil, status.Errorf(codes.Unavailable, "grpc dial failed: %v", g.dialErr)
	}

	dialCtx, cancel := context.WithTimeout(ctx, g.opts.dialTimeout)
	defer cancel()

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(agentrpc.GobCodec{}),
			grpc.WaitForReady(true),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   10 * time.Second,
			},
			MinConnectTimeout: g.opts.dialTimeout,
		}),
	}
	if g.secure {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := g.dialContext(dialCtx, g.target, opts...)
	if err != nil {
		g.dialErr = err
		return nil, status.Errorf(codes.Unavailable, "grpc dial failed: %v", err)
	}
	g.conn = conn
	g.client = agentrpc.NewAgentServiceClient(conn)
	return g.client, nil
}

func fromRPCUpdateInstruction(update *agentrpc.UpdateInstruction) *RemoteUpdateInstruction {
	if update == nil {
		return nil
	}
	return &RemoteUpdateInstruction{
		ID:          update.ID,
		Version:     update.Version,
		DownloadURL: update.DownloadURL,
		ChecksumURL: update.ChecksumURL,
		RequestedAt: update.RequestedAt,
	}
}

func shouldFallbackToHTTP(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		// gRPC status 错误只按 code 判定。status 的 message 会携带服务端
		// 透传的应用层错误文本（grpcStatusFromAPIError 原样保留），其中
		// 常见 "connection refused"（下游 store/数据库）等字样，若落入下方
		// 原始串扫描会误触发回退，复活"关健康连接 + HTTP 重放"的抖动。
		switch st.Code() {
		case codes.Unavailable, codes.Unimplemented, codes.DeadlineExceeded:
			return true
		case codes.Internal:
			// grpc 框架自身的编解码/传输类 Internal 以 message 关键字识别。
			msg := strings.ToLower(st.Message())
			return strings.Contains(msg, "transport") || strings.Contains(msg, "content-type") || strings.Contains(msg, "http status")
		}
		return false
	}
	// 非 status 错误是客户端本地/net 层错误，按 marker 启发式回退。
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unexpected eof",
		"malformed http response",
		"http status code",
		"content-type",
		"connection refused",
		"no connection established",
		"error reading server preface",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
