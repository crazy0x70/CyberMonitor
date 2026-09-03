package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	defaultGRPCDialTimeout     = 4 * time.Second
	defaultGRPCCallTimeout     = 5 * time.Second
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

	mu               sync.Mutex
	grpcBackoffUntil time.Time
	lastMode         string
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

	mu       sync.Mutex
	conn     *grpc.ClientConn
	client   agentrpc.AgentServiceClient
	dialOnce sync.Once
	dialErr  error
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
	if t.useHTTPForStats() {
		return t.http.ReportStats(ctx, stats, token)
	}
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

func (t *controlPlaneTransport) useHTTPForStats() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.grpcBackoffUntil.IsZero() && time.Now().Before(t.grpcBackoffUntil)
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
	t.grpcBackoffUntil = time.Now().Add(t.opts.fallbackBackoff)
	t.lastMode = "http"
	t.mu.Unlock()
	if t.grpc != nil {
		target, state := t.grpc.connectionStatus()
		log.Printf("gRPC 控制链路不可用，已回退 HTTP %s: target=%s state=%s err=%v", t.opts.fallbackBackoff, target, state, err)
		_ = t.grpc.Close()
		return
	}
	log.Printf("gRPC 控制链路不可用，已回退 HTTP %s: %v", t.opts.fallbackBackoff, err)
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
	if mode == "grpc" && t.lastMode == "http" {
		log.Printf("gRPC 控制链路已恢复")
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
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, readAgentAPIStatusError(resp, "ingest")
	}
	var result struct {
		RefreshConfig bool `json:"refresh_config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.RefreshConfig, nil
}

func (h *httpControlPlane) ReportUpdate(ctx context.Context, nodeID, token, updateID, state, version, message string) error {
	return postAgentUpdateReport(ctx, h.client, h.updateEndpoint, nodeID, token, updateID, state, version, message)
}

func (g *grpcControlPlane) RegisterNodeToken(ctx context.Context, nodeID, bootstrapToken string) (string, error) {
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
	// Close rewrites dialOnce without holding a lock that clientConn's Do
	// would honor; this is safe because the whole transport (Close included)
	// is only ever used from the agent's single report loop goroutine.
	g.mu.Lock()
	defer g.mu.Unlock()
	var err error
	if g.conn != nil {
		err = g.conn.Close()
		g.conn = nil
		g.client = nil
	}
	// Re-arm the once-synchronized dial even when no connection was ever
	// established: a transient dial failure must not permanently kill the
	// gRPC transport, otherwise the HTTP-fallback backoff recovery can
	// never retry the dial.
	g.dialErr = nil
	g.dialOnce = sync.Once{}
	return err
}

func (g *grpcControlPlane) connectionStatus() (string, string) {
	if g == nil {
		return "", "disabled"
	}
	g.mu.Lock()
	conn := g.conn
	target := g.target
	g.mu.Unlock()
	if conn == nil {
		return target, "not_initialized"
	}
	return target, conn.GetState().String()
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

func (g *grpcControlPlane) clientConn(ctx context.Context) (agentrpc.AgentServiceClient, error) {
	g.dialOnce.Do(func() {
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
			return
		}

		g.mu.Lock()
		g.conn = conn
		g.client = agentrpc.NewAgentServiceClient(conn)
		g.mu.Unlock()
	})

	if g.dialErr != nil {
		return nil, g.dialErr
	}

	g.mu.Lock()
	client := g.client
	g.mu.Unlock()

	if client == nil {
		return nil, status.Error(codes.Unavailable, "grpc client not initialized")
	}
	return client, nil
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
		switch st.Code() {
		case codes.Unavailable, codes.Unimplemented, codes.DeadlineExceeded:
			return true
		case codes.Internal:
			msg := strings.ToLower(st.Message())
			if strings.Contains(msg, "transport") || strings.Contains(msg, "content-type") || strings.Contains(msg, "http status") {
				return true
			}
		}
	}
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
