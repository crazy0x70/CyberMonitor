package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

const grpcFallbackBackoff = 30 * time.Second

type agentControlPlane interface {
	RegisterNodeToken(context.Context, string, string) (string, error)
	FetchConfig(context.Context, string, string) (RemoteConfig, error)
	ReportStats(context.Context, metrics.NodeStats, string) error
	ReportUpdate(context.Context, string, string, string, string, string) error
	Close() error
}

type controlPlaneTransport struct {
	http *httpControlPlane
	grpc *grpcControlPlane

	mu              sync.Mutex
	grpcBackoffUntil time.Time
	lastMode        string
}

type httpControlPlane struct {
	client          *http.Client
	configEndpoint  string
	registerEndpoint string
	statsEndpoint   string
	updateEndpoint  string
}

type grpcControlPlane struct {
	target string
	secure bool

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client agentrpc.AgentServiceClient
}

func newControlPlaneTransport(cfg Config, client *http.Client) agentControlPlane {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	return &controlPlaneTransport{
		http: &httpControlPlane{
			client:           client,
			statsEndpoint:    baseURL + "/api/v1/ingest",
			configEndpoint:   baseURL + "/api/v1/agent/config",
			registerEndpoint: baseURL + "/api/v1/agent/register",
			updateEndpoint:   baseURL + "/api/v1/agent/update/report",
		},
		grpc: newGRPCControlPlane(baseURL),
	}
}

func newGRPCControlPlane(serverURL string) *grpcControlPlane {
	target, secure, err := parseGRPCTarget(serverURL)
	if err != nil || target == "" {
		return nil
	}
	return &grpcControlPlane{
		target: target,
		secure: secure,
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
	return target, strings.EqualFold(parsed.Scheme, "https"), nil
}

func (t *controlPlaneTransport) RegisterNodeToken(ctx context.Context, nodeID, bootstrapToken string) (string, error) {
	if t.grpc != nil && t.canUseGRPC() {
		token, err := t.grpc.RegisterNodeToken(ctx, nodeID, bootstrapToken)
		if err == nil {
			t.noteMode("grpc")
			return token, nil
		}
		if !shouldFallbackToHTTP(err) {
			return "", err
		}
		t.disableGRPCTemporarily(err)
	}
	token, err := t.http.RegisterNodeToken(ctx, nodeID, bootstrapToken)
	if err == nil {
		t.noteMode("http")
	}
	return token, err
}

func (t *controlPlaneTransport) FetchConfig(ctx context.Context, nodeID, token string) (RemoteConfig, error) {
	if t.grpc != nil && t.canUseGRPC() {
		config, err := t.grpc.FetchConfig(ctx, nodeID, token)
		if err == nil {
			t.noteMode("grpc")
			return config, nil
		}
		if !shouldFallbackToHTTP(err) {
			return RemoteConfig{}, err
		}
		t.disableGRPCTemporarily(err)
	}
	config, err := t.http.FetchConfig(ctx, nodeID, token)
	if err == nil {
		t.noteMode("http")
	}
	return config, err
}

func (t *controlPlaneTransport) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) error {
	if t.grpc != nil && t.canUseGRPC() {
		err := t.grpc.ReportStats(ctx, stats, token)
		if err == nil {
			t.noteMode("grpc")
			return nil
		}
		if !shouldFallbackToHTTP(err) {
			return err
		}
		t.disableGRPCTemporarily(err)
	}
	if err := t.http.ReportStats(ctx, stats, token); err != nil {
		return err
	}
	t.noteMode("http")
	return nil
}

func (t *controlPlaneTransport) ReportUpdate(ctx context.Context, nodeID, token, state, version, message string) error {
	if t.grpc != nil && t.canUseGRPC() {
		err := t.grpc.ReportUpdate(ctx, nodeID, token, state, version, message)
		if err == nil {
			t.noteMode("grpc")
			return nil
		}
		if !shouldFallbackToHTTP(err) {
			return err
		}
		t.disableGRPCTemporarily(err)
	}
	if err := t.http.ReportUpdate(ctx, nodeID, token, state, version, message); err != nil {
		return err
	}
	t.noteMode("http")
	return nil
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
	t.grpcBackoffUntil = time.Now().Add(grpcFallbackBackoff)
	t.lastMode = "http"
	t.mu.Unlock()
	log.Printf("gRPC 控制链路不可用，已回退 HTTP %s: %v", grpcFallbackBackoff, err)
	if t.grpc != nil {
		_ = t.grpc.Close()
	}
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
	return fetchRemoteConfig(ctx, h.client, h.configEndpoint, nodeID, token)
}

func (h *httpControlPlane) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) error {
	payload, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.statsEndpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-AGENT-TOKEN", token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		text := strings.TrimSpace(string(body))
		if text == "" {
			text = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return fmt.Errorf("ingest failed: %s", text)
	}
	return nil
}

func (h *httpControlPlane) ReportUpdate(ctx context.Context, nodeID, token, state, version, message string) error {
	return postAgentUpdateReport(ctx, h.client, h.updateEndpoint, nodeID, token, state, version, message)
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
		NodeID:     nodeID,
		AgentToken: token,
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

func (g *grpcControlPlane) ReportStats(ctx context.Context, stats metrics.NodeStats, token string) error {
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = client.ReportStats(callCtx, &agentrpc.ReportStatsRequest{
		AgentToken: token,
		Stats:      stats,
	})
	return err
}

func (g *grpcControlPlane) ReportUpdate(ctx context.Context, nodeID, token, state, version, message string) error {
	client, callCtx, cancel, err := g.prepareCall(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = client.ReportUpdate(callCtx, &agentrpc.ReportUpdateRequest{
		NodeID:     nodeID,
		AgentToken: token,
		State:      state,
		Version:    version,
		Message:    message,
	})
	return err
}

func (g *grpcControlPlane) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.conn == nil {
		return nil
	}
	err := g.conn.Close()
	g.conn = nil
	g.client = nil
	return err
}

func (g *grpcControlPlane) prepareCall(ctx context.Context) (agentrpc.AgentServiceClient, context.Context, context.CancelFunc, error) {
	client, err := g.clientConn(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	return client, callCtx, cancel, nil
}

func (g *grpcControlPlane) clientConn(ctx context.Context) (agentrpc.AgentServiceClient, error) {
	g.mu.Lock()
	if g.client != nil {
		client := g.client
		g.mu.Unlock()
		return client, nil
	}
	g.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.ForceCodec(agentrpc.GobCodec{})),
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
			MinConnectTimeout: 4 * time.Second,
		}),
	}
	if g.secure {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.DialContext(dialCtx, g.target, opts...)
	if err != nil {
		return nil, err
	}

	client := agentrpc.NewAgentServiceClient(conn)
	g.mu.Lock()
	if g.conn != nil {
		g.mu.Unlock()
		_ = conn.Close()
		return g.client, nil
	}
	g.conn = conn
	g.client = client
	g.mu.Unlock()
	return client, nil
}

func fromRPCUpdateInstruction(update *agentrpc.UpdateInstruction) *RemoteUpdateInstruction {
	if update == nil {
		return nil
	}
	return &RemoteUpdateInstruction{
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
