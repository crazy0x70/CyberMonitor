package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const maxAgentNetworkTests = 128

type agentAPIError struct {
	statusCode int
	message    string
}

func (e *agentAPIError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

type agentAPI struct {
	store *Store
	hub   *Hub
}

func newAgentAPI(store *Store, hub *Hub) *agentAPI {
	return &agentAPI{store: store, hub: hub}
}

func badAgentRequest(message string) *agentAPIError {
	return &agentAPIError{statusCode: http.StatusBadRequest, message: message}
}

func invalidAgentTokenError() *agentAPIError {
	return &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid agent token"}
}

func invalidBootstrapTokenError() *agentAPIError {
	return &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid bootstrap token"}
}

func agentServiceUnavailable(message string) *agentAPIError {
	return &agentAPIError{statusCode: http.StatusServiceUnavailable, message: message}
}

func normalizeAgentNodeID(nodeID string) (string, *agentAPIError) {
	var err error
	nodeID, err = history.NormalizeNodeID(nodeID)
	if err != nil {
		return "", badAgentRequest("invalid node id")
	}
	if nodeID == "" {
		return "", badAgentRequest("node_id required")
	}
	return nodeID, nil
}

func normalizeStatsPayload(payload metrics.NodeStats) (metrics.NodeStats, *agentAPIError) {
	if payload.NodeID == "" {
		if payload.NodeName != "" {
			payload.NodeID = payload.NodeName
		} else if payload.Hostname != "" {
			payload.NodeID = payload.Hostname
		}
	}
	nodeID, apiErr := normalizeAgentNodeID(payload.NodeID)
	if apiErr != nil {
		return metrics.NodeStats{}, apiErr
	}
	payload.NodeID = nodeID
	if payload.NodeName == "" {
		payload.NodeName = payload.NodeID
	}
	payload.NetworkTests = normalizeAgentNetworkTestResults(payload.NetworkTests)
	return payload, nil
}

func (a *agentAPI) validateAgentToken(nodeID, token string) *agentAPIError {
	if a.store.validateAgentAuthToken(nodeID, token) {
		return nil
	}
	return invalidAgentTokenError()
}

func normalizeAgentNetworkTestResults(items []metrics.NetworkTestResult) []metrics.NetworkTestResult {
	if len(items) == 0 {
		return nil
	}
	if len(items) > maxAgentNetworkTests {
		items = items[:maxAgentNetworkTests]
	}
	normalized := make([]metrics.NetworkTestResult, 0, len(items))
	for _, item := range items {
		name := cleanAgentText(item.Name, 120)
		host := cleanAgentText(item.Host, 253)
		if name == "" && host == "" {
			continue
		}
		if name == "" {
			name = host
		}
		kind := strings.ToLower(strings.TrimSpace(item.Type))
		if kind != "tcp" && kind != "icmp" {
			if item.Port > 0 {
				kind = "tcp"
			} else {
				kind = "icmp"
			}
		}
		port := item.Port
		if kind == "icmp" {
			port = 0
		} else if port < 0 || port > 65535 {
			continue
		}
		statusText := cleanAgentText(strings.ToLower(strings.TrimSpace(item.Status)), 32)
		if statusText != "ok" && statusText != "error" && statusText != "timeout" {
			statusText = "error"
		}
		item.Name = name
		item.Host = host
		item.Type = kind
		item.Port = port
		item.Status = statusText
		item.Error = cleanAgentText(item.Error, 240)
		if item.PacketLoss < 0 {
			item.PacketLoss = 0
		} else if item.PacketLoss > 100 || math.IsNaN(item.PacketLoss) || math.IsInf(item.PacketLoss, 0) {
			item.PacketLoss = 100
		}
		if item.LatencyMs != nil && (math.IsNaN(*item.LatencyMs) || math.IsInf(*item.LatencyMs, 0) || *item.LatencyMs < 0) {
			item.LatencyMs = nil
		}
		normalized = append(normalized, item)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func cleanAgentText(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		switch r {
		case '<', '>', '"', '\'', '`':
			return -1
		case '\r', '\n', '\t':
			return ' '
		default:
			if r < 32 {
				return -1
			}
			return r
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if maxLen > 0 {
		runes := []rune(value)
		if len(runes) > maxLen {
			value = string(runes[:maxLen])
		}
	}
	return strings.TrimSpace(value)
}

func agentRateLimitError() *agentAPIError {
	return &agentAPIError{statusCode: http.StatusTooManyRequests, message: "rate limit exceeded"}
}

func (a *agentAPI) broadcastPublicDelta(nodeID string) {
	if a.hub == nil {
		return
	}
	if delta, ok := a.store.PublicNodeDelta(nodeID); ok {
		if data, err := json.Marshal(delta); err == nil {
			a.hub.BroadcastVariant(data, publicVariantBalanced)
		}
	}
}

func (a *agentAPI) broadcastSnapshot() {
	broadcastStoreSnapshot(a.hub, a.store, false)
}

func (a *agentAPI) ingest(remoteAddr string, payload metrics.NodeStats, token string) (bool, *agentAPIError) {
	payload, apiErr := normalizeStatsPayload(payload)
	if apiErr != nil {
		return false, apiErr
	}
	updateReconciled, refreshConfig, apiErr := func() (bool, bool, *agentAPIError) {
		unlock := a.store.lockAgentNodeRead(payload.NodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(payload.NodeID, token); apiErr != nil {
			return false, false, apiErr
		}
		if !a.store.allowAgentRate("ingest:"+payload.NodeID, agentIngestWindow, defaultAgentIngestLimit, time.Now(), true) {
			return false, false, agentRateLimitError()
		}
		updateReconciled, err := a.store.updateNodeStats(payload)
		if err != nil {
			return false, false, agentServiceUnavailable(err.Error())
		}
		return updateReconciled, a.store.HasPendingAgentConfigRefresh(payload.NodeID), nil
	}()
	if apiErr != nil {
		return false, apiErr
	}
	a.broadcastPublicDelta(payload.NodeID)
	if updateReconciled {
		a.broadcastSnapshot()
	}
	if strings.TrimSpace(remoteAddr) == "" {
		remoteAddr = "grpc"
	}
	return refreshConfig, nil
}

func (a *agentAPI) config(nodeID, token string) (AgentConfig, *agentAPIError) {
	nodeID, apiErr := normalizeAgentNodeID(nodeID)
	if apiErr != nil {
		return AgentConfig{}, apiErr
	}
	config, leaseUpdated, apiErr := func() (AgentConfig, bool, *agentAPIError) {
		unlock := a.store.lockAgentNodeRead(nodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(nodeID, token); apiErr != nil {
			return AgentConfig{}, false, apiErr
		}
		config, leaseUpdated := a.store.DeliverAgentConfig(nodeID)
		return config, leaseUpdated, nil
	}()
	if apiErr != nil {
		return AgentConfig{}, apiErr
	}
	if leaseUpdated {
		a.store.persist()
	}
	return config, nil
}

func (a *agentAPI) register(nodeID, bootstrapToken string) (string, *agentAPIError) {
	nodeID, apiErr := normalizeAgentNodeID(nodeID)
	if apiErr != nil {
		return "", apiErr
	}
	unlock := a.store.lockAgentNodeRead(nodeID)
	defer unlock()
	return a.store.registerAgentAuthToken(nodeID, bootstrapToken, time.Now())
}

func (a *agentAPI) reportUpdate(nodeID, token string, report AgentUpdateReport) *agentAPIError {
	nodeID, apiErr := normalizeAgentNodeID(nodeID)
	if apiErr != nil {
		return apiErr
	}
	if apiErr := func() *agentAPIError {
		unlock := a.store.lockAgentNodeRead(nodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(nodeID, token); apiErr != nil {
			return apiErr
		}
		a.store.applyAgentUpdateReportNodeLocked(nodeID, report)
		return nil
	}(); apiErr != nil {
		return apiErr
	}
	a.broadcastSnapshot()
	return nil
}

type agentRPCServer struct {
	agentrpc.AgentServiceServer
	api *agentAPI
}

func newAgentRPCServer(api *agentAPI) *grpc.Server {
	codec := agentrpc.GobCodec{}
	server := grpc.NewServer(
		grpc.ForceServerCodec(codec),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	agentrpc.RegisterAgentServiceServer(server, &agentRPCServer{api: api})
	return server
}

func wrapPublicHandler(httpHandler http.Handler, grpcServer *grpc.Server) http.Handler {
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAgentGRPCRequest(r) {
			grpcServer.ServeHTTP(w, r)
			return
		}
		httpHandler.ServeHTTP(w, r)
	})
	return h2c.NewHandler(mux, &http2.Server{})
}

func isAgentGRPCRequest(r *http.Request) bool {
	if r == nil || r.ProtoMajor != 2 {
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "application/grpc")
}

func (s *agentRPCServer) Register(ctx context.Context, req *agentrpc.RegisterRequest) (*agentrpc.RegisterResponse, error) {
	agentToken, apiErr := s.api.register(req.NodeID, req.BootstrapToken)
	if apiErr != nil {
		return nil, grpcStatusFromAPIError(apiErr)
	}
	return &agentrpc.RegisterResponse{
		NodeID:     strings.TrimSpace(req.NodeID),
		AgentToken: agentToken,
	}, nil
}

func (s *agentRPCServer) GetConfig(ctx context.Context, req *agentrpc.ConfigRequest) (*agentrpc.ConfigResponse, error) {
	config, apiErr := s.api.config(req.NodeID, req.AgentToken)
	if apiErr != nil {
		return nil, grpcStatusFromAPIError(apiErr)
	}
	return &agentrpc.ConfigResponse{
		Alias:           config.Alias,
		Group:           config.Group,
		AgentToken:      config.AgentToken,
		Tests:           config.Tests,
		TestIntervalSec: config.TestIntervalSec,
		Update:          toRPCUpdateInstruction(config.Update),
	}, nil
}

func (s *agentRPCServer) ReportStats(ctx context.Context, req *agentrpc.ReportStatsRequest) (*agentrpc.ReportStatsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	refreshConfig, apiErr := s.api.ingest(remoteAddrFromContext(ctx), req.Stats, req.AgentToken)
	if apiErr != nil {
		return nil, grpcStatusFromAPIError(apiErr)
	}
	return &agentrpc.ReportStatsResponse{Status: "ok", RefreshConfig: refreshConfig}, nil
}

func (s *agentRPCServer) ReportUpdate(ctx context.Context, req *agentrpc.ReportUpdateRequest) (*agentrpc.ReportUpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	apiErr := s.api.reportUpdate(req.NodeID, req.AgentToken, AgentUpdateReport{
		State:   req.State,
		Version: req.Version,
		Message: req.Message,
	})
	if apiErr != nil {
		return nil, grpcStatusFromAPIError(apiErr)
	}
	return &agentrpc.ReportUpdateResponse{Status: "ok"}, nil
}

func toRPCUpdateInstruction(update *AgentUpdateInstruction) *agentrpc.UpdateInstruction {
	if update == nil {
		return nil
	}
	return &agentrpc.UpdateInstruction{
		Version:     update.Version,
		DownloadURL: update.DownloadURL,
		ChecksumURL: update.ChecksumURL,
		RequestedAt: update.RequestedAt,
	}
}

func grpcStatusFromAPIError(err *agentAPIError) error {
	if err == nil {
		return nil
	}
	switch err.statusCode {
	case http.StatusBadRequest:
		return status.Error(codes.InvalidArgument, err.message)
	case http.StatusUnauthorized:
		return status.Error(codes.Unauthenticated, err.message)
	case http.StatusNotFound:
		return status.Error(codes.NotFound, err.message)
	case http.StatusTooManyRequests:
		return status.Error(codes.ResourceExhausted, err.message)
	case http.StatusServiceUnavailable:
		return status.Error(codes.Unavailable, err.message)
	default:
		return status.Error(codes.Internal, err.message)
	}
}

func remoteAddrFromContext(ctx context.Context) string {
	peerInfo, ok := grpcpeer.FromContext(ctx)
	if !ok || peerInfo.Addr == nil {
		return "grpc"
	}
	return peerInfo.Addr.String()
}
