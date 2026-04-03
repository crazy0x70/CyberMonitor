package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

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
	cfg   *Config
}

type legacyAgentConfigResponse struct {
	Alias           string                      `json:"alias"`
	Group           string                      `json:"group"`
	Tests           []metrics.NetworkTestConfig `json:"tests"`
	TestIntervalSec int                         `json:"test_interval_sec"`
}

func newAgentAPI(store *Store, hub *Hub, cfg *Config) *agentAPI {
	return &agentAPI{store: store, hub: hub, cfg: cfg}
}

func (a *agentAPI) ingest(remoteAddr string, payload metrics.NodeStats, token string) *agentAPIError {
	if payload.NodeID == "" {
		if payload.NodeName != "" {
			payload.NodeID = payload.NodeName
		} else if payload.Hostname != "" {
			payload.NodeID = payload.Hostname
		}
	}
	if payload.NodeID == "" {
		return &agentAPIError{statusCode: http.StatusBadRequest, message: "node_id required"}
	}
	if payload.NodeName == "" {
		payload.NodeName = payload.NodeID
	}
	if !a.store.validateOrProvisionAgentAuthToken(payload.NodeID, token, a.cfg.AgentToken) {
		return &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid agent token"}
	}
	a.store.Update(payload)
	if delta, ok := a.store.PublicNodeDelta(payload.NodeID); ok {
		if data, err := json.Marshal(delta); err == nil {
			a.hub.BroadcastVariant(data, publicVariantBalanced)
		}
	}
	if strings.TrimSpace(remoteAddr) == "" {
		remoteAddr = "grpc"
	}
	reportLogger.Printf("Agent 上报: %s (%s)", payload.NodeID, remoteAddr)
	return nil
}

func (a *agentAPI) config(nodeID, token string) (AgentConfig, *agentAPIError) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return AgentConfig{}, &agentAPIError{statusCode: http.StatusBadRequest, message: "node_id required"}
	}
	if !a.store.validateOrProvisionAgentAuthToken(nodeID, token, a.cfg.AgentToken) {
		return AgentConfig{}, &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid agent token"}
	}
	return a.store.AgentConfig(nodeID), nil
}

func (a *agentAPI) register(nodeID, bootstrapToken string) (string, *agentAPIError) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", &agentAPIError{statusCode: http.StatusBadRequest, message: "node_id required"}
	}
	if strings.TrimSpace(a.cfg.AgentToken) != "" && strings.TrimSpace(bootstrapToken) != strings.TrimSpace(a.cfg.AgentToken) {
		return "", &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid bootstrap token"}
	}
	return a.store.ensureAgentAuthToken(nodeID), nil
}

func (a *agentAPI) reportUpdate(nodeID, token string, report AgentUpdateReport) *agentAPIError {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return &agentAPIError{statusCode: http.StatusBadRequest, message: "node_id required"}
	}
	if !a.store.validateOrProvisionAgentAuthToken(nodeID, token, a.cfg.AgentToken) {
		return &agentAPIError{statusCode: http.StatusUnauthorized, message: "invalid agent token"}
	}
	a.store.ApplyAgentUpdateReport(nodeID, report)
	snapshot := storeSnapshot(a.store, false)
	payload, _ := json.Marshal(snapshot)
	a.hub.Broadcast(payload)
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
	if apiErr := s.api.ingest(remoteAddrFromContext(ctx), req.Stats, req.AgentToken); apiErr != nil {
		return nil, grpcStatusFromAPIError(apiErr)
	}
	return &agentrpc.ReportStatsResponse{Status: "ok"}, nil
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

func httpAgentConfigResponse(config AgentConfig, capabilities string) any {
	if supportsAgentConfigExtension(capabilities, agentrpc.AgentCapabilityDedicatedToken) || supportsAgentConfigExtension(capabilities, agentrpc.AgentCapabilityRemoteUpdate) {
		return config
	}
	return legacyAgentConfigResponse{
		Alias:           config.Alias,
		Group:           config.Group,
		Tests:           config.Tests,
		TestIntervalSec: config.TestIntervalSec,
	}
}

func supportsAgentConfigExtension(capabilities, capability string) bool {
	capability = strings.TrimSpace(strings.ToLower(capability))
	if capability == "" {
		return false
	}
	for _, item := range strings.Split(capabilities, ",") {
		if strings.TrimSpace(strings.ToLower(item)) == capability {
			return true
		}
	}
	return false
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
