package server

import (
	"context"
	"encoding/json"
	"log"
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

func agentUpdateReportConflict() *agentAPIError {
	return &agentAPIError{statusCode: http.StatusConflict, message: "agent update report does not match pending instruction"}
}

// maxAgentNodeIDBytes 限制节点 ID 长度：该值流入持久化键、TSDB label、
// 限流键与日志行，无上限时被控/异常 agent 可缓慢膨胀各存储。在 ingest
// 收口处净化（截断+剔控制字符）而非 history.NormalizeNodeID 拒绝——
// 后者被持久化加载链路复用，收紧会对存量脏 ID 回溯卡死启动。
const maxAgentNodeIDBytes = 128

func cleanAgentNodeID(nodeID string) string {
	nodeID = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(nodeID))
	if len(nodeID) > maxAgentNodeIDBytes {
		nodeID = strings.ToValidUTF8(nodeID[:maxAgentNodeIDBytes], "")
	}
	return nodeID
}

func normalizeAgentNodeID(nodeID string) (string, *agentAPIError) {
	var err error
	nodeID, err = history.NormalizeNodeID(nodeID)
	if err != nil {
		return "", badAgentRequest("invalid node id")
	}
	nodeID = cleanAgentNodeID(nodeID)
	// 剔除控制字符可再造出 "." / ".."（如 "\x01..\x02"）——它们是
	// NormalizeNodeID 显式拒绝的形态，净化后必须复查。
	if nodeID == "" || nodeID == "." || nodeID == ".." {
		return "", badAgentRequest("invalid node id")
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
	// 身份类字符串经同一净化收口：它们播种 profile（Alias/Group）、进入
	// 告警 webhook、WS 广播与日志，控制字符/超长文本不得原样入库。
	payload.NodeName = cleanAgentText(payload.NodeName, 128)
	payload.NodeAlias = cleanAgentText(payload.NodeAlias, 128)
	payload.NodeGroup = cleanAgentText(payload.NodeGroup, 128)
	payload.Hostname = cleanAgentText(payload.Hostname, 253)
	payload.OS = cleanAgentText(payload.OS, 128)
	payload.Arch = cleanAgentText(payload.Arch, 64)
	payload.AgentVersion = cleanAgentText(payload.AgentVersion, 64)
	payload.DeployMode = cleanAgentText(payload.DeployMode, 32)
	payload.PublicIPv4 = cleanAgentText(payload.PublicIPv4, 64)
	payload.PublicIPv6 = cleanAgentText(payload.PublicIPv6, 64)
	payload.CPU.Model = cleanAgentText(payload.CPU.Model, 256)
	for i := range payload.Disk {
		payload.Disk[i].Device = cleanAgentText(payload.Disk[i].Device, 128)
		payload.Disk[i].Mountpoint = cleanAgentText(payload.Disk[i].Mountpoint, 128)
		payload.Disk[i].Fstype = cleanAgentText(payload.Disk[i].Fstype, 64)
	}
	for i := range payload.GPU {
		payload.GPU[i].ID = cleanAgentText(payload.GPU[i].ID, 128)
		payload.GPU[i].Name = cleanAgentText(payload.GPU[i].Name, 256)
		payload.GPU[i].Vendor = cleanAgentText(payload.GPU[i].Vendor, 128)
		payload.GPU[i].DriverVersion = cleanAgentText(payload.GPU[i].DriverVersion, 64)
	}
	if payload.NodeName == "" {
		payload.NodeName = nodeID
	}
	metrics.SanitizeNodeStats(&payload)
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
	// 与下发侧 maxNetworkTestsPerNode（server.go）同一约束，共用常量。
	if len(items) > maxNetworkTestsPerNode {
		items = items[:maxNetworkTestsPerNode]
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

func (a *agentAPI) broadcastNodeDelta(nodeID string) {
	if a.hub == nil {
		return
	}
	// 零观众早退：无人订阅时跳过 NodeView 深拷贝与序列化
	//（无面板常驻部署下每条上报都在做全链路空转）。
	if !a.hub.HasVariant(publicVariantBalanced) && !a.hub.HasVariant(adminVariant) {
		return
	}
	delta, ok := a.store.PublicNodeDelta(nodeID)
	if !ok {
		return
	}
	data, err := json.Marshal(delta)
	if err != nil {
		return
	}
	a.hub.BroadcastAllVariants(data, a.store.Credentials().TokenSalt)
}

func (a *agentAPI) broadcastSnapshot() {
	broadcastStoreSnapshot(a.hub, a.store)
}

func (a *agentAPI) ingest(payload metrics.NodeStats, token string) (bool, *agentAPIError) {
	payload, apiErr := normalizeStatsPayload(payload)
	if apiErr != nil {
		return false, apiErr
	}
	updateReconciled, refreshConfig, recoveryCandidate, apiErr := func() (bool, bool, *offlineRecoveryCandidate, *agentAPIError) {
		unlock := a.store.lockAgentNodeRead(payload.NodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(payload.NodeID, token); apiErr != nil {
			return false, false, nil, apiErr
		}
		if !a.store.allowAgentRate("ingest:"+payload.NodeID, agentIngestWindow, defaultAgentIngestLimit, time.Now(), true) {
			return false, false, nil, agentRateLimitError()
		}
		updateReconciled, recoveryCandidate, err := a.store.updateNodeStats(payload)
		if err != nil {
			// 错误细节（含磁盘路径等）只留服务端日志，不回传给 agent。
			log.Printf("节点 %s 数据写入失败: %v", payload.NodeID, err)
			return false, false, nil, agentServiceUnavailable("节点数据写入失败")
		}
		return updateReconciled, a.store.HasPendingAgentConfigRefresh(payload.NodeID), recoveryCandidate, nil
	}()
	if apiErr != nil {
		return false, apiErr
	}
	if recoveryCandidate != nil {
		a.store.completeOfflineRecovery(*recoveryCandidate)
	}
	a.broadcastNodeDelta(payload.NodeID)
	if updateReconciled {
		a.broadcastSnapshot()
	}
	return refreshConfig, nil
}

func (a *agentAPI) config(nodeID, token string, remoteUpdateCapable bool) (AgentConfig, *agentAPIError) {
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
		// ingest 同款限流：GetConfig 持全局写锁且 lease 变更触发整库
		// persist，异常 agent 循环拉取不得绕过节流。
		if !a.store.allowAgentRate("config:"+nodeID, agentIngestWindow, defaultAgentIngestLimit, time.Now(), false) {
			return AgentConfig{}, false, agentRateLimitError()
		}
		config, leaseUpdated := a.store.DeliverAgentConfig(nodeID, remoteUpdateCapable)
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

func agentRemoteUpdateCapable(capabilities []string) bool {
	for _, capability := range capabilities {
		if strings.TrimSpace(capability) == agentrpc.AgentCapabilityRemoteUpdate {
			return true
		}
	}
	return false
}

func agentRemoteUpdateCapableHeader(header string) bool {
	return agentRemoteUpdateCapable(strings.Split(header, ","))
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
	if _, ok := normalizeAgentUpdateReportState(report.State); !ok {
		return badAgentRequest("invalid agent update state")
	}
	// message 会随 NodeView 对全部 WS 订阅者放大重播并持久化，
	// 与 network test 字段同策略截断，防单个 agent 写入 4MB 文本。
	report.Message = cleanAgentText(report.Message, 240)
	applied, apiErr := func() (bool, *agentAPIError) {
		unlock := a.store.lockAgentNodeRead(nodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(nodeID, token); apiErr != nil {
			return false, apiErr
		}
		_, applied := a.store.applyAgentUpdateReportNodeLocked(nodeID, report)
		return applied, nil
	}()
	if apiErr != nil {
		return apiErr
	}
	if !applied {
		return agentUpdateReportConflict()
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
		// 对齐客户端 keepalive 20s（transport.go ClientParameters.Time）：
		// 默认 EnforcementPolicy MinTime=5min 且禁无流 ping，上报间隔被调大
		// 或休眠恢复时客户端 keepalive 会触发 GOAWAY too_many_pings 断连。
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
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
	// 精确匹配 grpc 媒体类型族：Contains 会把 grpc-web 也路由进
	// grpc.Server（其不支持 grpc-web，只能报错），而非落回 public handler。
	mediaType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = strings.TrimSpace(mediaType[:i])
	}
	return mediaType == "application/grpc" || strings.HasPrefix(mediaType, "application/grpc+")
}

func (s *agentRPCServer) Register(ctx context.Context, req *agentrpc.RegisterRequest) (*agentrpc.RegisterResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
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
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	config, apiErr := s.api.config(req.NodeID, req.AgentToken, agentRemoteUpdateCapable(req.Capabilities))
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
	refreshConfig, apiErr := s.api.ingest(req.Stats, req.AgentToken)
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
		ID:      req.UpdateID,
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
		ID:          update.ID,
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
	case http.StatusConflict:
		return status.Error(codes.FailedPrecondition, err.message)
	case http.StatusTooManyRequests:
		return status.Error(codes.ResourceExhausted, err.message)
	case http.StatusServiceUnavailable:
		// 应用层 503（如 store 写入失败）不能映射为 Unavailable：
		// agent 端会把它当传输故障，关闭健康连接并整包改走 HTTP 重发，
		// 在 store 故障期间引发连接抖动与重复提交。Internal 不触发回退。
		return status.Error(codes.Internal, err.message)
	default:
		return status.Error(codes.Internal, err.message)
	}
}
