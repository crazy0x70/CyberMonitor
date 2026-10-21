package server

import (
	"context"
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

const maxAgentNodeIDBytes = 128

// 单次上报允许携带的磁盘/GPU 条数上限，与 maxNetworkTestsPerNode 同一意图：
// 持有任一节点 token 的一方可以提交最大 4MB 的请求体（maxJSONBodySize），
// 若不设上限，可一次写入数万条 disk/GPU 记录，并被写入 store、落盘快照、
// 广播给所有公开 WS 客户端，形成放大式资源消耗。
//
// 取值明显高于真实硬件规模——60 盘位机型、8 卡 GPU 机——
// 因此不会截断正常节点，只在异常/恶意 payload 上生效。
const (
	maxDisksPerNode = 128
	maxGPUsPerNode  = 64
)

// reportUpdate 的限速阈值。reportUpdate 是唯一未接限速的 Agent 入口：每个被接受的
// 升级上报都会触发一次全量快照广播（a.broadcastSnapshot）与一次全量 state.json 落盘
// （applyAgentUpdateReportNodeLocked → persist），而 agentUpdateReportAllowedForCurrentState
// 允许 current=updating → next=updating 重复上报，同一状态可被无限次重放，且升级任务
// 在 1 小时内不收口。持该节点 token 的一方因此可在升级窗口内以任意速率制造全量写盘与
// 全量广播。这里与 ingest/config 一致接入限速，使用 ingest 那张表（useIngestMap=true），
// 以便被 sweepExpiredAgentRateWindows 回收。
//
// 窗口与 ingest 同量级（agentIngestWindow），上限明显放宽到 10：一次升级仅产生
// pending→updating→restarting→done/failed 等少量状态迁移，阈值过紧会丢掉中间态，
// 使服务端任务状态停滞到 1 小时超时才收口——这是本限速的主要风险，故留足余量。
const (
	agentUpdateReportRateWindow = agentIngestWindow
	agentUpdateReportRateLimit  = 10
)

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
	if len(payload.Disk) > maxDisksPerNode {
		log.Printf("节点 %s 上报磁盘条目过多，已截断: %d -> %d", nodeID, len(payload.Disk), maxDisksPerNode)
		payload.Disk = payload.Disk[:maxDisksPerNode]
	}
	for i := range payload.Disk {
		payload.Disk[i].Device = cleanAgentText(payload.Disk[i].Device, 128)
		payload.Disk[i].Mountpoint = cleanAgentText(payload.Disk[i].Mountpoint, 128)
		payload.Disk[i].Fstype = cleanAgentText(payload.Disk[i].Fstype, 64)
	}
	if len(payload.GPU) > maxGPUsPerNode {
		log.Printf("节点 %s 上报 GPU 条目过多，已截断: %d -> %d", nodeID, len(payload.GPU), maxGPUsPerNode)
		payload.GPU = payload.GPU[:maxGPUsPerNode]
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
		// 服务端不信任 agent 侧诊断文案（含内网探测细节与本地化文本），
		// 展示一律由 status 推导；Error 置空防止其进入公开快照。
		item.Error = ""
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
	// 常规 ingest 不再广播 node_delta：每个 tick 的脱敏全量快照是唯一推送渠道，
	// 逐节点 delta 与快照内容重复，白白放大出站流量。
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
		a.store.persistLogged()
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
	report.Message = cleanAgentText(report.Message, 240)
	applied, apiErr := func() (bool, *agentAPIError) {
		unlock := a.store.lockAgentNodeRead(nodeID)
		defer unlock()
		if apiErr := a.validateAgentToken(nodeID, token); apiErr != nil {
			return false, apiErr
		}
		if !a.store.allowAgentRate("update-report:"+nodeID, agentUpdateReportRateWindow, agentUpdateReportRateLimit, time.Now(), true) {
			return false, agentRateLimitError()
		}
		_, applied, persistErr := a.store.applyAgentUpdateReportNodeLocked(nodeID, report)
		if persistErr != nil {
			return false, &agentAPIError{statusCode: http.StatusServiceUnavailable, message: "persist failed, retry later"}
		}
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
	// h2c 的 HTTP/1.1 upgrade 握手会在路由/鉴权之前把整个请求体 io.ReadAll 进内存
	// （x/net/http2/h2c 的 h2cUpgrade），唯一边界只有 ReadTimeout。按 h2c.NewHandler
	// 文档要求，用 http.MaxBytesHandler 包在最外层给这条入口加上界。
	// prior-knowledge 连接（gRPC）由 h2c hijack 后交给 http2 重新解析请求，不经过
	// 这层 MaxBytesReader，gRPC 消息体大小不受该上限约束。
	return http.MaxBytesHandler(h2c.NewHandler(mux, &http2.Server{}), maxPublicRequestBodySize)
}

func isAgentGRPCRequest(r *http.Request) bool {
	if r == nil || r.ProtoMajor != 2 {
		return false
	}
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
		return status.Error(codes.Internal, err.message)
	default:
		return status.Error(codes.Internal, err.message)
	}
}
