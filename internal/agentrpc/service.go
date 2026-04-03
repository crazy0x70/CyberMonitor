package agentrpc

import (
	"context"

	"google.golang.org/grpc"
)

const (
	ServiceName            = "cyber_monitor.agentrpc.AgentService"
	MethodRegister         = "/" + ServiceName + "/Register"
	MethodGetConfig        = "/" + ServiceName + "/GetConfig"
	MethodReportStats      = "/" + ServiceName + "/ReportStats"
	MethodReportUpdate     = "/" + ServiceName + "/ReportUpdate"
)

type AgentServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	GetConfig(context.Context, *ConfigRequest) (*ConfigResponse, error)
	ReportStats(context.Context, *ReportStatsRequest) (*ReportStatsResponse, error)
	ReportUpdate(context.Context, *ReportUpdateRequest) (*ReportUpdateResponse, error)
}

type AgentServiceClient interface {
	Register(context.Context, *RegisterRequest, ...grpc.CallOption) (*RegisterResponse, error)
	GetConfig(context.Context, *ConfigRequest, ...grpc.CallOption) (*ConfigResponse, error)
	ReportStats(context.Context, *ReportStatsRequest, ...grpc.CallOption) (*ReportStatsResponse, error)
	ReportUpdate(context.Context, *ReportUpdateRequest, ...grpc.CallOption) (*ReportUpdateResponse, error)
}

type agentServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAgentServiceClient(cc grpc.ClientConnInterface) AgentServiceClient {
	return &agentServiceClient{cc: cc}
}

func (c *agentServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	if err := c.cc.Invoke(ctx, MethodRegister, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentServiceClient) GetConfig(ctx context.Context, in *ConfigRequest, opts ...grpc.CallOption) (*ConfigResponse, error) {
	out := new(ConfigResponse)
	if err := c.cc.Invoke(ctx, MethodGetConfig, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentServiceClient) ReportStats(ctx context.Context, in *ReportStatsRequest, opts ...grpc.CallOption) (*ReportStatsResponse, error) {
	out := new(ReportStatsResponse)
	if err := c.cc.Invoke(ctx, MethodReportStats, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentServiceClient) ReportUpdate(ctx context.Context, in *ReportUpdateRequest, opts ...grpc.CallOption) (*ReportUpdateResponse, error) {
	out := new(ReportUpdateResponse)
	if err := c.cc.Invoke(ctx, MethodReportUpdate, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func RegisterAgentServiceServer(server grpc.ServiceRegistrar, srv AgentServiceServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*AgentServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Register",
				Handler:    unaryHandler[RegisterRequest, RegisterResponse](srv.Register),
			},
			{
				MethodName: "GetConfig",
				Handler:    unaryHandler[ConfigRequest, ConfigResponse](srv.GetConfig),
			},
			{
				MethodName: "ReportStats",
				Handler:    unaryHandler[ReportStatsRequest, ReportStatsResponse](srv.ReportStats),
			},
			{
				MethodName: "ReportUpdate",
				Handler:    unaryHandler[ReportUpdateRequest, ReportUpdateResponse](srv.ReportUpdate),
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "internal/agentrpc/service.go",
	}, srv)
}

func unaryHandler[Req any, Resp any](handler func(context.Context, *Req) (*Resp, error)) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := new(Req)
		if err := dec(in); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return handler(ctx, in)
		}
		info := &grpc.UnaryServerInfo{
			Server:     srv,
			FullMethod: "",
		}
		wrapped := func(nextCtx context.Context, req any) (any, error) {
			return handler(nextCtx, req.(*Req))
		}
		return interceptor(ctx, in, info, wrapped)
	}
}
