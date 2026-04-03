package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/metrics"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func TestControlPlaneTransportFallsBackToHTTPConfig(t *testing.T) {
	t.Parallel()

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/config" {
			http.NotFound(w, r)
			return
		}
		hits++
		if got := r.URL.Query().Get("node_id"); got != "node-1" {
			t.Fatalf("expected node_id query parameter, got %q", got)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != "node-token" {
			t.Fatalf("expected agent token header, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"alias":             "edge-hk",
			"group":             "Asia",
			"agent_token":       "node-token",
			"test_interval_sec": 5,
			"tests":             []any{},
		})
	}))
	defer server.Close()

	transport := newControlPlaneTransport(Config{ServerURL: server.URL}, server.Client())
	defer transport.Close()

	resp, err := transport.FetchConfig(context.Background(), "node-1", "node-token")
	if err != nil {
		t.Fatalf("fetch config through fallback transport: %v", err)
	}
	if resp.Alias != "edge-hk" {
		t.Fatalf("expected alias edge-hk, got %q", resp.Alias)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP config request after grpc fallback, got %d", hits)
	}
}

type testAgentRPCServer struct {
	agentrpc.AgentServiceServer
	fetchConfig func(context.Context, *agentrpc.ConfigRequest) (*agentrpc.ConfigResponse, error)
}

func (s *testAgentRPCServer) Register(context.Context, *agentrpc.RegisterRequest) (*agentrpc.RegisterResponse, error) {
	return nil, nil
}

func (s *testAgentRPCServer) GetConfig(ctx context.Context, req *agentrpc.ConfigRequest) (*agentrpc.ConfigResponse, error) {
	return s.fetchConfig(ctx, req)
}

func (s *testAgentRPCServer) ReportStats(context.Context, *agentrpc.ReportStatsRequest) (*agentrpc.ReportStatsResponse, error) {
	return nil, nil
}

func (s *testAgentRPCServer) ReportUpdate(context.Context, *agentrpc.ReportUpdateRequest) (*agentrpc.ReportUpdateResponse, error) {
	return nil, nil
}

func TestControlPlaneTransportPrefersGRPCWhenAvailable(t *testing.T) {
	t.Parallel()

	httpHits := 0
	grpcHits := 0
	grpcServer := grpc.NewServer(grpc.ForceServerCodec(agentrpc.GobCodec{}))
	agentrpc.RegisterAgentServiceServer(grpcServer, &testAgentRPCServer{
		fetchConfig: func(_ context.Context, req *agentrpc.ConfigRequest) (*agentrpc.ConfigResponse, error) {
			grpcHits++
			if req.NodeID != "node-1" {
				t.Fatalf("expected grpc node id node-1, got %q", req.NodeID)
			}
			return &agentrpc.ConfigResponse{
				Alias:           "grpc-edge",
				Group:           "Asia",
				AgentToken:      "node-token",
				TestIntervalSec: 5,
				Tests:           []metrics.NetworkTestConfig{},
			}, nil
		},
	})
	defer grpcServer.Stop()

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/api/v1/agent/config", func(w http.ResponseWriter, r *http.Request) {
		httpHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"alias":             "http-edge",
			"group":             "fallback",
			"agent_token":       "node-token",
			"test_interval_sec": 5,
			"tests":             []any{},
		})
	})

	handler := h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && r.Header.Get("Content-Type") != "" {
			grpcServer.ServeHTTP(w, r)
			return
		}
		httpMux.ServeHTTP(w, r)
	}), &http2.Server{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test server: %v", err)
	}
	defer listener.Close()

	srv := &http.Server{Handler: handler}
	defer srv.Close()
	go func() {
		_ = srv.Serve(listener)
	}()

	transport := newControlPlaneTransport(Config{ServerURL: "http://" + listener.Addr().String()}, &http.Client{Timeout: 3 * time.Second})
	defer transport.Close()

	resp, err := transport.FetchConfig(context.Background(), "node-1", "node-token")
	if err != nil {
		t.Fatalf("fetch config through grpc-preferred transport: %v", err)
	}
	if resp.Alias != "grpc-edge" {
		t.Fatalf("expected grpc response alias grpc-edge, got %q", resp.Alias)
	}
	if grpcHits != 1 {
		t.Fatalf("expected one grpc config request, got %d", grpcHits)
	}
	if httpHits != 0 {
		t.Fatalf("expected no HTTP fallback request when grpc is available, got %d", httpHits)
	}
}

func TestControlPlaneTransportFallsBackToHTTPStatsReport(t *testing.T) {
	t.Parallel()

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest" {
			http.NotFound(w, r)
			return
		}
		hits++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != "node-token" {
			t.Fatalf("expected agent token header, got %q", got)
		}
		var payload metrics.NodeStats
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode ingest payload: %v", err)
		}
		if payload.NodeID != "node-1" {
			t.Fatalf("expected node id node-1, got %q", payload.NodeID)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	transport := newControlPlaneTransport(Config{ServerURL: server.URL}, server.Client())
	defer transport.Close()

	err := transport.ReportStats(context.Background(), metrics.NodeStats{
		NodeID:    "node-1",
		NodeName:  "node-1",
		Hostname:  "node-1",
		OS:        "linux",
		Arch:      "amd64",
		Timestamp: time.Now().Unix(),
		CPU:       metrics.CPUInfo{},
		Memory:    metrics.MemInfo{},
		Disk:      []metrics.DiskPartition{},
		DiskIO:    metrics.DiskIO{},
		Network:   metrics.NetworkIO{},
	}, "node-token")
	if err != nil {
		t.Fatalf("report stats through fallback transport: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP ingest request after grpc fallback, got %d", hits)
	}
}

func TestControlPlaneTransportFallsBackToHTTPRegister(t *testing.T) {
	t.Parallel()

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/register" {
			http.NotFound(w, r)
			return
		}
		hits++
		if got := r.URL.Query().Get("node_id"); got != "node-1" {
			t.Fatalf("expected node_id query parameter, got %q", got)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != "bootstrap-token" {
			t.Fatalf("expected bootstrap token header, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_id":     "node-1",
			"agent_token": "node-token-1",
		})
	}))
	defer server.Close()

	transport := newControlPlaneTransport(Config{ServerURL: server.URL}, server.Client())
	defer transport.Close()

	token, err := transport.RegisterNodeToken(context.Background(), "node-1", "bootstrap-token")
	if err != nil {
		t.Fatalf("register through fallback transport: %v", err)
	}
	if token != "node-token-1" {
		t.Fatalf("expected node token node-token-1, got %q", token)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP register request after grpc fallback, got %d", hits)
	}
}

func TestControlPlaneTransportFallsBackToHTTPReportUpdate(t *testing.T) {
	t.Parallel()

	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/update/report" {
			http.NotFound(w, r)
			return
		}
		hits++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != "node-token" {
			t.Fatalf("expected node token header, got %q", got)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode update payload: %v", err)
		}
		if payload["node_id"] != "node-1" {
			t.Fatalf("expected node_id node-1, got %q", payload["node_id"])
		}
		if payload["state"] != "succeeded" {
			t.Fatalf("expected succeeded state, got %q", payload["state"])
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	transport := newControlPlaneTransport(Config{ServerURL: server.URL}, server.Client())
	defer transport.Close()

	if err := transport.ReportUpdate(context.Background(), "node-1", "node-token", "succeeded", "1.1.0", "done"); err != nil {
		t.Fatalf("report update through fallback transport: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP update-report request after grpc fallback, got %d", hits)
	}
}
