package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestPerformAgentRequestStopsRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, sameOrigin := range []bool{true, false} {
				t.Run(fmt.Sprintf("%d/%s/sameOrigin=%t", status, method, sameOrigin), func(t *testing.T) {
					var targetHits, policyCalls atomic.Int32
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						targetHits.Add(1)
						_, _ = io.WriteString(w, `{}`)
					}))
					defer target.Close()
					source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/target" {
							targetHits.Add(1)
							return
						}
						if got := r.Header.Get("X-AGENT-TOKEN"); got != "secret-token" {
							t.Errorf("source token = %q", got)
						}
						location := target.URL
						if sameOrigin {
							location = "/target"
						}
						w.Header().Set("Location", location)
						w.WriteHeader(status)
						_, _ = io.WriteString(w, `{"error":"redirect blocked"}`)
					}))
					defer source.Close()
					jar := &redirectTestJar{}
					client := source.Client()
					client.Jar = jar
					client.Timeout = 3 * time.Second
					transport := client.Transport
					client.CheckRedirect = func(*http.Request, []*http.Request) error { policyCalls.Add(1); return nil }
					req, err := http.NewRequest(method, source.URL, strings.NewReader(`{"token":"body-secret"}`))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("X-AGENT-TOKEN", "secret-token")
					decoded := false
					err = performAgentRequest(client, req, "config", func(io.Reader) error { decoded = true; return nil })
					var statusErr *agentAPIStatusError
					if !errors.As(err, &statusErr) {
						t.Fatalf("expected status error, got %v", err)
					}
					if statusErr.statusCode != status || statusErr.operation != "config" || statusErr.message != "redirect blocked" {
						t.Fatalf("unexpected status error: %#v", statusErr)
					}
					if decoded {
						t.Error("decoder called for redirect")
					}
					if targetHits.Load() != 0 {
						t.Errorf("redirect target received %d requests", targetHits.Load())
					}
					if policyCalls.Load() != 0 {
						t.Error("caller redirect policy invoked")
					}
					if client.Transport != transport || client.Jar != jar || client.Timeout != 3*time.Second {
						t.Error("caller client configuration changed")
					}
					if client.CheckRedirect == nil {
						t.Fatal("caller redirect policy removed")
					}
					if err := client.CheckRedirect(nil, nil); err != nil || policyCalls.Load() != 1 {
						t.Error("caller redirect policy replaced")
					}
				})
			}
		}
	}
}

func TestPerformAgentRequestDecodesSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"alias":"node"}`)
	}))
	defer server.Close()
	for _, decodeBody := range []bool{true, false} {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		var decode func(io.Reader) error
		if decodeBody {
			decode = func(body io.Reader) error {
				data, err := io.ReadAll(body)
				if err != nil {
					return err
				}
				if string(data) != `{"alias":"node"}` {
					t.Errorf("unexpected response: %s", data)
				}
				return nil
			}
		}
		if err := performAgentRequest(server.Client(), req, "config", decode); err != nil {
			t.Fatal(err)
		}
	}
}

// Keep the caller jar attached without relying on a concrete cookie store.
type redirectTestJar struct{}

func (*redirectTestJar) SetCookies(*url.URL, []*http.Cookie) {}
func (*redirectTestJar) Cookies(*url.URL) []*http.Cookie     { return nil }

func TestAgentHTTPEntrypointsStopRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, operation := range []string{"register", "config", "ingest", "update report"} {
			t.Run(fmt.Sprintf("%d/%s", status, operation), func(t *testing.T) {
				var hits atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/target" {
						hits.Add(1)
						_, _ = io.WriteString(w, `{}`)
						return
					}
					w.Header().Set("Location", "/target")
					w.WriteHeader(status)
				}))
				defer server.Close()
				h := &httpControlPlane{client: server.Client(), registerEndpoint: server.URL, configEndpoint: server.URL, statsEndpoint: server.URL, updateEndpoint: server.URL}
				var err error
				switch operation {
				case "register":
					_, err = h.RegisterNodeToken(context.Background(), "node", "secret")
				case "config":
					_, err = h.FetchConfig(context.Background(), "node", "secret")
				case "ingest":
					_, err = h.ReportStats(context.Background(), metrics.NodeStats{}, "secret")
				case "update report":
					err = h.ReportUpdate(context.Background(), "node", "secret", "update", "failed", "v1", "message")
				}
				var statusErr *agentAPIStatusError
				if !errors.As(err, &statusErr) {
					t.Fatalf("expected typed status error, got %v", err)
				}
				if statusErr.statusCode != status || statusErr.operation != operation {
					t.Fatalf("unexpected status error: %#v", statusErr)
				}
				if hits.Load() != 0 {
					t.Errorf("target received %d requests", hits.Load())
				}
			})
		}
	}
}

func TestAgentHTTPEntrypointsDirectSuccess(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-AGENT-TOKEN") != "fixture-token" {
			t.Errorf("missing source credential at %s", r.URL.Path)
		}
		wantMethod := http.MethodPost
		if r.URL.Path == "/config" {
			wantMethod = http.MethodGet
		}
		if r.Method != wantMethod {
			t.Errorf("method = %s; want %s", r.Method, wantMethod)
		}
		switch r.URL.Path {
		case "/register", "/config":
			if r.URL.Query().Get("node_id") != "fixture-node" {
				t.Error("missing node query")
			}
			_, _ = io.WriteString(w, `{"node_id":"fixture-node","agent_token":"issued-token","alias":"fixture-alias","test_interval_sec":15}`)
		case "/ingest":
			_, _ = io.WriteString(w, `{"status":"ok","refresh_config":true}`)
		case "/update":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("update body: %v", err)
			}
			if body["node_id"] != "fixture-node" || body["update_id"] != "fixture-update" || body["state"] != "failed" || body["message"] != "fixture-message" {
				t.Errorf("update body = %#v", body)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	h := &httpControlPlane{client: server.Client(), registerEndpoint: server.URL + "/register", configEndpoint: server.URL + "/config", statsEndpoint: server.URL + "/ingest", updateEndpoint: server.URL + "/update"}
	ctx := context.Background()
	token, err := h.RegisterNodeToken(ctx, "fixture-node", "fixture-token")
	if err != nil || token != "issued-token" {
		t.Fatalf("register = %q, %v", token, err)
	}
	cfg, err := h.FetchConfig(ctx, "fixture-node", "fixture-token")
	if err != nil || cfg.Alias != "fixture-alias" || cfg.AgentToken != "issued-token" || cfg.TestIntervalSec != 15 {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	refresh, err := h.ReportStats(ctx, metrics.NodeStats{}, "fixture-token")
	if err != nil || !refresh {
		t.Fatalf("ingest refresh = %v, %v", refresh, err)
	}
	if err := h.ReportUpdate(ctx, "fixture-node", "fixture-token", "fixture-update", "failed", "v1", "fixture-message"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("source calls = %d; want 4", calls.Load())
	}
}
