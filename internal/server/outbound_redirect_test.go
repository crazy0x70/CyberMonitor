package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// redirectTransport 拦截全部出站请求（零网络）：首个请求返回 3xx +
// Location，其余请求返回 200；记录每个请求的 URL 与 Referer 供断言。
type redirectTransport struct {
	status int

	mu       sync.Mutex
	requests []redirectTransportRecord
}

type redirectTransportRecord struct {
	url     string
	referer string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, redirectTransportRecord{
		url:     req.URL.String(),
		referer: req.Header.Get("Referer"),
	})
	first := len(t.requests) == 1
	t.mu.Unlock()

	if first {
		return &http.Response{
			StatusCode: t.status,
			Status:     fmt.Sprintf("%d Redirected", t.status),
			Header:     http.Header{"Location": []string{"https://redirect-target.test/next"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
		Request:    req,
	}, nil
}

func (t *redirectTransport) requestCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

func (t *redirectTransport) refererAt(i int) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i < 0 || i >= len(t.requests) {
		return ""
	}
	return t.requests[i].referer
}

// TestNoRedirectHTTPClientReturnsRedirectUntouched：凭据类出站 client 对
// 301/302/307/308 一律原样返回首个响应且只发出一次请求（不跟随）。
func TestNoRedirectHTTPClientReturnsRedirectUntouched(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		rt := &redirectTransport{status: status}
		client := noRedirectHTTPClient(time.Second)
		client.Transport = rt
		resp, err := client.Get("https://api.example.test/v1/method")
		if err != nil {
			t.Fatalf("status %d: unexpected error: %v", status, err)
		}
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Errorf("status %d: got %d, want original 3xx returned untouched", status, resp.StatusCode)
		}
		if got := rt.requestCount(); got != 1 {
			t.Errorf("status %d: got %d outbound requests, want exactly 1 (redirect must not be followed)", status, got)
		}
	}
}

// TestTelegramBotAPICallDoesNotFollowRedirect：真实入口在 3xx 下返回错误
// 且只发出一次请求（token 位于 URL path，不得被带往重定向目标）。
func TestTelegramBotAPICallDoesNotFollowRedirect(t *testing.T) {
	rt := &redirectTransport{status: http.StatusFound}
	client := noRedirectHTTPClient(time.Second)
	client.Transport = rt
	_, err := telegramBotAPICall(context.Background(), client,
		"123456:ABCdefGhIJKlmNoPQRstUVwxy", "sendMessage",
		map[string]interface{}{"chat_id": 1, "text": "hi"}, "测试")
	if err == nil {
		t.Fatal("expected error for 3xx response, got nil")
	}
	if got := rt.requestCount(); got != 1 {
		t.Errorf("got %d outbound requests, want exactly 1", got)
	}
}

// TestAdminOAuthContextClientDoesNotFollowRedirect：OAuth 上下文注入的
// client 不跟随重定向（Exchange/identity 的 secret 与 Bearer 不外泄）。
func TestAdminOAuthContextClientDoesNotFollowRedirect(t *testing.T) {
	rt := &redirectTransport{status: http.StatusFound}
	ctx := adminOAuthContext(context.Background())
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		t.Fatalf("context does not carry *http.Client")
	}
	client.Transport = rt
	resp, err := client.Get("https://idp.example.test/oauth/token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("got %d, want 302 returned untouched", resp.StatusCode)
	}
	if got := rt.requestCount(); got != 1 {
		t.Errorf("got %d outbound requests, want exactly 1", got)
	}
}

// TestOIDCDiscoveryRejectsRedirect：经 adminOAuthContext 驱动真实 go-oidc
// discovery——302 端点必须报错（修复前会跟随到目标端点并成功）；对照
// 组证明直连 200 端点在本测试链路下可正常完成 discovery。
func TestOIDCDiscoveryRejectsRedirect(t *testing.T) {
	var issuerURL string
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuerURL})
	}))
	defer final.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/.well-known/openid-configuration", http.StatusFound)
	}))
	defer redirector.Close()

	issuerURL = final.URL
	if _, err := oidc.NewProvider(adminOAuthContext(context.Background()), final.URL); err != nil {
		t.Fatalf("direct discovery should succeed: %v", err)
	}

	issuerURL = redirector.URL
	if _, err := oidc.NewProvider(adminOAuthContext(context.Background()), redirector.URL); err == nil {
		t.Fatal("discovery must not follow redirects")
	}
}

// TestWebhookRedirectPolicyStripsReferer：策略必须摘除 stdlib 在回调前
// 写入的 Referer（webhook secret 在 path 中），并保留跳数上限与私网目标
// 拒绝两个既有行为。
func TestWebhookRedirectPolicyStripsReferer(t *testing.T) {
	first, _ := http.NewRequest(http.MethodPost, "https://hook.example/open-apis/bot/v2/hook/secret-token", nil)
	next, _ := http.NewRequest(http.MethodPost, "https://hook.example/redirected", nil)
	next.Header.Set("Referer", "https://hook.example/open-apis/bot/v2/hook/secret-token")
	if err := webhookRedirectPolicy(next, []*http.Request{first}); err != nil {
		t.Fatalf("valid redirect target rejected: %v", err)
	}
	if got := next.Header.Get("Referer"); got != "" {
		t.Errorf("Referer leaked to redirect target: %q", got)
	}

	if err := webhookRedirectPolicy(next, make([]*http.Request, 10)); err == nil {
		t.Error("expected redirect limit error for 10 prior requests")
	}

	bad, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/x", nil)
	if err := webhookRedirectPolicy(bad, []*http.Request{first}); err == nil {
		t.Error("expected private redirect target to be rejected")
	}
}

// TestWebhookClientRedirectRefererMechanism：经真实 net/http 重定向机制
// 验证——stdlib 把上一跳完整 URL（含 path secret）写入 Referer 后，由
// 策略在出站前摘除；跟随本身保留（r50 逐跳校验设计）。
func TestWebhookClientRedirectRefererMechanism(t *testing.T) {
	rt := &redirectTransport{status: http.StatusFound}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: webhookRedirectPolicy}
	client.Transport = rt
	resp, err := client.Post("https://hook.example/open-apis/bot/v2/hook/secret-token",
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want final 200 after followed redirect", resp.StatusCode)
	}
	if got := rt.requestCount(); got != 2 {
		t.Fatalf("got %d outbound requests, want 2 (redirect followed)", got)
	}
	if ref := rt.refererAt(1); ref != "" {
		t.Errorf("second hop carried Referer %q, want empty", ref)
	}
	if ref := rt.refererAt(0); ref != "" {
		t.Errorf("first hop unexpectedly carried Referer %q", ref)
	}

	// 阴性对照：同一机制下不装策略的 client，stdlib 会在第二跳携带
	// 含 path secret 的 Referer——证明上述断言的前提成立，防止 stdlib
	// 行为变化后测试空转。
	ctrl := &redirectTransport{status: http.StatusFound}
	ctrlClient := &http.Client{Timeout: 5 * time.Second}
	ctrlClient.Transport = ctrl
	ctrlResp, err := ctrlClient.Post("https://hook.example/open-apis/bot/v2/hook/secret-token",
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("negative control: unexpected error: %v", err)
	}
	ctrlResp.Body.Close()
	if got := ctrl.requestCount(); got != 2 {
		t.Fatalf("negative control: got %d outbound requests, want 2", got)
	}
	if ref := ctrl.refererAt(1); !strings.Contains(ref, "hook/secret-token") {
		t.Errorf("negative control: expected stdlib to set Referer carrying path secret, got %q", ref)
	}
}

// TestVerifyTurnstileTokenRejectsRedirect：Turnstile 校验在 3xx 下报错且
// 只发出一次请求（secret 在 form body，307/308 不得被重放）。
func TestVerifyTurnstileTokenRejectsRedirect(t *testing.T) {
	orig := turnstileHTTPClient
	defer func() { turnstileHTTPClient = orig }()
	client := noRedirectHTTPClient(time.Second)
	client.Transport = &redirectTransport{status: http.StatusFound}
	turnstileHTTPClient = client

	err := verifyTurnstileToken(context.Background(), "secret-key-value", "tok", "")
	if err == nil {
		t.Fatal("expected error for 3xx response, got nil")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Errorf("error should mention response status, got: %v", err)
	}
}
