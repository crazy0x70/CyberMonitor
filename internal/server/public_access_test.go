package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
)

const testPublicViewCookieName = "cm_public_view"

func TestPublicSnapshotRequiresBootstrapPageAccess(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/api/v1/public/snapshot")
	if err != nil {
		t.Fatalf("get public snapshot without bootstrap: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected public snapshot without bootstrap to return 401, got %d: %s", resp.StatusCode, string(raw))
	}

	client, publicURL := bootstrapPublicPageClient(t, baseURL)
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/public/snapshot", nil)
	if err != nil {
		t.Fatalf("create public snapshot request: %v", err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("get public snapshot after bootstrap: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected public snapshot after bootstrap to return 200, got %d: %s", resp.StatusCode, string(raw))
	}

	cookies := client.Jar.Cookies(publicURL)
	if !hasCookieNamed(cookies, testPublicViewCookieName) {
		t.Fatalf("expected bootstrap page to set %s cookie", testPublicViewCookieName)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode public snapshot payload: %v", err)
	}
	if _, ok := payload["test_history"]; ok {
		t.Fatal("public snapshot should not expose test_history")
	}
	settings, _ := payload["settings"].(map[string]any)
	if settings != nil {
		if _, ok := settings["commit"]; ok {
			t.Fatal("public snapshot should not expose commit metadata")
		}
		if _, ok := settings["version"]; ok {
			t.Fatal("public snapshot should not expose version metadata")
		}
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected public snapshot Cache-Control no-store, got %q", got)
	}
}

func TestSplitModePublicPageServesIndexAndSetsCookie(t *testing.T) {
	publicAddr := reserveTCPAddr(t)
	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		PublicAddr: publicAddr,
		AdminPath:  "/cm-admin",
	})
	_ = baseURL

	publicBaseURL := "http://" + publicAddr
	client, publicURL := bootstrapPublicPageClient(t, publicBaseURL)
	if client == nil {
		t.Fatal("expected public bootstrap client")
	}
	if !hasCookieNamed(client.Jar.Cookies(publicURL), testPublicViewCookieName) {
		t.Fatalf("expected split public page to set %s cookie", testPublicViewCookieName)
	}

	resp, err := client.Get(publicBaseURL + "/config.json")
	if err != nil {
		t.Fatalf("get public config: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected public config Cache-Control no-store, got %q", got)
	}
}

func TestPublicWebSocketRequiresBootstrapPageAccessAndOmitsHistory(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})
	seedPublicHistory(t, baseURL, "bootstrap-token", "node-ws", "1.1.1.1", "ws-history", []int64{1735689600})

	wsURL := websocketURLForBase(t, baseURL) + "/ws"
	dialer := websocket.Dialer{}

	resp, err := dialPublicWebSocket(&dialer, wsURL, nil, baseURL)
	if err == nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal("expected public websocket without bootstrap to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected public websocket without bootstrap to return 401, got resp=%v err=%v", statusCode(resp), err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}

	client, publicURL := bootstrapPublicPageClient(t, baseURL)
	cookies := client.Jar.Cookies(publicURL)
	if !hasCookieNamed(cookies, testPublicViewCookieName) {
		t.Fatalf("expected bootstrap page to set %s cookie", testPublicViewCookieName)
	}

	headers := http.Header{}
	headers.Set("Origin", baseURL)
	for _, cookie := range cookies {
		headers.Add("Cookie", cookie.String())
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("dial public websocket after bootstrap: %v", err)
	}
	defer conn.Close()

	var payload map[string]any
	if err := conn.ReadJSON(&payload); err != nil {
		t.Fatalf("read initial public websocket payload: %v", err)
	}
	if payload["type"] != "snapshot" {
		t.Fatalf("expected initial websocket payload type snapshot, got %#v", payload["type"])
	}
	if _, ok := payload["test_history"]; ok {
		t.Fatal("public websocket snapshot should not expose test_history")
	}
	settings, _ := payload["settings"].(map[string]any)
	if settings != nil {
		if _, ok := settings["commit"]; ok {
			t.Fatal("public websocket snapshot should not expose commit metadata")
		}
		if _, ok := settings["version"]; ok {
			t.Fatal("public websocket snapshot should not expose version metadata")
		}
	}
}

func TestPublicSnapshotRejectsExplicitTokenBypassWithoutCookie(t *testing.T) {
	const jwtSecret = "public-jwt-secret"
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		JWTSecret: jwtSecret,
	})

	token, _, err := generatePublicViewToken(jwtSecret)
	if err != nil {
		t.Fatalf("generate public view token: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/public/snapshot?public_token="+url.QueryEscape(token), nil)
	if err != nil {
		t.Fatalf("create explicit token request: %v", err)
	}
	req.Header.Set("X-CM-Public-Token", token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("perform explicit token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected explicit token bypass to return 401, got %d: %s", resp.StatusCode, string(raw))
	}
}

func bootstrapPublicPageClient(t *testing.T, baseURL string) (*http.Client, *url.URL) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("get public page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected public page 200, got %d: %s", resp.StatusCode, string(raw))
	}

	publicURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse public base url: %v", err)
	}
	return client, publicURL
}

func hasCookieNamed(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name == name && cookie.Value != "" {
			return true
		}
	}
	return false
}

func websocketURLForBase(t *testing.T, baseURL string) string {
	t.Helper()

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse websocket base url: %v", err)
	}
	scheme := "ws"
	if parsed.Scheme == "https" {
		scheme = "wss"
	}
	return scheme + "://" + parsed.Host
}

func dialPublicWebSocket(dialer *websocket.Dialer, wsURL string, header http.Header, origin string) (*http.Response, error) {
	requestHeader := http.Header{}
	for key, values := range header {
		for _, value := range values {
			requestHeader.Add(key, value)
		}
	}
	if origin != "" {
		requestHeader.Set("Origin", origin)
	}
	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if conn != nil {
		_ = conn.Close()
	}
	return resp, err
}

func statusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}
