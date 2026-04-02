package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestLoginSetsAdminSessionCookie(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "demo123",
		JWTSecret: "jwt-secret",
	})

	body, err := json.Marshal(map[string]string{
		"username": "admin",
		"password": "demo123",
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected login 200, got %d: %s", resp.StatusCode, string(raw))
	}
	sessionCookie := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == adminSessionCookieName {
			sessionCookie = cookie.Value
			if !cookie.HttpOnly {
				t.Fatal("expected admin session cookie to be httpOnly")
			}
			break
		}
	}
	if sessionCookie == "" {
		t.Fatal("expected login response to include admin session cookie")
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode login payload: %v", err)
	}
	if _, exists := payload["token"]; exists {
		t.Fatalf("expected login payload to avoid exposing token, got %+v", payload)
	}
}

func TestAdminSettingsAcceptsCookieSessionWithoutAuthorizationHeader(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "demo123",
		JWTSecret: "jwt-secret",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	loginBody, err := json.Marshal(map[string]string{
		"username": "admin",
		"password": "demo123",
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	loginResp, err := client.Post(baseURL+"/api/v1/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	_ = loginResp.Body.Close()

	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/admin/settings", nil)
	if err != nil {
		t.Fatalf("create settings request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get settings with cookie session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected settings 200 with cookie session, got %d: %s", resp.StatusCode, string(raw))
	}
}

func TestAdminSettingsRejectsBearerTokenInQueryString(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "demo123",
		JWTSecret: "jwt-secret",
	})

	loginBody, err := json.Marshal(map[string]string{
		"username": "admin",
		"password": "demo123",
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/v1/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	defer resp.Body.Close()

	sessionCookie := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == adminSessionCookieName {
			sessionCookie = cookie.Value
			break
		}
	}
	if sessionCookie == "" {
		t.Fatal("expected login response to include admin session cookie")
	}

	queryResp, err := http.Get(baseURL + "/api/v1/admin/settings?token=" + sessionCookie)
	if err != nil {
		t.Fatalf("get settings with query token: %v", err)
	}
	defer queryResp.Body.Close()
	if queryResp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(queryResp.Body)
		t.Fatalf("expected query token auth to be rejected, got %d: %s", queryResp.StatusCode, string(raw))
	}
}

func TestAdminSessionProbeReturnsAuthenticationState(t *testing.T) {
	t.Parallel()

	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		AdminUser: "admin",
		AdminPass: "demo123",
		JWTSecret: "jwt-secret",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	checkSession := func(expected bool) {
		resp, err := client.Get(baseURL + "/api/v1/admin/session")
		if err != nil {
			t.Fatalf("get admin session probe: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected session probe 200, got %d: %s", resp.StatusCode, string(raw))
		}

		var payload struct {
			Authenticated bool `json:"authenticated"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("decode session probe payload: %v", err)
		}
		if payload.Authenticated != expected {
			t.Fatalf("expected authenticated=%v, got %v", expected, payload.Authenticated)
		}
	}

	checkSession(false)

	loginBody, err := json.Marshal(map[string]string{
		"username": "admin",
		"password": "demo123",
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	loginResp, err := client.Post(baseURL+"/api/v1/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	_ = loginResp.Body.Close()

	checkSession(true)
}
