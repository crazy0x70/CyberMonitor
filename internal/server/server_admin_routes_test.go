package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

var adminAssetPattern = regexp.MustCompile(`/cm-admin/assets/[^"' ]+`)

func reserveTCPAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	defer listener.Close()

	return listener.Addr().String()
}

func waitForServer(t *testing.T, baseURL string) {
	t.Helper()

	client := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	healthURL := fmt.Sprintf("%s/api/v1/health", baseURL)

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("server did not become ready: %s", healthURL)
}

func startTestServer(t *testing.T, cfg Config) (string, context.CancelFunc) {
	t.Helper()

	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = reserveTCPAddr(t)
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = t.TempDir()
	}
	if strings.TrimSpace(cfg.AdminPath) == "" {
		cfg.AdminPath = "/cm-admin"
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, cfg)
	}()

	baseURL := "http://" + cfg.Addr
	waitForServer(t, baseURL)

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				t.Fatalf("server shutdown failed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("server shutdown timed out")
		}
	})

	return baseURL, cancel
}

func TestAdminRouteServesReactApp(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/cm-admin")
	if err != nil {
		t.Fatalf("get admin route: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read admin body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected admin route 200, got %d: %s", resp.StatusCode, string(body))
	}
	bodyText := string(body)
	if !strings.Contains(bodyText, "<div id=\"root\"></div>") {
		t.Fatalf("expected react root mount, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "CyberMonitor 管理后台") {
		t.Fatalf("expected admin title marker, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "/cm-admin/assets/") {
		t.Fatalf("expected admin asset base path, got: %s", bodyText)
	}

	assetPath := adminAssetPattern.FindString(bodyText)
	if assetPath == "" {
		t.Fatalf("expected admin html to include a hashed asset path, got: %s", bodyText)
	}

	assetResp, err := http.Get(baseURL + assetPath)
	if err != nil {
		t.Fatalf("get admin asset from html: %v", err)
	}
	defer assetResp.Body.Close()

	assetBody, err := io.ReadAll(assetResp.Body)
	if err != nil {
		t.Fatalf("read admin asset from html: %v", err)
	}
	if assetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected admin html asset 200, got %d: %s", assetResp.StatusCode, string(assetBody))
	}
}

func TestAdminPreviewRouteRedirectsToAdmin(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(baseURL + "/cm-admin/preview")
	if err != nil {
		t.Fatalf("get preview route: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected preview route 302, got %d: %s", resp.StatusCode, string(body))
	}
	if location := resp.Header.Get("Location"); location != "/cm-admin" {
		t.Fatalf("expected preview route redirect to /cm-admin, got %q", location)
	}
}

func TestAdminLegacyRouteServesClassicHTML(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/cm-admin/legacy")
	if err != nil {
		t.Fatalf("get legacy route: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read legacy body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected legacy route 200, got %d: %s", resp.StatusCode, string(body))
	}
	bodyText := string(body)
	if !strings.Contains(bodyText, "CyberMonitor 管理后台") {
		t.Fatalf("expected classic admin title marker, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "login-panel") {
		t.Fatalf("expected classic admin login panel marker, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "/assets/styles.css") {
		t.Fatalf("expected classic admin assets, got: %s", bodyText)
	}
}

func TestAdminAssetsRouteServesAdminAssets(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/cm-admin/assets/admin-marker.txt")
	if err != nil {
		t.Fatalf("get admin asset marker: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read asset body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected admin asset marker 200, got %d: %s", resp.StatusCode, string(body))
	}
	if strings.TrimSpace(string(body)) != "CyberMonitor Admin Asset" {
		t.Fatalf("unexpected admin asset marker body: %q", string(body))
	}
}

func TestLegacyAdminAssetsRouteStillServesAdminAssets(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/admin-assets/admin-marker.txt")
	if err != nil {
		t.Fatalf("get legacy admin asset marker: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read legacy asset body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected legacy admin asset marker 200, got %d: %s", resp.StatusCode, string(body))
	}
	if strings.TrimSpace(string(body)) != "CyberMonitor Admin Asset" {
		t.Fatalf("unexpected legacy admin asset marker body: %q", string(body))
	}
}
