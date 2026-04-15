package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

var adminAssetPattern = regexp.MustCompile(`(?:\./)?assets/[^"' ]+`)

func resolveAdminAssetPath(t *testing.T, assetRef string) string {
	t.Helper()

	trimmed := strings.TrimSpace(assetRef)
	if trimmed == "" {
		t.Fatal("admin asset path is empty")
	}

	return "/cm-admin/" + strings.TrimPrefix(trimmed, "./")
}

func fetchAdminHTML(t *testing.T, baseURL string) string {
	t.Helper()

	resp, err := http.Get(baseURL + "/cm-admin/")
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

	return string(body)
}

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

func TestAdminRouteRedirectsToTrailingSlash(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(baseURL + "/cm-admin")
	if err != nil {
		t.Fatalf("get admin route: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected admin route 302, got %d: %s", resp.StatusCode, string(body))
	}
	if location := resp.Header.Get("Location"); location != "/cm-admin/" {
		t.Fatalf("expected admin route redirect to /cm-admin/, got %q", location)
	}
}

func TestAdminRouteServesReactApp(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
		Version:   "1.2.3",
	})

	bodyText := fetchAdminHTML(t, baseURL)
	if !strings.Contains(bodyText, "<div id=\"root\"></div>") {
		t.Fatalf("expected react root mount, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "CyberMonitor 管理后台") {
		t.Fatalf("expected admin title marker, got: %s", bodyText)
	}
	if !strings.Contains(bodyText, "cm-admin-boot") {
		t.Fatalf("expected admin boot payload, got: %s", bodyText)
	}
	bootMatch := regexp.MustCompile(`name="cm-admin-boot" content="([^"]+)"`).FindStringSubmatch(bodyText)
	if len(bootMatch) != 2 {
		t.Fatalf("expected admin boot meta content, got: %s", bodyText)
	}
	bootPayload, err := base64.StdEncoding.DecodeString(bootMatch[1])
	if err != nil {
		t.Fatalf("decode admin boot payload: %v", err)
	}
	if !strings.Contains(string(bootPayload), "\"version\":\"1.2.3\"") {
		t.Fatalf("expected boot payload to include deployed version, got: %s", string(bootPayload))
	}
	if !strings.Contains(bodyText, "./assets/") {
		t.Fatalf("expected relative admin asset path, got: %s", bodyText)
	}

	assetPath := adminAssetPattern.FindString(bodyText)
	if assetPath == "" {
		t.Fatalf("expected admin html to include a hashed asset path, got: %s", bodyText)
	}

	assetResp, err := http.Get(baseURL + resolveAdminAssetPath(t, assetPath))
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
	if got := assetResp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected admin html asset Cache-Control no-store, got %q", got)
	}
}

func TestAdminAssetsRouteServesAdminAssets(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	bodyText := fetchAdminHTML(t, baseURL)
	assetPath := adminAssetPattern.FindString(bodyText)
	if assetPath == "" {
		t.Fatalf("expected admin html to include a hashed asset path, got: %s", bodyText)
	}

	resp, err := http.Get(baseURL + resolveAdminAssetPath(t, assetPath))
	if err != nil {
		t.Fatalf("get admin asset: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read asset body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected admin asset 200, got %d: %s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected admin assets Cache-Control no-store, got %q", got)
	}
	if len(body) == 0 {
		t.Fatal("expected admin asset body to be non-empty")
	}
}

func TestSplitModePublicAssetsRouteServesPublicAssets(t *testing.T) {
	publicAddr := reserveTCPAddr(t)
	startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		PublicAddr: publicAddr,
		AdminPath:  "/cm-admin",
	})

	resp, err := http.Get("http://" + publicAddr + "/assets/monitor.js")
	if err != nil {
		t.Fatalf("get split public monitor asset: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read split public asset body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected split public monitor asset 200, got %d: %s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected split public assets Cache-Control no-store, got %q", got)
	}
	if !strings.Contains(string(body), "fetchPublicSnapshot") {
		t.Fatalf("expected split public monitor asset to include latest snapshot loader, got: %s", string(body))
	}
}

func TestPublicAssetsRouteDisablesCaching(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	resp, err := http.Get(baseURL + "/assets/monitor.js")
	if err != nil {
		t.Fatalf("get public monitor asset: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected public monitor asset 200, got %d: %s", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected public assets Cache-Control no-store, got %q", got)
	}
}
