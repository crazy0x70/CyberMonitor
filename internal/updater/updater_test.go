package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCanSelfUpdateDisabledForDockerDeployMode(t *testing.T) {
	t.Setenv("CM_DEPLOY_MODE", "docker")

	if CanSelfUpdate() {
		t.Fatal("expected self update to be disabled in docker deploy mode")
	}
	if got := DetectDeployMode(); got != DeployModeDocker {
		t.Fatalf("expected deploy mode %q, got %q", DeployModeDocker, got)
	}
}

func TestCanDockerManagedUpdateEnabledWithSocketAndContainerID(t *testing.T) {
	t.Setenv("CM_DEPLOY_MODE", "docker")
	t.Setenv("CM_CONTAINER_ID", "container-123")
	tmpDir, err := os.MkdirTemp("/tmp", "cm-docker-updater-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()
	t.Setenv("CM_DOCKER_SOCKET", socketPath)

	if !CanDockerManagedUpdate() {
		t.Fatal("expected docker managed update capability when socket is available")
	}
	if got := DetectUpdateMode(); got != "docker-managed" {
		t.Fatalf("expected update mode docker-managed, got %q", got)
	}
}

func TestResolveDockerTargetImageUsesReleaseVersionTag(t *testing.T) {
	t.Parallel()

	got := ResolveDockerTargetImage("ghcr.io/crazy0x70/cyber-monitor-server:latest", "0.3.2")
	if got != "ghcr.io/crazy0x70/cyber-monitor-server:0.3.2" {
		t.Fatalf("unexpected docker target image: %q", got)
	}
}

func TestVerifyChecksumUsesDownloadedAssetName(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "cyber-monitor")
	assetName := "cyber-monitor-server-linux-amd64"
	body := []byte("test-binary")
	if err := os.WriteFile(filePath, body, 0o755); err != nil {
		t.Fatalf("write temp binary: %v", err)
	}

	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksum + "  " + assetName + "\n"))
	}))
	defer server.Close()

	client := NewClient(DefaultRepo, KindServer, "1.0.0")
	if err := client.verifyChecksum(context.Background(), filePath, server.URL, "https://example.com/releases/"+assetName); err != nil {
		t.Fatalf("expected checksum verification to succeed, got %v", err)
	}
}
