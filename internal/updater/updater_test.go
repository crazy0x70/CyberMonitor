package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
