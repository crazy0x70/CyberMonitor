package updater

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r65 审计 U4：downloadFile 的限长预检（os.Create 之前拒超限）、非 200
// 错误体提取、成功写盘。经注入 Transport 直测，零网络。
func TestDownloadFileRejectsOversizeBeforeCreate(t *testing.T) {
	client := &Client{
		Repo: "owner/repo", Kind: KindServer, CurrentVersion: "1.0.0",
		HTTPClient: &http.Client{Transport: redirectRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Status:        "200 OK",
				ContentLength: maxDownloadBytes + 1,
				Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
				Body:          http.NoBody,
				Request:       req,
			}, nil
		})},
	}
	dest := filepath.Join(t.TempDir(), "update-asset")
	if err := client.downloadFile(context.Background(), "https://github.com/owner/repo/releases/download/v1.0.0/asset", dest); err == nil || !strings.Contains(err.Error(), "更新文件过大") {
		t.Fatalf("err=%v, want oversize rejection", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("oversize precheck must run before os.Create, dest exists: %v", err)
	}
}

func TestDownloadFileSurfacesErrorBody(t *testing.T) {
	client := &Client{
		Repo: "owner/repo", Kind: KindServer, CurrentVersion: "1.0.0",
		HTTPClient: &http.Client{Transport: redirectRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 Internal Server Error",
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("upstream boom")),
				Request:    req,
			}, nil
		})},
	}
	dest := filepath.Join(t.TempDir(), "update-asset")
	if err := client.downloadFile(context.Background(), "https://github.com/owner/repo/releases/download/v1.0.0/asset", dest); err == nil || !strings.Contains(err.Error(), "upstream boom") {
		t.Fatalf("err=%v, want error body surfaced", err)
	}
}

func TestDownloadFileWritesBody(t *testing.T) {
	client := &Client{
		Repo: "owner/repo", Kind: KindServer, CurrentVersion: "1.0.0",
		HTTPClient: &http.Client{Transport: redirectRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("payload-bytes")),
				Request:    req,
			}, nil
		})},
	}
	dest := filepath.Join(t.TempDir(), "update-asset")
	if err := client.downloadFile(context.Background(), "https://github.com/owner/repo/releases/download/v1.0.0/asset", dest); err != nil {
		t.Fatalf("err=%v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "payload-bytes" {
		t.Fatalf("dest content: %q err=%v", data, err)
	}
}

// r65 审计 U8：部署模式检测的环境驱动分支。容器探测分支（/.dockerenv）
// 依赖宿主环境，仅断言回退值落在合法枚举内。
func TestDetectDeployModeEnv(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  DeployMode
	}{
		{"docker", DeployModeDocker},
		{"container", DeployModeDocker},
		{"podman", DeployModeDocker},
		{"BINARY", DeployModeBinary},
		{"  binary  ", DeployModeBinary},
	} {
		t.Setenv(deployModeEnvKey, tc.value)
		if got := DetectDeployMode(); got != tc.want {
			t.Errorf("env %q: got %q, want %q", tc.value, got, tc.want)
		}
	}
	t.Setenv(deployModeEnvKey, "garbage-value")
	switch got := DetectDeployMode(); got {
	case DeployModeBinary, DeployModeDocker:
	default:
		t.Errorf("invalid env fallback: got %q, want binary or docker (runtime-probed)", got)
	}
}
