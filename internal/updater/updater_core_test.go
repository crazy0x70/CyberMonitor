package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// r37 以来版本比较族承载自更新门禁（dev 构建不自动替换、预发布优先级），
// 此前零覆盖。
func TestVersionComparisonFamily(t *testing.T) {
	updateCases := []struct {
		current, latest string
		want            bool
	}{
		{"1.2.3", "1.2.4", true},
		{"1.2.4", "1.2.3", false},
		{"v1.0.0", "1.0.0", false},
		{"1.0.0", "", false},
		{"1.0.0", "latest", false},
		{"dev", "1.0.0", false},
		{"1.0.0", "1.0", false},
		{"1.0.0", "1", false},
		{"1.0.0", "1.2", true},
		{"1.0.0", "01.2.3", true},
		{"1.0.0", "1.2.3.4", false},
		{"1.0.0+build", "1.0.1", true},
		{"1.0.0-alpha", "1.0.0", true},
		{"1.0.0", "1.0.0-rc.1", false},
		{"1.0.0-rc.1", "1.0.0", true},
		{"1.0.0-alpha", "1.0.0-alpha.1", true},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", true},
		{"1.0.0-beta.2", "1.0.0-beta.11", true},
		{"1.0.0-2", "1.0.0-10", true},
	}
	for _, tc := range updateCases {
		if got := HasVersionUpdate(tc.current, tc.latest); got != tc.want {
			t.Errorf("HasVersionUpdate(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}

	orNewer := []struct {
		current, latest string
		want            bool
	}{
		{"1.2.4", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"1.0.0", "v1.0.0", true},
		{"dev", "1.0.0", false},
		{"", "1.0.0", false},
	}
	for _, tc := range orNewer {
		if got := VersionCurrentOrNewer(tc.current, tc.latest); got != tc.want {
			t.Errorf("VersionCurrentOrNewer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}

	equal := []struct {
		current, latest string
		want            bool
	}{
		{"1.0.0", "v1.0.0", true},
		{"1.0.0+meta", "1.0.0", true},
		{"1.0.0", "1.0.1", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
	}
	for _, tc := range equal {
		if got := VersionsEqual(tc.current, tc.latest); got != tc.want {
			t.Errorf("VersionsEqual(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}

	valid := []struct {
		version string
		want    bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},
		{"1.2", true},
		{"1.2.3-rc.1", true},
		{"1.2.3+build.5", true},
		{"01.2.3", true},
		{"1..3", false},
		{"1.2.3.4", false},
		{"1.2.3-", false},
		{"1.2.3-rc.01", false},
		{"+5", false},
		{"", false},
	}
	for _, tc := range valid {
		if got := ValidReleaseVersion(tc.version); got != tc.want {
			t.Errorf("ValidReleaseVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestLookupChecksumAndResolveName(t *testing.T) {
	contents := "aaa  one\nignored-single\nbbb  two\nccc\tthree\n"
	if got, err := lookupChecksum(contents, "one"); err != nil || got != "aaa" {
		t.Errorf("one: %q err=%v", got, err)
	}
	if got, err := lookupChecksum(contents, "two"); err != nil || got != "bbb" {
		t.Errorf("two: %q err=%v", got, err)
	}
	if got, err := lookupChecksum(contents, "three"); err != nil || got != "ccc" {
		t.Errorf("three: %q err=%v", got, err)
	}
	if _, err := lookupChecksum(contents, "missing"); err == nil || !strings.Contains(err.Error(), "未找到") {
		t.Errorf("missing: err=%v", err)
	}

	if got := resolveChecksumLookupName("https://github.com/o/r/releases/download/v1.0.0/asset-bin", "/tmp/x"); got != "asset-bin" {
		t.Errorf("url base: %q", got)
	}
	if got := resolveChecksumLookupName("://bad url", filepath.Join("tmp", "fallback-bin")); got != "fallback-bin" {
		t.Errorf("bad url fallback: %q", got)
	}
	if got := resolveChecksumLookupName("", filepath.Join("tmp", "empty-bin")); got != "empty-bin" {
		t.Errorf("empty url fallback: %q", got)
	}
}

func TestVerifyChecksum(t *testing.T) {
	content := []byte("update-binary-payload")
	digest := sha256.Sum256(content)
	hash := hex.EncodeToString(digest[:])
	var broken atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s  update-asset\n", hash)
	}))
	defer srv.Close()
	client := &Client{Repo: "owner/repo", Kind: KindServer, CurrentVersion: "1.0.0", HTTPClient: srv.Client()}
	downloadURL := "https://github.com/owner/repo/releases/download/v1.0.0/update-asset"
	checksumURL := srv.URL + "/SHA256SUMS"

	filePath := filepath.Join(t.TempDir(), "update-asset")
	if err := os.WriteFile(filePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.verifyChecksum(context.Background(), filePath, checksumURL, downloadURL); err != nil {
		t.Fatalf("matching checksum rejected: %v", err)
	}

	if err := os.WriteFile(filePath, append(content, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	err := client.verifyChecksum(context.Background(), filePath, checksumURL, downloadURL)
	if err == nil || !strings.Contains(err.Error(), "校验和不匹配") {
		t.Fatalf("tampered file: err=%v", err)
	}

	// 未在 sums 中列出的下载文件名 → 显式报缺。
	otherURL := "https://github.com/owner/repo/releases/download/v1.0.0/other-asset"
	err = client.verifyChecksum(context.Background(), filePath, checksumURL, otherURL)
	if err == nil || !strings.Contains(err.Error(), "未找到") {
		t.Fatalf("missing entry: err=%v", err)
	}

	broken.Store(true)
	err = client.verifyChecksum(context.Background(), filePath, checksumURL, downloadURL)
	if err == nil || !strings.Contains(err.Error(), "下载校验文件失败") {
		t.Fatalf("server error: err=%v", err)
	}
}

func TestValidateReleaseAssetURLs(t *testing.T) {
	client := &Client{Repo: "owner/repo", Kind: KindServer}
	asset := AssetName(KindServer)
	validDownload := "https://github.com/owner/repo/releases/download/v1.2.3/" + asset
	validChecksum := "https://github.com/owner/repo/releases/download/v1.2.3/" + checksumAssetName
	if err := client.ValidateReleaseAssetURLs("1.2.3", validDownload, validChecksum); err != nil {
		t.Fatalf("valid URLs rejected: %v", err)
	}

	mustReject := []struct {
		name, version, download, checksum, wantIn string
	}{
		{"other host", "1.2.3", "https://objects.githubusercontent.com/owner/repo/releases/download/v1.2.3/" + asset, validChecksum, "github.com"},
		{"http scheme", "1.2.3", "http://github.com/owner/repo/releases/download/v1.2.3/" + asset, validChecksum, "HTTPS"},
		{"userinfo", "1.2.3", "https://user:pass@github.com/owner/repo/releases/download/v1.2.3/" + asset, validChecksum, "拒绝更新下载地址"},
		{"query", "1.2.3", validDownload + "?x=1", validChecksum, "拒绝更新下载地址"},
		{"wrong repo", "1.2.3", "https://github.com/other/repo/releases/download/v1.2.3/" + asset, validChecksum, "release asset"},
		{"wrong asset", "1.2.3", "https://github.com/owner/repo/releases/download/v1.2.3/other-asset", validChecksum, "不一致"},
		{"tag mismatch", "1.2.3", validDownload, "https://github.com/owner/repo/releases/download/v1.2.4/" + checksumAssetName, "同一 release tag"},
		{"version mismatch", "1.2.4", validDownload, validChecksum, "不一致"},
		{"traversal", "1.2.3", "https://github.com/owner/repo/releases/download/v1.2.3/%2e%2e/" + asset, validChecksum, "拒绝更新下载地址"},
	}
	for _, tc := range mustReject {
		err := client.ValidateReleaseAssetURLs(tc.version, tc.download, tc.checksum)
		if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
			t.Errorf("%s: err=%v want contains %q", tc.name, err, tc.wantIn)
		}
	}
}

func TestBuildReleaseInfo(t *testing.T) {
	asset := AssetName(KindServer)
	release := githubRelease{
		TagName:     "v2.0.1",
		HTMLURL:     "https://github.com/owner/repo/releases/tag/v2.0.1",
		PublishedAt: "2026-09-19T00:00:00Z",
		Assets: []githubAsset{
			{Name: asset, BrowserDownloadURL: "https://github.com/owner/repo/releases/download/v2.0.1/" + asset, Size: 1024},
			{Name: checksumAssetName, BrowserDownloadURL: "https://github.com/owner/repo/releases/download/v2.0.1/" + checksumAssetName},
		},
	}
	client := &Client{Repo: "owner/repo", Kind: KindServer, CurrentVersion: "2.0.0"}
	info := client.buildReleaseInfo(release)
	if info.LatestVersion != "2.0.1" || info.Tag != "v2.0.1" || !info.HasUpdate {
		t.Fatalf("info head: %+v", info)
	}
	if info.DownloadURL == "" || info.ChecksumURL == "" || info.AssetName != asset {
		t.Fatalf("asset wiring: %+v", info)
	}

	same := &Client{Repo: "owner/repo", Kind: KindServer, CurrentVersion: "2.0.1"}
	if info := same.buildReleaseInfo(release); info.HasUpdate {
		t.Fatalf("same version should not report update: %+v", info)
	}

	empty := githubRelease{TagName: "v2.0.1"}
	if info := client.buildReleaseInfo(empty); info.DownloadURL != "" || info.ChecksumURL != "" {
		t.Fatalf("missing assets should leave URLs empty: %+v", info)
	}
}
