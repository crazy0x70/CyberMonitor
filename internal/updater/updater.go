package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRepo              = "crazy0x70/CyberMonitor"
	defaultUserAgent         = "CyberMonitor-Updater"
	maxDownloadBytes         = 512 * 1024 * 1024
	deployModeEnvKey         = "CM_DEPLOY_MODE"
	checksumAssetName        = "SHA256SUMS"
	maxUpdaterErrorBodyBytes = 4096
	maxChecksumFileBytes     = 1024 * 1024
)

type Kind string
type DeployMode string

const (
	KindServer Kind = "server"
	KindAgent  Kind = "agent"

	DeployModeBinary DeployMode = "binary"
	DeployModeDocker DeployMode = "docker"
)

type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
}

type ReleaseInfo struct {
	CurrentVersion string         `json:"current_version"`
	LatestVersion  string         `json:"latest_version"`
	Tag            string         `json:"tag"`
	HTMLURL        string         `json:"html_url,omitempty"`
	PublishedAt    string         `json:"published_at,omitempty"`
	HasUpdate      bool           `json:"has_update"`
	AssetName      string         `json:"asset_name,omitempty"`
	DownloadURL    string         `json:"download_url,omitempty"`
	ChecksumURL    string         `json:"checksum_url,omitempty"`
	Assets         []ReleaseAsset `json:"assets,omitempty"`
}

type Client struct {
	Repo           string
	Kind           Kind
	CurrentVersion string
	HTTPClient     *http.Client
	UserAgent      string
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	HTMLURL     string        `json:"html_url"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func NewClient(repo string, kind Kind, currentVersion string) *Client {
	if strings.TrimSpace(repo) == "" {
		repo = DefaultRepo
	}
	return &Client{
		Repo:           repo,
		Kind:           kind,
		CurrentVersion: strings.TrimSpace(currentVersion),
		HTTPClient: &http.Client{
			Timeout: 45 * time.Second,
		},
		UserAgent: defaultUserAgent,
	}
}

func CanSelfUpdate() bool {
	return runtime.GOOS != "windows" && DetectDeployMode() == DeployModeBinary
}

func DetectDeployMode() DeployMode {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(deployModeEnvKey))) {
	case "docker", "container", "podman":
		return DeployModeDocker
	case "binary":
		return DeployModeBinary
	}
	if isContainerRuntime() {
		return DeployModeDocker
	}
	return DeployModeBinary
}

func DefaultUnsupportedUpdateMessage() string {
	if DetectDeployMode() == DeployModeDocker {
		if CanDockerManagedUpdate() {
			return ""
		}
		return "Docker 部署请挂载 /var/run/docker.sock 以启用后台一键更新；否则请拉取最新镜像并重建容器"
	}
	return ""
}

func isContainerRuntime() bool {
	if value := strings.TrimSpace(os.Getenv("container")); value != "" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return false
}

func (c *Client) CheckLatest(ctx context.Context) (ReleaseInfo, error) {
	release, err := c.fetchLatestRelease(ctx)
	if err != nil {
		return ReleaseInfo{}, err
	}
	return c.buildReleaseInfo(release), nil
}

func (c *Client) ApplyLatest(ctx context.Context) (ReleaseInfo, error) {
	info, err := c.CheckLatest(ctx)
	if err != nil {
		return ReleaseInfo{}, err
	}
	if !info.HasUpdate && CompareVersions(info.CurrentVersion, info.LatestVersion) >= 0 {
		return info, fmt.Errorf("当前已是最新版本")
	}
	if err := c.ApplyAsset(ctx, info.DownloadURL, info.ChecksumURL); err != nil {
		return info, err
	}
	return info, nil
}

func (c *Client) ApplyAsset(ctx context.Context, downloadURL, checksumURL string) error {
	if !CanSelfUpdate() {
		return fmt.Errorf("当前平台暂不支持自更新")
	}
	downloadURL = strings.TrimSpace(downloadURL)
	if downloadURL == "" {
		return fmt.Errorf("缺少更新下载地址")
	}
	exePath, err := resolveExecutablePath()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	tmpDir, err := os.MkdirTemp(exeDir, ".cm-update-*")
	if err != nil {
		return fmt.Errorf("创建更新临时目录失败: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	tmpBinary := filepath.Join(tmpDir, filepath.Base(exePath))
	if err := c.downloadFile(ctx, downloadURL, tmpBinary); err != nil {
		return err
	}
	if checksumURL = strings.TrimSpace(checksumURL); checksumURL != "" {
		if err := c.verifyChecksum(ctx, tmpBinary, checksumURL, downloadURL); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmpBinary, 0o755); err != nil {
		return fmt.Errorf("设置新二进制权限失败: %w", err)
	}
	if err := replaceExecutable(exePath, tmpBinary); err != nil {
		return err
	}
	return nil
}

func (c *Client) buildReleaseInfo(release githubRelease) ReleaseInfo {
	assets := make([]ReleaseAsset, 0, len(release.Assets))
	for _, asset := range release.Assets {
		assets = append(assets, ReleaseAsset{
			Name:        asset.Name,
			DownloadURL: asset.BrowserDownloadURL,
			Size:        asset.Size,
		})
	}

	info := ReleaseInfo{
		CurrentVersion: c.CurrentVersion,
		LatestVersion:  strings.TrimPrefix(strings.TrimSpace(release.TagName), "v"),
		Tag:            strings.TrimSpace(release.TagName),
		HTMLURL:        strings.TrimSpace(release.HTMLURL),
		PublishedAt:    strings.TrimSpace(release.PublishedAt),
		Assets:         assets,
	}
	info.HasUpdate = CompareVersions(info.CurrentVersion, info.LatestVersion) < 0

	assetName := AssetName(c.Kind)
	info.AssetName = assetName
	for _, asset := range assets {
		switch asset.Name {
		case assetName:
			info.DownloadURL = asset.DownloadURL
		case checksumAssetName:
			info.ChecksumURL = asset.DownloadURL
		}
	}
	return info
}

func (c *Client) fetchLatestRelease(ctx context.Context) (githubRelease, error) {
	resp, err := c.getOK(ctx, fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", c.Repo), "application/vnd.github+json", "获取最新 Release 失败", "", "GitHub API 返回状态码 %d")
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("解析 Release 信息失败: %w", err)
	}
	return release, nil
}

func (c *Client) downloadFile(ctx context.Context, downloadURL, dest string) error {
	resp, err := c.getOK(ctx, downloadURL, "", "下载更新文件失败", "", "下载返回状态码 %d")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxDownloadBytes {
		return fmt.Errorf("更新文件过大: %d bytes", resp.ContentLength)
	}

	file, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("创建更新文件失败: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	written, err := io.Copy(file, limited)
	if err != nil {
		return fmt.Errorf("写入更新文件失败: %w", err)
	}
	if written > maxDownloadBytes {
		return fmt.Errorf("更新文件超过大小限制")
	}
	return nil
}

func (c *Client) verifyChecksum(ctx context.Context, filePath, checksumURL, downloadURL string) error {
	resp, err := c.getOK(ctx, checksumURL, "", "下载校验文件失败", "下载校验文件失败", "状态码 %d")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	checksumBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumFileBytes))
	if err != nil {
		return fmt.Errorf("读取校验文件失败: %w", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开更新文件失败: %w", err)
	}
	defer file.Close()

	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return fmt.Errorf("计算更新文件校验失败: %w", err)
	}
	actual := hex.EncodeToString(sum.Sum(nil))
	expected, err := lookupChecksum(string(checksumBytes), resolveChecksumLookupName(downloadURL, filePath))
	if err != nil {
		return err
	}
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("校验和不匹配")
	}
	return nil
}

func (c *Client) getOK(ctx context.Context, rawURL, accept, requestErrorPrefix, statusErrorPrefix, statusFallback string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", requestErrorPrefix, err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()

	message := readUpdaterHTTPErrorMessage(resp, fmt.Sprintf(statusFallback, resp.StatusCode))
	if statusErrorPrefix != "" {
		return nil, fmt.Errorf("%s: %s", statusErrorPrefix, message)
	}
	return nil, fmt.Errorf("%s", message)
}

func readUpdaterHTTPErrorMessage(resp *http.Response, fallback string) string {
	message := strings.TrimSpace(fallback)
	if resp == nil {
		return message
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpdaterErrorBodyBytes))
	if text := strings.TrimSpace(string(body)); text != "" {
		return text
	}
	return message
}

func resolveChecksumLookupName(downloadURL, filePath string) string {
	if raw := strings.TrimSpace(downloadURL); raw != "" {
		if parsed, err := url.Parse(raw); err == nil {
			name := path.Base(strings.TrimSpace(parsed.Path))
			if name != "" && name != "." && name != "/" {
				return name
			}
		}
	}
	return filepath.Base(filePath)
}

func lookupChecksum(contents, filename string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if fields[1] == filename {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("读取校验文件失败: %w", err)
	}
	return "", fmt.Errorf("未找到 %s 的校验和", filename)
}

func replaceExecutable(targetPath, nextPath string) error {
	backupPath := targetPath + ".backup"
	_ = os.Remove(backupPath)
	if err := os.Rename(targetPath, backupPath); err != nil {
		return fmt.Errorf("备份当前二进制失败: %w", err)
	}
	if err := os.Rename(nextPath, targetPath); err != nil {
		if restoreErr := os.Rename(backupPath, targetPath); restoreErr != nil {
			return fmt.Errorf("替换失败且回滚失败: %w", restoreErr)
		}
		return fmt.Errorf("替换当前二进制失败: %w", err)
	}
	return nil
}

func resolveExecutablePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取当前可执行文件路径失败: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("解析可执行文件路径失败: %w", err)
	}
	return resolved, nil
}

func AssetName(kind Kind) string {
	arch := runtime.GOARCH
	switch arch {
	case "arm":
		arch = "armv7"
	case "amd64", "arm64":
	default:
		arch = runtime.GOARCH
	}
	name := fmt.Sprintf("cyber-monitor-%s-%s-%s", kind, runtime.GOOS, arch)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func CompareVersions(current, latest string) int {
	currentParts := parseVersion(current)
	latestParts := parseVersion(latest)
	for idx := 0; idx < 3; idx++ {
		switch {
		case currentParts[idx] < latestParts[idx]:
			return -1
		case currentParts[idx] > latestParts[idx]:
			return 1
		}
	}
	return 0
}

func parseVersion(value string) [3]int {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		value = value[:dash]
	}
	parts := strings.Split(value, ".")
	var result [3]int
	for idx := 0; idx < len(parts) && idx < len(result); idx++ {
		parsed, err := strconv.Atoi(parts[idx])
		if err == nil {
			result[idx] = parsed
		}
	}
	return result
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) userAgent() string {
	if c != nil && strings.TrimSpace(c.UserAgent) != "" {
		return strings.TrimSpace(c.UserAgent)
	}
	return defaultUserAgent
}
