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
	maxReleaseJSONBytes      = 1 << 20
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
	// 不设 Client.Timeout：512MB 上限的二进制下载在慢链路上远超任何整客户端
	// 超时；API 类小请求由调用处的 ctx 超时约束，下载由 LimitReader+外层 ctx 兜底。
	return &Client{
		Repo:           repo,
		Kind:           kind,
		CurrentVersion: strings.TrimSpace(currentVersion),
		HTTPClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// GitHub release 下载正常会 302 到 *.githubusercontent.com；
				// 其余主机一律拒绝，防止上游开放重定向把二进制/校验文件
				// 导向第三方源。
				host := req.URL.Hostname()
				if host == "github.com" || strings.HasSuffix(host, ".githubusercontent.com") {
					return nil
				}
				return fmt.Errorf("更新下载重定向到不受信主机: %s", host)
			},
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
		return "Docker 部署请设置 CM_ENABLE_DOCKER_UPDATE=1 并挂载 /var/run/docker.sock 以启用后台一键更新；否则请拉取最新镜像并重建容器"
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

func (c *Client) ApplyReleaseAsset(ctx context.Context, expectedVersion, downloadURL, checksumURL string) error {
	if !CanSelfUpdate() {
		return fmt.Errorf("当前平台暂不支持自更新")
	}
	expectedVersion = strings.TrimSpace(expectedVersion)
	if expectedVersion == "" {
		return fmt.Errorf("缺少更新目标版本")
	}
	downloadURL = strings.TrimSpace(downloadURL)
	if downloadURL == "" {
		return fmt.Errorf("缺少更新下载地址")
	}
	checksumURL = strings.TrimSpace(checksumURL)
	if checksumURL == "" {
		return fmt.Errorf("缺少更新校验地址")
	}
	if err := c.ValidateReleaseAssetURLs(expectedVersion, downloadURL, checksumURL); err != nil {
		return err
	}
	exePath, err := resolveExecutablePath()
	if err != nil {
		return err
	}
	exeInfo, err := os.Stat(exePath)
	if err != nil {
		return fmt.Errorf("读取当前二进制信息失败: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	// 清扫此前进程被强杀（SIGKILL/OOM）残留的更新临时目录——defer 清理在
	// 那些场景不会执行。只清修改时间超过 1 小时的，避免误删并发进行中的更新。
	if matches, globErr := filepath.Glob(filepath.Join(exeDir, ".cm-update-*")); globErr == nil {
		staleCutoff := time.Now().Add(-time.Hour)
		for _, match := range matches {
			if info, statErr := os.Stat(match); statErr == nil && info.ModTime().Before(staleCutoff) {
				_ = os.RemoveAll(match)
			}
		}
	}
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
	if err := c.verifyChecksum(ctx, tmpBinary, checksumURL, downloadURL); err != nil {
		return err
	}
	// 沿用现有权限位（至少保留属主可执行位），不把受限执行策略放宽为 0755。
	newMode := exeInfo.Mode().Perm()
	if newMode&0o100 == 0 {
		newMode |= 0o100
	}
	if err := os.Chmod(tmpBinary, newMode); err != nil {
		return fmt.Errorf("设置新二进制权限失败: %w", err)
	}
	if err := replaceExecutable(exePath, tmpBinary); err != nil {
		return err
	}
	return nil
}

type releaseAssetRef struct {
	tag   string
	asset string
}

func ValidateReleaseAssetURLs(kind Kind, expectedVersion, downloadURL, checksumURL string) error {
	return NewClient(DefaultRepo, kind, "").ValidateReleaseAssetURLs(expectedVersion, downloadURL, checksumURL)
}

func (c *Client) ValidateReleaseAssetURLs(expectedVersion, downloadURL, checksumURL string) error {
	download, err := c.parseGitHubReleaseAssetURL(downloadURL, AssetName(c.Kind))
	if err != nil {
		return fmt.Errorf("拒绝更新下载地址: %w", err)
	}
	checksum, err := c.parseGitHubReleaseAssetURL(checksumURL, checksumAssetName)
	if err != nil {
		return fmt.Errorf("拒绝更新校验地址: %w", err)
	}
	if download.tag != checksum.tag {
		return fmt.Errorf("更新下载地址和校验地址不属于同一 release tag")
	}
	if !VersionsEqual(download.tag, expectedVersion) {
		return fmt.Errorf("更新地址版本 %s 与目标版本 %s 不一致", download.tag, expectedVersion)
	}
	return nil
}

func (c *Client) parseGitHubReleaseAssetURL(rawURL, expectedAsset string) (releaseAssetRef, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return releaseAssetRef{}, err
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Host, "github.com") {
		return releaseAssetRef{}, fmt.Errorf("必须使用 github.com 的 HTTPS release 地址")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return releaseAssetRef{}, fmt.Errorf("release 地址不能包含 query 或 fragment")
	}

	owner, repo, ok := strings.Cut(strings.Trim(strings.TrimSpace(c.Repo), "/"), "/")
	if !ok || owner == "" || repo == "" {
		return releaseAssetRef{}, fmt.Errorf("更新仓库配置无效")
	}
	segments, err := splitEscapedPathSegments(parsed.EscapedPath())
	if err != nil {
		return releaseAssetRef{}, err
	}
	if len(segments) != 6 ||
		!strings.EqualFold(segments[0], owner) ||
		!strings.EqualFold(segments[1], repo) ||
		segments[2] != "releases" ||
		segments[3] != "download" {
		return releaseAssetRef{}, fmt.Errorf("必须指向 %s 的 release asset", c.Repo)
	}
	if segments[5] != expectedAsset {
		return releaseAssetRef{}, fmt.Errorf("asset %q 与期望 %q 不一致", segments[5], expectedAsset)
	}
	return releaseAssetRef{tag: segments[4], asset: segments[5]}, nil
}

func splitEscapedPathSegments(escapedPath string) ([]string, error) {
	trimmed := strings.Trim(escapedPath, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("release 地址路径为空")
	}
	rawSegments := strings.Split(trimmed, "/")
	segments := make([]string, 0, len(rawSegments))
	for _, raw := range rawSegments {
		segment, err := url.PathUnescape(raw)
		if err != nil {
			return nil, fmt.Errorf("release 地址路径编码无效")
		}
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) {
			return nil, fmt.Errorf("release 地址路径包含非法片段")
		}
		segments = append(segments, segment)
	}
	return segments, nil
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
	info.HasUpdate = HasVersionUpdate(info.CurrentVersion, info.LatestVersion)

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
	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.getOK(apiCtx, fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", c.Repo), "application/vnd.github+json", "获取最新 Release 失败", "", "GitHub API 返回状态码 %d")
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()

	var release githubRelease
	// 与其他读取路径（错误体 4KB、SHA256SUMS 1MB、下载 512MB）对齐：
	// API 响应同样限长，截断会让 Decode 报错，fail-closed。
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReleaseJSONBytes)).Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("解析 Release 信息失败: %w", err)
	}
	return release, nil
}

func (c *Client) downloadFile(ctx context.Context, downloadURL, dest string) error {
	// agent 自更新路径的外层 ctx 无 deadline（server 路径有 10 分钟）：
	// 连接 stall 会让 io.Copy 无限期挂起并占死 remoteUpdateTracker，此处
	// 统一加时间兜底（512MB @ ~0.3MB/s 慢链路）。
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
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
	// 落盘后再 rename：掉电/崩溃不留截断的二进制。
	if err := file.Sync(); err != nil {
		return fmt.Errorf("同步更新文件失败: %w", err)
	}
	return nil
}

func (c *Client) verifyChecksum(ctx context.Context, filePath, checksumURL, downloadURL string) error {
	// 校验文件是小请求：30s 足够，避免与二进制下载共用无超时客户端。
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
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
	// 先复制备份、再单次原子 rename：两个 rename 之间存在目标路径短暂
	// 不存在的窗口，进程恰在此刻崩溃会留下无可执行文件且无法自愈。
	// 复制式备份下，rename 失败时旧二进制原位未动，无需回滚。
	backupPath := targetPath + ".backup"
	if err := copyExecutableBackup(targetPath, backupPath); err != nil {
		return fmt.Errorf("备份当前二进制失败: %w", err)
	}
	if err := os.Rename(nextPath, targetPath); err != nil {
		return fmt.Errorf("替换当前二进制失败: %w", err)
	}
	syncDirForUpdate(filepath.Dir(targetPath))
	return nil
}

// syncDirForUpdate 对父目录做 fsync，确保 rename 的目录项在掉电后不回退。
// Windows 不支持以文件语义打开目录，依赖 NTFS 元数据日志，跳过。
func syncDirForUpdate(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = dirFile.Sync()
	_ = dirFile.Close()
}

func copyExecutableBackup(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	_ = os.Remove(dst)
	backup, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(backup, source); err != nil {
		backup.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := backup.Sync(); err != nil {
		backup.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := backup.Close(); err != nil {
		_ = os.Remove(dst)
		return err
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
	if arch == "arm" {
		arch = "armv7"
	}
	name := fmt.Sprintf("cyber-monitor-%s-%s-%s", kind, runtime.GOOS, arch)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func compareVersionParts(currentParts, latestParts [3]int) int {
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

type comparableVersion struct {
	parts      [3]int
	prerelease []string
}

func HasVersionUpdate(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if latest == "" || VersionsEqual(current, latest) {
		return false
	}
	latestVersion, latestOK := parseComparableVersion(latest)
	if !latestOK {
		return false
	}
	currentVersion, currentOK := parseComparableVersion(current)
	if !currentOK {
		// dev/unknown 等无法解析的当前版本（多为源码构建）不做自动替换，
		// 避免任意 release 都会覆盖非发布构建。
		return false
	}
	return compareComparableVersions(currentVersion, latestVersion) < 0
}

func ValidReleaseVersion(version string) bool {
	_, ok := parseComparableVersion(version)
	return ok
}

func VersionCurrentOrNewer(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if VersionsEqual(current, latest) {
		return true
	}
	currentVersion, currentOK := parseComparableVersion(current)
	latestVersion, latestOK := parseComparableVersion(latest)
	if !currentOK || !latestOK {
		return false
	}
	return compareComparableVersions(currentVersion, latestVersion) >= 0
}

// VersionsEqual reports whether two non-empty version strings refer to the same version.
func VersionsEqual(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if current == "" || latest == "" {
		return false
	}
	if current == latest {
		return true
	}
	currentVersion, currentOK := parseComparableVersion(current)
	latestVersion, latestOK := parseComparableVersion(latest)
	if !currentOK || !latestOK {
		return false
	}
	return compareComparableVersions(currentVersion, latestVersion) == 0
}

func parseComparableVersion(value string) (comparableVersion, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if plus := strings.IndexByte(value, '+'); plus >= 0 {
		value = value[:plus]
	}
	var version comparableVersion
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		prerelease := value[dash+1:]
		if prerelease == "" {
			return version, false
		}
		identifiers, ok := parsePrereleaseIdentifiers(prerelease)
		if !ok {
			return version, false
		}
		version.prerelease = identifiers
		value = value[:dash]
	}
	if value == "" {
		return version, false
	}
	parts := strings.Split(value, ".")
	if len(parts) > len(version.parts) {
		return version, false
	}
	for idx := 0; idx < len(parts); idx++ {
		part := strings.TrimSpace(parts[idx])
		// isDecimalIdentifier 同时拒绝空段、"+" 前缀（Atoi 接受 "+5"）
		// 与非数字段，保证数字语义不被strconv的宽松解析绕过。
		if !isDecimalIdentifier(part) {
			return version, false
		}
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return version, false
		}
		version.parts[idx] = parsed
	}
	return version, true
}

func compareComparableVersions(current, latest comparableVersion) int {
	if result := compareVersionParts(current.parts, latest.parts); result != 0 {
		return result
	}
	if len(current.prerelease) == 0 && len(latest.prerelease) == 0 {
		return 0
	}
	if len(current.prerelease) == 0 {
		return 1
	}
	if len(latest.prerelease) == 0 {
		return -1
	}
	return comparePrereleaseIdentifiers(current.prerelease, latest.prerelease)
}

func parsePrereleaseIdentifiers(value string) ([]string, bool) {
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" || !isPrereleaseIdentifier(part) {
			return nil, false
		}
		if len(part) > 1 && part[0] == '0' && isDecimalIdentifier(part) {
			return nil, false
		}
	}
	return parts, true
}

func isPrereleaseIdentifier(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func comparePrereleaseIdentifiers(current, latest []string) int {
	for idx := 0; idx < len(current) && idx < len(latest); idx++ {
		if current[idx] == latest[idx] {
			continue
		}
		currentNumber, currentNumeric := parseNumericPrereleaseIdentifier(current[idx])
		latestNumber, latestNumeric := parseNumericPrereleaseIdentifier(latest[idx])
		switch {
		case currentNumeric && latestNumeric:
			switch {
			case currentNumber < latestNumber:
				return -1
			case currentNumber > latestNumber:
				return 1
			default:
				continue
			}
		case currentNumeric:
			return -1
		case latestNumeric:
			return 1
		case current[idx] < latest[idx]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(current) < len(latest):
		return -1
	case len(current) > len(latest):
		return 1
	default:
		return 0
	}
}

func parseNumericPrereleaseIdentifier(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	if !isDecimalIdentifier(value) {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func isDecimalIdentifier(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func (c *Client) httpClient() *http.Client {
	return c.HTTPClient
}

func (c *Client) userAgent() string {
	if c != nil && strings.TrimSpace(c.UserAgent) != "" {
		return strings.TrimSpace(c.UserAgent)
	}
	return defaultUserAgent
}
