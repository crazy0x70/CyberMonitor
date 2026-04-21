package updater

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	dockerSocketEnvKey             = "CM_DOCKER_SOCKET"
	containerIDEnvKey              = "CM_CONTAINER_ID"
	dockerHelperCommand            = "docker-recreate-helper"
	dockerHelperTargetContainerEnv = "CM_DOCKER_HELPER_TARGET_CONTAINER"
	dockerHelperTargetImageEnv     = "CM_DOCKER_HELPER_TARGET_IMAGE"
	dockerHelperNodeIDEnv          = "CM_DOCKER_HELPER_NODE_ID"
	dockerHelperSocketSourceEnv    = "CM_DOCKER_HELPER_SOCKET_SOURCE"
	dockerHelperSocketTargetEnv    = "CM_DOCKER_HELPER_SOCKET_TARGET"
	dockerDefaultSocketPath        = "/var/run/docker.sock"
	dockerHelperMountTarget        = "/var/run/docker.sock"
	dockerManagedMode              = "docker-managed"
	dockerSelfMountInfoPath        = "/proc/self/mountinfo"
	dockerSelfCgroupPath           = "/proc/self/cgroup"
	dockerManagedProbeCacheTTL     = 2 * time.Second
)

var (
	mountInfoContainerIDPattern = regexp.MustCompile(`/containers/([a-f0-9]{64})/(?:hostname|hosts|resolv\.conf)\b`)
	cgroupContainerIDPatterns   = []*regexp.Regexp{
		regexp.MustCompile(`(?:^|[/:_-])docker[-/]([a-f0-9]{64})(?:\.scope)?(?:$|[/:_.-])`),
		regexp.MustCompile(`(?:^|[/:_-])docker[-/]([a-f0-9]{12})(?:\.scope)?(?:$|[/:_.-])`),
		regexp.MustCompile(`(?:^|[/:_-])cri-containerd[-/]([a-f0-9]{64})(?:\.scope)?(?:$|[/:_.-])`),
		regexp.MustCompile(`(?:^|[/:_-])cri-containerd[-/]([a-f0-9]{12})(?:\.scope)?(?:$|[/:_.-])`),
		regexp.MustCompile(`(?:^|[/:_-])containerd[-/]([a-f0-9]{64})(?:\.scope)?(?:$|[/:_.-])`),
		regexp.MustCompile(`(?:^|[/:_-])containerd[-/]([a-f0-9]{12})(?:\.scope)?(?:$|[/:_.-])`),
	}
	dockerManagedProbeCache = struct {
		mu    sync.Mutex
		until time.Time
		probe dockerManagedProbe
		err   error
	}{}
)

type DockerManagedUpdater struct {
	socketPath       string
	socketSource     string
	containerID      string
	containerName    string
	currentImage     string
	helperImage      string
	helperEntrypoint []string
	cli              *client.Client
}

type dockerManagedProbe struct {
	socketPath  string
	containerID string
}

func (u *DockerManagedUpdater) CurrentImage() string {
	if u == nil {
		return ""
	}
	return strings.TrimSpace(u.currentImage)
}

func DetectUpdateMode() string {
	if DetectDeployMode() == DeployModeDocker {
		if CanDockerManagedUpdate() {
			return dockerManagedMode
		}
		return string(DeployModeDocker)
	}
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return string(DeployModeBinary)
}

func CanDockerManagedUpdate() bool {
	_, err := probeDockerManagedUpdate()
	return err == nil
}

func CanCurrentDeployUpdate() bool {
	return CanSelfUpdate() || CanDockerManagedUpdate()
}

func ResolveDockerTargetImage(currentImage, targetVersion string) string {
	currentImage = strings.TrimSpace(currentImage)
	targetVersion = strings.TrimSpace(targetVersion)
	if currentImage == "" {
		return ""
	}
	repo := currentImage
	if at := strings.Index(repo, "@"); at >= 0 {
		repo = repo[:at]
	}
	lastSlash := strings.LastIndex(repo, "/")
	lastColon := strings.LastIndex(repo, ":")
	if lastColon > lastSlash {
		repo = repo[:lastColon]
	}
	if targetVersion == "" {
		return repo
	}
	return repo + ":" + strings.TrimPrefix(targetVersion, "v")
}

func resolveDockerSocketPath() string {
	if value := strings.TrimSpace(os.Getenv(dockerSocketEnvKey)); value != "" {
		return value
	}
	return dockerDefaultSocketPath
}

func resolveCurrentContainerID() (string, error) {
	return resolveCurrentContainerIDWithSources(os.Getenv, os.ReadFile)
}

func probeDockerManagedUpdate() (dockerManagedProbe, error) {
	dockerManagedProbeCache.mu.Lock()
	defer dockerManagedProbeCache.mu.Unlock()
	now := time.Now()
	if now.Before(dockerManagedProbeCache.until) {
		return dockerManagedProbeCache.probe, dockerManagedProbeCache.err
	}
	probe, err := probeDockerManagedUpdateUncached()
	dockerManagedProbeCache.probe = probe
	dockerManagedProbeCache.err = err
	dockerManagedProbeCache.until = now.Add(dockerManagedProbeCacheTTL)
	return probe, err
}

func probeDockerManagedUpdateUncached() (dockerManagedProbe, error) {
	if DetectDeployMode() != DeployModeDocker {
		return dockerManagedProbe{}, fmt.Errorf("当前部署模式不是 Docker")
	}
	socketPath := resolveDockerSocketPath()
	if err := ensureDockerSocketAccessible(socketPath); err != nil {
		return dockerManagedProbe{}, err
	}
	containerID, err := resolveCurrentContainerID()
	if err != nil {
		return dockerManagedProbe{}, err
	}
	return dockerManagedProbe{
		socketPath:  socketPath,
		containerID: containerID,
	}, nil
}

func ensureDockerSocketAccessible(socketPath string) error {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return fmt.Errorf("未配置 docker socket")
	}
	if _, err := os.Stat(socketPath); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func resolveCurrentContainerIDWithSources(
	getenv func(string) string,
	readFile func(string) ([]byte, error),
) (string, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if value := strings.TrimSpace(getenv(containerIDEnvKey)); value != "" {
		return value, nil
	}
	if readFile != nil {
		for _, source := range [...]struct {
			path  string
			parse func([]byte) string
		}{
			{path: dockerSelfMountInfoPath, parse: parseContainerIDFromMountInfo},
			{path: dockerSelfCgroupPath, parse: parseContainerIDFromCgroup},
		} {
			raw, err := readFile(source.path)
			if err != nil {
				continue
			}
			if value := source.parse(raw); value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("无法解析当前容器 ID")
}

func parseContainerIDFromMountInfo(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	matches := mountInfoContainerIDPattern.FindSubmatch(raw)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(string(matches[1]))
}

func parseContainerIDFromCgroup(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return ""
	}
	for _, pattern := range cgroupContainerIDPatterns {
		matches := pattern.FindStringSubmatch(text)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func NewDockerManagedUpdater() (*DockerManagedUpdater, error) {
	return NewDockerManagedUpdaterContext(context.Background())
}

func NewDockerManagedUpdaterContext(ctx context.Context) (*DockerManagedUpdater, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	probe, err := probeDockerManagedUpdate()
	if err != nil {
		return nil, fmt.Errorf("Docker 一键更新需要挂载可访问的 docker.sock")
	}
	cli, err := newDockerClient(probe.socketPath)
	if err != nil {
		return nil, err
	}
	inspect, err := cli.ContainerInspect(ctx, probe.containerID)
	if err != nil {
		return nil, fmt.Errorf("读取当前容器信息失败: %w", err)
	}
	if err := validateContainerInspect(inspect, "当前容器"); err != nil {
		return nil, err
	}
	socketSource := resolveDockerSocketSource(inspect.Mounts, probe.socketPath)
	if socketSource == "" {
		return nil, fmt.Errorf("当前容器未挂载 docker socket: %s", probe.socketPath)
	}
	helperEntrypoint := append([]string{}, inspect.Config.Entrypoint...)
	if len(helperEntrypoint) == 0 {
		helperEntrypoint = []string{"/app/cyber-monitor"}
	}
	return &DockerManagedUpdater{
		socketPath:       probe.socketPath,
		socketSource:     socketSource,
		containerID:      inspect.ID,
		containerName:    strings.TrimPrefix(inspect.Name, "/"),
		currentImage:     strings.TrimSpace(inspect.Config.Image),
		helperImage:      strings.TrimSpace(inspect.Config.Image),
		helperEntrypoint: helperEntrypoint,
		cli:              cli,
	}, nil
}

func (u *DockerManagedUpdater) LaunchSelfContainerUpdate(ctx context.Context, targetImage string, currentNodeID string) error {
	if u == nil {
		return fmt.Errorf("docker updater 未初始化")
	}
	targetImage = strings.TrimSpace(targetImage)
	if targetImage == "" {
		return fmt.Errorf("缺少目标镜像")
	}
	helperName := fmt.Sprintf("cm-update-helper-%s-%d", sanitizeContainerName(u.containerName), time.Now().Unix())
	config := &container.Config{
		Image:      u.helperImage,
		Entrypoint: append([]string{}, u.helperEntrypoint...),
		Cmd:        []string{dockerHelperCommand},
		User:       "0",
		Env: []string{
			fmt.Sprintf("%s=%s", dockerHelperTargetContainerEnv, u.containerID),
			fmt.Sprintf("%s=%s", dockerHelperTargetImageEnv, targetImage),
			fmt.Sprintf("%s=%s", dockerHelperNodeIDEnv, currentNodeID),
			fmt.Sprintf("%s=%s", dockerHelperSocketSourceEnv, u.socketSource),
			fmt.Sprintf("%s=%s", dockerHelperSocketTargetEnv, dockerHelperMountTarget),
		},
	}
	hostConfig := &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: "none",
		Binds: []string{
			fmt.Sprintf("%s:%s", u.socketSource, dockerHelperMountTarget),
		},
		RestartPolicy: container.RestartPolicy{Name: "no"},
	}
	resp, err := u.cli.ContainerCreate(ctx, config, hostConfig, nil, nil, helperName)
	if err != nil {
		return fmt.Errorf("创建 Docker 更新 helper 失败: %w", err)
	}
	if err := u.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("启动 Docker 更新 helper 失败: %w", err)
	}
	return nil
}

func RunDockerRecreateHelper(ctx context.Context) error {
	targetContainerID := strings.TrimSpace(os.Getenv(dockerHelperTargetContainerEnv))
	targetImage := strings.TrimSpace(os.Getenv(dockerHelperTargetImageEnv))
	currentNodeID := strings.TrimSpace(os.Getenv(dockerHelperNodeIDEnv))
	socketPath := strings.TrimSpace(os.Getenv(dockerHelperSocketTargetEnv))
	if socketPath == "" {
		socketPath = dockerHelperMountTarget
	}
	if targetContainerID == "" {
		return fmt.Errorf("缺少 helper 目标容器 ID")
	}
	if targetImage == "" {
		return fmt.Errorf("缺少 helper 目标镜像")
	}
	cli, err := newDockerClient(socketPath)
	if err != nil {
		return err
	}
	inspect, err := cli.ContainerInspect(ctx, targetContainerID)
	if err != nil {
		return fmt.Errorf("读取目标容器信息失败: %w", err)
	}
	if err := validateContainerInspect(inspect, "目标容器"); err != nil {
		return err
	}
	if err := pullDockerImage(ctx, cli, targetImage); err != nil {
		return err
	}
	tempName := fmt.Sprintf("%s-next-%d", sanitizeContainerName(strings.TrimPrefix(inspect.Name, "/")), time.Now().Unix())
	cfg, hostCfg, netCfg, extraNetworks := buildReplacementSpec(inspect, targetImage, currentNodeID)
	created, err := cli.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, tempName)
	if err != nil {
		return fmt.Errorf("创建替换容器失败: %w", err)
	}
	defer func() {
		if err != nil {
			_ = cli.ContainerRemove(context.Background(), created.ID, container.RemoveOptions{Force: true})
		}
	}()
	for networkName, endpoint := range extraNetworks {
		if connectErr := cli.NetworkConnect(ctx, networkName, created.ID, endpoint); connectErr != nil {
			err = fmt.Errorf("连接附加网络 %s 失败: %w", networkName, connectErr)
			return err
		}
	}
	timeout := 20
	_ = cli.ContainerStop(ctx, inspect.ID, container.StopOptions{Timeout: &timeout})
	if removeErr := cli.ContainerRemove(ctx, inspect.ID, container.RemoveOptions{Force: true}); removeErr != nil {
		return fmt.Errorf("移除旧容器失败: %w", removeErr)
	}
	originalName := strings.TrimPrefix(inspect.Name, "/")
	if renameErr := cli.ContainerRename(ctx, created.ID, originalName); renameErr != nil {
		return fmt.Errorf("恢复容器名称失败: %w", renameErr)
	}
	if startErr := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); startErr != nil {
		return fmt.Errorf("启动新容器失败: %w", startErr)
	}
	return nil
}

func validateContainerInspect(inspect dockertypes.ContainerJSON, subject string) error {
	switch {
	case inspect.Config == nil:
		return fmt.Errorf("%s缺少 Config 信息", subject)
	case inspect.HostConfig == nil:
		return fmt.Errorf("%s缺少 HostConfig 信息", subject)
	default:
		return nil
	}
}

func buildReplacementSpec(inspect dockertypes.ContainerJSON, targetImage string, currentNodeID string) (*container.Config, *container.HostConfig, *network.NetworkingConfig, map[string]*network.EndpointSettings) {
	hostname := strings.TrimSpace(inspect.Config.Hostname)
	shortID := strings.TrimSpace(inspect.ID)
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	if hostname == shortID {
		hostname = ""
	}
	env := append([]string{}, inspect.Config.Env...)
	env = backfillEnvValueIfEmpty(env, "CM_NODE_ID", currentNodeID)
	cfg := &container.Config{
		Hostname:     hostname,
		Image:        targetImage,
		Env:          env,
		Cmd:          append([]string{}, inspect.Config.Cmd...),
		Entrypoint:   append([]string{}, inspect.Config.Entrypoint...),
		WorkingDir:   inspect.Config.WorkingDir,
		User:         inspect.Config.User,
		Labels:       cloneStringMap(inspect.Config.Labels),
		ExposedPorts: clonePortSet(inspect.Config.ExposedPorts),
		Volumes:      cloneVolumeMap(inspect.Config.Volumes),
		Tty:          inspect.Config.Tty,
		OpenStdin:    inspect.Config.OpenStdin,
		StdinOnce:    inspect.Config.StdinOnce,
		AttachStdin:  inspect.Config.AttachStdin,
		AttachStdout: inspect.Config.AttachStdout,
		AttachStderr: inspect.Config.AttachStderr,
	}
	hostCfg := *inspect.HostConfig
	hostCfg.RestartPolicy = inspect.HostConfig.RestartPolicy
	hostCfg.AutoRemove = false
	hostCfg.Mounts = append([]mount.Mount{}, inspect.HostConfig.Mounts...)
	netCfg, extraNetworks := buildReplacementNetworking(inspect)
	return cfg, &hostCfg, netCfg, extraNetworks
}

func buildReplacementNetworking(inspect dockertypes.ContainerJSON) (*network.NetworkingConfig, map[string]*network.EndpointSettings) {
	mode := strings.TrimSpace(string(inspect.HostConfig.NetworkMode))
	if !shouldCloneEndpointConfig(mode) || inspect.NetworkSettings == nil || len(inspect.NetworkSettings.Networks) == 0 {
		return nil, nil
	}
	primaryNetworkName := resolvePrimaryNetworkName(mode, inspect.NetworkSettings.Networks)
	netCfg := &network.NetworkingConfig{}
	extraNetworks := make(map[string]*network.EndpointSettings)
	for networkName, endpoint := range inspect.NetworkSettings.Networks {
		copied := cloneEndpointSettings(endpoint)
		if networkName == primaryNetworkName {
			netCfg.EndpointsConfig = map[string]*network.EndpointSettings{
				networkName: copied,
			}
			continue
		}
		extraNetworks[networkName] = copied
	}
	if len(netCfg.EndpointsConfig) == 0 {
		netCfg = nil
	}
	if len(extraNetworks) == 0 {
		extraNetworks = nil
	}
	return netCfg, extraNetworks
}

func resolvePrimaryNetworkName(mode string, networks map[string]*network.EndpointSettings) string {
	mode = strings.TrimSpace(mode)
	if mode != "" {
		return mode
	}
	if len(networks) != 1 {
		return ""
	}
	for networkName := range networks {
		return networkName
	}
	return ""
}

func shouldCloneEndpointConfig(mode string) bool {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return true
	}
	switch {
	case mode == "host", mode == "none":
		return false
	case strings.HasPrefix(mode, "container:"):
		return false
	default:
		return true
	}
}

func newDockerClient(socketPath string) (*client.Client, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = dockerDefaultSocketPath
	}
	host := "unix://" + socketPath
	return client.NewClientWithOpts(client.WithHost(host), client.WithAPIVersionNegotiation())
}

func pullDockerImage(ctx context.Context, cli *client.Client, targetImage string) error {
	reader, err := cli.ImagePull(ctx, targetImage, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("拉取目标镜像失败: %w", err)
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

func resolveDockerSocketSource(mounts []container.MountPoint, target string) string {
	target = strings.TrimSpace(target)
	for _, item := range mounts {
		if strings.TrimSpace(item.Destination) == target {
			return strings.TrimSpace(item.Source)
		}
	}
	return ""
}

func sanitizeContainerName(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "/"))
	if value == "" {
		return "cyber-monitor"
	}
	replacer := strings.NewReplacer("/", "-", ":", "-", "@", "-", ".", "-", "_", "-")
	return replacer.Replace(value)
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func clonePortSet(input nat.PortSet) nat.PortSet {
	if len(input) == 0 {
		return nil
	}
	cloned := make(nat.PortSet, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneVolumeMap(input map[string]struct{}) map[string]struct{} {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]struct{}, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneEndpointSettings(input *network.EndpointSettings) *network.EndpointSettings {
	if input == nil {
		return nil
	}
	cloned := *input
	if len(input.Aliases) > 0 {
		cloned.Aliases = append([]string{}, input.Aliases...)
	}
	if input.DriverOpts != nil {
		cloned.DriverOpts = cloneStringMap(input.DriverOpts)
	}
	if input.Links != nil {
		cloned.Links = append([]string{}, input.Links...)
	}
	return &cloned
}

func backfillEnvValueIfEmpty(env []string, key string, value string) []string {
	prefix := strings.TrimSpace(key) + "="
	value = strings.TrimSpace(value)
	if prefix == "=" || value == "" {
		return env
	}
	firstEmptyIndex := -1
	for idx, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			continue
		}
		if strings.TrimSpace(strings.TrimPrefix(entry, prefix)) != "" {
			return env
		}
		if firstEmptyIndex == -1 {
			firstEmptyIndex = idx
		}
	}
	if firstEmptyIndex >= 0 {
		env[firstEmptyIndex] = prefix + value
		return env
	}
	return append(env, prefix+value)
}
