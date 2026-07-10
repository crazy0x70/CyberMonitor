package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/nat"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	dockerSocketEnvKey             = "CM_DOCKER_SOCKET"
	dockerUpdateOptInEnvKey        = "CM_ENABLE_DOCKER_UPDATE"
	containerIDEnvKey              = "CM_CONTAINER_ID"
	containerVersionEnvKey         = "CM_VERSION"
	containerCommitEnvKey          = "CM_COMMIT"
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
	dockerReplacementReadyTimeout  = 120 * time.Second
	dockerReplacementReadyInterval = 2 * time.Second
	dockerCleanupTimeout           = 30 * time.Second
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

type dockerContainerRollbackClient interface {
	ContainerRemove(context.Context, string, container.RemoveOptions) error
	ContainerRename(context.Context, string, string) error
	ContainerStart(context.Context, string, container.StartOptions) error
	NetworkDisconnect(context.Context, string, string, bool) error
}

type dockerContainerInspectClient interface {
	ContainerInspect(context.Context, string) (dockertypes.ContainerJSON, error)
}

type dockerImageInspectClient interface {
	ImageInspect(context.Context, string, ...client.ImageInspectOption) (image.InspectResponse, error)
}

type dockerUpdateHelperClient interface {
	ContainerCreate(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, *ocispec.Platform, string) (container.CreateResponse, error)
	ContainerRemove(context.Context, string, container.RemoveOptions) error
	ContainerStart(context.Context, string, container.StartOptions) error
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

func ResolveDockerTargetImage(currentImage, targetVersion string) (string, error) {
	currentImage = strings.TrimSpace(currentImage)
	targetVersion = strings.TrimSpace(targetVersion)
	if currentImage == "" {
		return "", fmt.Errorf("当前 Docker 镜像为空")
	}
	if targetVersion == "" {
		return "", fmt.Errorf("目标版本为空")
	}
	ref, err := reference.ParseAnyReference(currentImage)
	if err != nil {
		return "", fmt.Errorf("解析当前 Docker 镜像 %q 失败: %w", currentImage, err)
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return "", fmt.Errorf("当前 Docker 镜像 %q 不是可打标签的仓库引用", currentImage)
	}
	if !strings.HasPrefix(targetVersion, "v") {
		targetVersion = "v" + targetVersion
	}
	targetRef, err := reference.WithTag(reference.TrimNamed(named), targetVersion)
	if err != nil {
		return "", fmt.Errorf("生成目标 Docker 镜像标签失败: %w", err)
	}
	return targetRef.String(), nil
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
	if err := requireDockerManagedUpdateOptIn(); err != nil {
		return dockerManagedProbe{}, err
	}
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
	if err := requireDockerManagedUpdateOptIn(); err != nil {
		return dockerManagedProbe{}, err
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

func requireDockerManagedUpdateOptIn() error {
	if strings.TrimSpace(os.Getenv(dockerUpdateOptInEnvKey)) == "1" {
		return nil
	}
	return fmt.Errorf("Docker 更新未显式启用，请设置 %s=1 并挂载 docker.sock", dockerUpdateOptInEnvKey)
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
		return nil, fmt.Errorf("Docker 一键更新不可用: %w", err)
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
	helperName, config, hostConfig := u.buildDockerUpdateHelperSpec(targetImage, currentNodeID, time.Now())
	_, err := launchDockerUpdateHelperDetached(ctx, u.cli, helperName, config, hostConfig)
	return err
}

func launchDockerUpdateHelperDetached(ctx context.Context, cli dockerUpdateHelperClient, helperName string, config *container.Config, hostConfig *container.HostConfig) (string, error) {
	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, helperName)
	if err != nil {
		return "", fmt.Errorf("创建 Docker 更新 helper 失败: %w", err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), dockerCleanupTimeout)
		defer cleanupCancel()
		if removeErr := cli.ContainerRemove(cleanupCtx, resp.ID, container.RemoveOptions{Force: true}); removeErr != nil && !errdefs.IsNotFound(removeErr) {
			return "", fmt.Errorf("启动 Docker 更新 helper 失败: %w；清理未启动 helper 失败: %w", err, removeErr)
		}
		return "", fmt.Errorf("启动 Docker 更新 helper 失败: %w", err)
	}
	return resp.ID, nil
}

func (u *DockerManagedUpdater) buildDockerUpdateHelperSpec(targetImage string, currentNodeID string, now time.Time) (string, *container.Config, *container.HostConfig) {
	helperName := fmt.Sprintf("cm-update-helper-%s-%d", sanitizeContainerName(u.containerName), now.Unix())
	config := &container.Config{
		Image:      u.helperImage,
		Entrypoint: append([]string{}, u.helperEntrypoint...),
		Cmd:        []string{dockerHelperCommand},
		User:       "0",
		Env: []string{
			dockerUpdateOptInEnvKey + "=1",
			fmt.Sprintf("%s=%s", dockerSocketEnvKey, dockerHelperMountTarget),
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
	return helperName, config, hostConfig
}

func RunDockerRecreateHelper(ctx context.Context) (err error) {
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
	targetImageID, err := resolveDockerImageID(ctx, cli, targetImage)
	if err != nil {
		return err
	}
	tempName := fmt.Sprintf("%s-next-%d", sanitizeContainerName(strings.TrimPrefix(inspect.Name, "/")), time.Now().Unix())
	cfg, hostCfg, netCfg, extraNetworks := buildReplacementSpec(inspect, targetImage, currentNodeID)
	created, err := cli.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, tempName)
	if err != nil {
		return fmt.Errorf("创建替换容器失败: %w", err)
	}
	originalName := strings.TrimPrefix(inspect.Name, "/")
	rollbackReplacement := true
	oldStopped := false
	oldRenamed := false
	connectedExtraNetworks := []string{}
	defer func() {
		if !rollbackReplacement {
			return
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), dockerCleanupTimeout)
		defer rollbackCancel()
		rollbackErr := rollbackCreatedContainer(rollbackCtx, cli, created.ID, inspect.ID, originalName, oldStopped, oldRenamed, connectedExtraNetworks)
		err = appendDockerRollbackError(err, rollbackErr)
	}()
	if verifyErr := verifyReplacementContainerImage(ctx, cli, created.ID, targetImageID); verifyErr != nil {
		err = verifyErr
		return err
	}
	for networkName, endpoint := range extraNetworks {
		if connectErr := cli.NetworkConnect(ctx, networkName, created.ID, endpoint); connectErr != nil {
			err = fmt.Errorf("连接附加网络 %s 失败: %w", networkName, connectErr)
			return err
		}
		connectedExtraNetworks = append(connectedExtraNetworks, networkName)
	}
	timeout := 20
	if stopErr := cli.ContainerStop(ctx, inspect.ID, container.StopOptions{Timeout: &timeout}); stopErr != nil {
		err = fmt.Errorf("停止旧容器失败: %w", stopErr)
		return err
	}
	oldStopped = true
	backupName := fmt.Sprintf("%s-prev-%d", sanitizeContainerName(originalName), time.Now().Unix())
	if renameErr := cli.ContainerRename(ctx, inspect.ID, backupName); renameErr != nil {
		err = fmt.Errorf("备份旧容器名称失败: %w", renameErr)
		return err
	}
	oldRenamed = true
	if renameErr := cli.ContainerRename(ctx, created.ID, originalName); renameErr != nil {
		err = fmt.Errorf("恢复容器名称失败: %w", renameErr)
		return err
	}
	if startErr := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); startErr != nil {
		err = fmt.Errorf("启动新容器失败: %w", startErr)
		return err
	}
	if readyErr := waitReplacementContainerReady(ctx, cli, created.ID); readyErr != nil {
		err = fmt.Errorf("替换容器未就绪: %w", readyErr)
		return err
	}
	rollbackReplacement = false
	if cleanupErr := cleanupOldContainerAfterReplacement(ctx, cli, inspect.ID); cleanupErr != nil {
		return cleanupErr
	}
	return nil
}

func cleanupOldContainerAfterReplacement(ctx context.Context, cli dockerContainerRollbackClient, oldID string) error {
	if removeErr := cli.ContainerRemove(ctx, oldID, container.RemoveOptions{Force: true}); removeErr != nil {
		if errdefs.IsNotFound(removeErr) {
			log.Printf("Docker 更新已完成，旧容器已不存在 container=%s", oldID)
			return nil
		}
		log.Printf("Docker 更新已完成，但清理旧容器失败 container=%s: %v", oldID, removeErr)
		return fmt.Errorf("清理旧容器失败: %w", removeErr)
	}
	return nil
}

func rollbackCreatedContainer(ctx context.Context, cli dockerContainerRollbackClient, createdID string, oldID string, originalName string, oldStopped bool, oldRenamed bool, connectedNetworks []string) error {
	errs := []error{}
	for i := len(connectedNetworks) - 1; i >= 0; i-- {
		networkName := strings.TrimSpace(connectedNetworks[i])
		if networkName == "" {
			continue
		}
		if disconnectErr := cli.NetworkDisconnect(ctx, networkName, createdID, true); disconnectErr != nil && !errdefs.IsNotFound(disconnectErr) {
			errs = append(errs, fmt.Errorf("断开替换容器附加网络 %s 失败: %w", networkName, disconnectErr))
		}
	}
	if removeErr := cli.ContainerRemove(ctx, createdID, container.RemoveOptions{Force: true}); removeErr != nil {
		errs = append(errs, fmt.Errorf("删除替换容器失败: %w", removeErr))
	}
	if oldRenamed {
		if renameErr := cli.ContainerRename(ctx, oldID, originalName); renameErr != nil {
			errs = append(errs, fmt.Errorf("恢复旧容器名称失败: %w", renameErr))
		}
		if startErr := cli.ContainerStart(ctx, oldID, container.StartOptions{}); startErr != nil {
			errs = append(errs, fmt.Errorf("重启旧容器失败: %w", startErr))
		}
		return errors.Join(errs...)
	}
	if oldStopped {
		if startErr := cli.ContainerStart(ctx, oldID, container.StartOptions{}); startErr != nil {
			errs = append(errs, fmt.Errorf("重启旧容器失败: %w", startErr))
		}
	}
	return errors.Join(errs...)
}

func appendDockerRollbackError(err error, rollbackErr error) error {
	if rollbackErr == nil {
		return err
	}
	if err == nil {
		return fmt.Errorf("Docker 更新回滚失败: %w", rollbackErr)
	}
	return fmt.Errorf("%w；Docker 更新回滚失败: %w", err, rollbackErr)
}

func waitReplacementContainerReady(ctx context.Context, cli dockerContainerInspectClient, containerID string) error {
	return waitReplacementContainerReadyFor(ctx, cli, containerID, dockerReplacementReadyTimeout, dockerReplacementReadyInterval)
}

func verifyReplacementContainerImage(ctx context.Context, cli dockerContainerInspectClient, containerID string, expectedImageID string) error {
	expectedImageID = strings.TrimSpace(expectedImageID)
	if expectedImageID == "" {
		return fmt.Errorf("缺少替换容器期望镜像 ID")
	}
	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("读取替换容器镜像信息失败: %w", err)
	}
	actualImageID := strings.TrimSpace(inspect.Image)
	if actualImageID == "" {
		return fmt.Errorf("替换容器缺少镜像 ID")
	}
	if actualImageID != expectedImageID {
		return fmt.Errorf("替换容器镜像 ID 不匹配: got %s, want %s", actualImageID, expectedImageID)
	}
	return nil
}

func waitReplacementContainerReadyFor(ctx context.Context, cli dockerContainerInspectClient, containerID string, timeout time.Duration, interval time.Duration) error {
	if timeout <= 0 {
		timeout = dockerReplacementReadyTimeout
	}
	if interval <= 0 {
		interval = dockerReplacementReadyInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	runningWithoutHealthcheckSeen := false
	for {
		inspect, err := cli.ContainerInspect(waitCtx, containerID)
		if err != nil {
			if waitErr := waitCtx.Err(); waitErr != nil {
				if waitErr == context.DeadlineExceeded {
					return fmt.Errorf("替换容器未在 %s 内就绪", timeout)
				}
				return waitErr
			}
			return fmt.Errorf("读取替换容器状态失败: %w", err)
		}
		ready, err := replacementContainerReady(inspect)
		if err != nil {
			return err
		}
		if ready {
			if replacementContainerHasEffectiveHealthcheck(inspect) {
				return nil
			}
			if runningWithoutHealthcheckSeen {
				return nil
			}
			runningWithoutHealthcheckSeen = true
		} else {
			runningWithoutHealthcheckSeen = false
		}
		select {
		case <-waitCtx.Done():
			if waitCtx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("替换容器未在 %s 内就绪", timeout)
			}
			return waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func replacementContainerReady(inspect dockertypes.ContainerJSON) (bool, error) {
	state := inspect.State
	if state == nil {
		return false, fmt.Errorf("替换容器缺少 State 信息")
	}
	if errText := strings.TrimSpace(state.Error); errText != "" {
		return false, fmt.Errorf("替换容器错误: %s", errText)
	}
	switch strings.TrimSpace(state.Status) {
	case container.StateExited:
		return false, fmt.Errorf("替换容器已退出: exit code %d", state.ExitCode)
	case container.StateDead:
		return false, fmt.Errorf("替换容器处于 dead 状态")
	}
	if state.Health != nil {
		switch strings.ToLower(strings.TrimSpace(state.Health.Status)) {
		case container.Healthy:
			return state.Running, nil
		case container.Unhealthy:
			return false, fmt.Errorf("替换容器 healthcheck 失败")
		case container.Starting:
			return false, nil
		case container.NoHealthcheck, "":
		default:
			return false, fmt.Errorf("替换容器 healthcheck 状态未知: %s", state.Health.Status)
		}
	}
	if state.Running {
		return true, nil
	}
	return false, nil
}

func replacementContainerHasEffectiveHealthcheck(inspect dockertypes.ContainerJSON) bool {
	state := inspect.State
	if state == nil || state.Health == nil {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(state.Health.Status))
	return status != "" && status != container.NoHealthcheck
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
	env := sanitizeReplacementEnv(inspect.Config.Env)
	env = backfillEnvValueIfEmpty(env, "CM_NODE_ID", currentNodeID)
	cfg := &container.Config{
		Hostname:     hostname,
		Image:        targetImage,
		Env:          env,
		Cmd:          append([]string{}, inspect.Config.Cmd...),
		Entrypoint:   append([]string{}, inspect.Config.Entrypoint...),
		Healthcheck:  cloneHealthConfig(inspect.Config.Healthcheck),
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
	hostCfg.Binds = append([]string{}, inspect.HostConfig.Binds...)
	hostCfg.RestartPolicy = inspect.HostConfig.RestartPolicy
	hostCfg.AutoRemove = false
	hostCfg.PortBindings = clonePortMap(inspect.HostConfig.PortBindings)
	hostCfg.VolumesFrom = append([]string{}, inspect.HostConfig.VolumesFrom...)
	hostCfg.Annotations = cloneStringMap(inspect.HostConfig.Annotations)
	hostCfg.CapAdd = append([]string{}, inspect.HostConfig.CapAdd...)
	hostCfg.CapDrop = append([]string{}, inspect.HostConfig.CapDrop...)
	hostCfg.DNS = append([]string{}, inspect.HostConfig.DNS...)
	hostCfg.DNSOptions = append([]string{}, inspect.HostConfig.DNSOptions...)
	hostCfg.DNSSearch = append([]string{}, inspect.HostConfig.DNSSearch...)
	hostCfg.ExtraHosts = append([]string{}, inspect.HostConfig.ExtraHosts...)
	hostCfg.GroupAdd = append([]string{}, inspect.HostConfig.GroupAdd...)
	hostCfg.Links = append([]string{}, inspect.HostConfig.Links...)
	hostCfg.SecurityOpt = append([]string{}, inspect.HostConfig.SecurityOpt...)
	hostCfg.StorageOpt = cloneStringMap(inspect.HostConfig.StorageOpt)
	hostCfg.Tmpfs = cloneStringMap(inspect.HostConfig.Tmpfs)
	hostCfg.Sysctls = cloneStringMap(inspect.HostConfig.Sysctls)
	hostCfg.Mounts = append([]mount.Mount{}, inspect.HostConfig.Mounts...)
	hostCfg.MaskedPaths = append([]string{}, inspect.HostConfig.MaskedPaths...)
	hostCfg.ReadonlyPaths = append([]string{}, inspect.HostConfig.ReadonlyPaths...)
	netCfg, extraNetworks := buildReplacementNetworking(inspect)
	return cfg, &hostCfg, netCfg, extraNetworks
}

func sanitizeReplacementEnv(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.TrimSpace(key) {
		case containerIDEnvKey, containerVersionEnvKey, containerCommitEnvKey:
			// Let the replacement container resolve its own identity and baked version metadata.
			continue
		default:
			filtered = append(filtered, entry)
		}
	}
	return filtered
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
	if _, ok := networks[mode]; ok {
		return mode
	}
	if mode == "default" {
		if _, ok := networks["bridge"]; ok {
			return "bridge"
		}
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
	decoder := json.NewDecoder(reader)
	for {
		var event struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("读取 Docker 拉取响应失败: %w", err)
		}
		message := strings.TrimSpace(event.Error)
		if message == "" {
			message = strings.TrimSpace(event.ErrorDetail.Message)
		}
		if message != "" {
			return fmt.Errorf("拉取目标镜像失败: %s", message)
		}
	}
}

func resolveDockerImageID(ctx context.Context, cli dockerImageInspectClient, imageRef string) (string, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return "", fmt.Errorf("目标镜像为空")
	}
	inspect, err := cli.ImageInspect(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("读取目标镜像 ID 失败: %w", err)
	}
	imageID := normalizeDockerImageID(inspect.ID)
	if imageID == "" {
		return "", fmt.Errorf("目标镜像缺少有效 image ID")
	}
	return imageID, nil
}

func normalizeDockerImageID(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") {
		return ""
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if len(digest) != 64 {
		return ""
	}
	for _, char := range digest {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			continue
		}
		return ""
	}
	return value
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

func cloneHealthConfig(input *container.HealthConfig) *container.HealthConfig {
	if input == nil {
		return nil
	}
	cloned := *input
	if len(input.Test) > 0 {
		cloned.Test = append([]string{}, input.Test...)
	}
	return &cloned
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

func clonePortMap(input nat.PortMap) nat.PortMap {
	if len(input) == 0 {
		return nil
	}
	cloned := make(nat.PortMap, len(input))
	for port, bindings := range input {
		cloned[port] = append([]nat.PortBinding{}, bindings...)
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
	cloned := &network.EndpointSettings{
		IPAMConfig: cloneEndpointIPAMConfig(input.IPAMConfig),
		MacAddress: input.MacAddress,
		GwPriority: input.GwPriority,
	}
	if len(input.Aliases) > 0 {
		cloned.Aliases = append([]string{}, input.Aliases...)
	}
	if input.DriverOpts != nil {
		cloned.DriverOpts = cloneStringMap(input.DriverOpts)
	}
	if input.Links != nil {
		cloned.Links = append([]string{}, input.Links...)
	}
	return cloned
}

func cloneEndpointIPAMConfig(input *network.EndpointIPAMConfig) *network.EndpointIPAMConfig {
	if input == nil {
		return nil
	}
	cloned := *input
	if len(input.LinkLocalIPs) > 0 {
		cloned.LinkLocalIPs = append([]string{}, input.LinkLocalIPs...)
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
