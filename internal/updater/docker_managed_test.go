package updater

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	dockertypes "github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

func TestBuildReplacementSpecBackfillsCMNodeID(t *testing.T) {
	t.Parallel()

	inspect := testDockerInspectResponse([]string{
		"CM_MODE=agent",
		"CM_SERVER=http://server:8080",
	})

	cfg, hostCfg, netCfg, extraNetworks := buildReplacementSpec(inspect, "example.com/cyber-monitor:1.2.3", "node-abc")

	if got := envValue(cfg.Env, "CM_NODE_ID"); got != "node-abc" {
		t.Fatalf("expected CM_NODE_ID to be backfilled to %q, got %q (env=%v)", "node-abc", got, cfg.Env)
	}
	if hostCfg.RestartPolicy.Name != "unless-stopped" {
		t.Fatalf("expected restart policy to be preserved, got %q", hostCfg.RestartPolicy.Name)
	}
	if len(hostCfg.Mounts) != 1 || hostCfg.Mounts[0].Target != "/data" {
		t.Fatalf("expected mounts to be preserved, got %+v", hostCfg.Mounts)
	}
	if netCfg.EndpointsConfig == nil || netCfg.EndpointsConfig["bridge"] == nil {
		t.Fatalf("expected primary network config to be preserved, got %+v", netCfg.EndpointsConfig)
	}
	if len(extraNetworks) != 1 || extraNetworks["monitoring"] == nil {
		t.Fatalf("expected extra networks to be preserved, got %+v", extraNetworks)
	}
}

func TestBuildReplacementSpecPreservesExistingCMNodeID(t *testing.T) {
	t.Parallel()

	inspect := testDockerInspectResponse([]string{
		"CM_MODE=agent",
		"CM_NODE_ID=old-node",
	})

	cfg, _, _, _ := buildReplacementSpec(inspect, "example.com/cyber-monitor:1.2.3", "node-abc")

	if got := envValue(cfg.Env, "CM_NODE_ID"); got != "old-node" {
		t.Fatalf("expected existing CM_NODE_ID to be preserved, got %q (env=%v)", got, cfg.Env)
	}
	if got := countEnvKey(cfg.Env, "CM_NODE_ID"); got != 1 {
		t.Fatalf("expected exactly one CM_NODE_ID entry, got %d (env=%v)", got, cfg.Env)
	}
}

func TestBuildReplacementSpecBackfillsWhenExistingCMNodeIDEmpty(t *testing.T) {
	t.Parallel()

	inspect := testDockerInspectResponse([]string{
		"CM_MODE=agent",
		"CM_NODE_ID=",
	})

	cfg, _, _, _ := buildReplacementSpec(inspect, "example.com/cyber-monitor:1.2.3", "node-abc")

	if got := envValue(cfg.Env, "CM_NODE_ID"); got != "node-abc" {
		t.Fatalf("expected empty CM_NODE_ID to be backfilled to %q, got %q (env=%v)", "node-abc", got, cfg.Env)
	}
	if got := countEnvKey(cfg.Env, "CM_NODE_ID"); got != 1 {
		t.Fatalf("expected exactly one CM_NODE_ID entry after backfill, got %d (env=%v)", got, cfg.Env)
	}
}

func TestLaunchSelfContainerUpdatePassesHelperNodeIDEnv(t *testing.T) {
	t.Parallel()

	socketFile, err := os.CreateTemp("/tmp", "cm-docker-*.sock")
	if err != nil {
		t.Fatalf("create temp socket path: %v", err)
	}
	socketPath := socketFile.Name()
	if err := socketFile.Close(); err != nil {
		t.Fatalf("close temp socket file: %v", err)
	}
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("remove temp socket file: %v", err)
	}
	defer os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	type createPayload struct {
		Image      string   `json:"Image"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		User       string   `json:"User"`
		Env        []string `json:"Env"`
	}

	var (
		mu            sync.Mutex
		createdConfig createPayload
		createCalled  bool
		startCalled   bool
	)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/containers/create"):
				defer r.Body.Close()
				var payload createPayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("decode create payload: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				createCalled = true
				createdConfig = payload
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"Id":"helper-123","Warnings":null}`))
			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/helper-123/start"):
				mu.Lock()
				startCalled = true
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Errorf("unexpected docker api call: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Shutdown(context.Background())
	}()

	cli, err := client.NewClientWithOpts(client.WithHost("unix://"+socketPath), client.WithVersion("1.43"))
	if err != nil {
		t.Fatalf("new docker client: %v", err)
	}
	defer cli.Close()

	updater := &DockerManagedUpdater{
		socketSource:     "/host/var/run/docker.sock",
		containerID:      "container-123",
		containerName:    "cyber-monitor-agent",
		helperImage:      "example.com/cyber-monitor:1.0.0",
		helperEntrypoint: []string{"/app/cyber-monitor"},
		cli:              cli,
	}

	if err := updater.LaunchSelfContainerUpdate(context.Background(), "example.com/cyber-monitor:1.2.3", "node-abc"); err != nil {
		t.Fatalf("launch self container update: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !createCalled {
		t.Fatal("expected helper container create to be called")
	}
	if !startCalled {
		t.Fatal("expected helper container start to be called")
	}
	if got := envValue(createdConfig.Env, dockerHelperNodeIDEnv); got != "node-abc" {
		t.Fatalf("expected helper env %s=node-abc, got %q (env=%v)", dockerHelperNodeIDEnv, got, createdConfig.Env)
	}
	if got := envValue(createdConfig.Env, dockerHelperTargetImageEnv); got != "example.com/cyber-monitor:1.2.3" {
		t.Fatalf("expected helper target image env to be preserved, got %q", got)
	}
}

func testDockerInspectResponse(env []string) dockertypes.ContainerJSON {
	return dockertypes.ContainerJSON{
		ContainerJSONBase: &dockercontainer.ContainerJSONBase{
			ID:   "1234567890abcdef1234567890abcdef",
			Name: "/cyber-monitor-agent",
			HostConfig: &dockercontainer.HostConfig{
				RestartPolicy: dockercontainer.RestartPolicy{Name: "unless-stopped"},
				NetworkMode:   dockercontainer.NetworkMode("bridge"),
				Mounts: []mount.Mount{{
					Type:   mount.TypeBind,
					Source: "/srv/cyber-monitor/data",
					Target: "/data",
				}},
			},
		},
		Config: &dockercontainer.Config{
			Hostname:   "1234567890ab",
			Image:      "example.com/cyber-monitor:1.0.0",
			Env:        append([]string{}, env...),
			Cmd:        []string{"agent"},
			Entrypoint: []string{"/app/cyber-monitor"},
			WorkingDir: "/app",
			Labels: map[string]string{
				"com.cybermonitor.role": "agent",
			},
		},
		NetworkSettings: &dockercontainer.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {
					Aliases: []string{"cm-agent"},
				},
				"monitoring": {
					Aliases: []string{"metrics"},
				},
			},
		},
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func countEnvKey(env []string, key string) int {
	prefix := key + "="
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			count++
		}
	}
	return count
}
