package server

import (
	"strings"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestAgentConfigIncludesPendingUpdateInstruction(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
					ChecksumURL: "https://example.com/checksums.txt",
				},
				AgentUpdateState: "pending",
			},
		},
		nodes: map[string]NodeState{},
	}

	cfg := store.AgentConfig("node-1")
	if cfg.Update == nil {
		t.Fatal("expected agent config to include update instruction")
	}
	if cfg.Update.Version != "1.2.3" {
		t.Fatalf("expected update version 1.2.3, got %q", cfg.Update.Version)
	}
	if cfg.Update.DownloadURL != "https://example.com/agent" {
		t.Fatalf("unexpected update download url %q", cfg.Update.DownloadURL)
	}
}

func TestAgentConfigSuppressesUpdateInstructionDuringActiveLease(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState:      "updating",
				AgentUpdateLeaseUntil: time.Now().Add(5 * time.Minute).Unix(),
			},
		},
		nodes: map[string]NodeState{},
	}

	cfg := store.AgentConfig("node-1")
	if cfg.Update != nil {
		t.Fatalf("expected active lease to suppress update dispatch, got %+v", cfg.Update)
	}
}

func TestAgentConfigRedispatchesUpdateAfterLeaseExpires(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState:      "restarting",
				AgentUpdateLeaseUntil: time.Now().Add(-time.Minute).Unix(),
			},
		},
		nodes: map[string]NodeState{},
	}

	cfg := store.AgentConfig("node-1")
	if cfg.Update == nil {
		t.Fatal("expected expired lease to allow update redispatch")
	}
}

func TestApplyAgentUpdateReportClearsPendingTaskOnSuccess(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState: "pending",
			},
		},
		nodes: map[string]NodeState{},
	}

	store.ApplyAgentUpdateReport("node-1", AgentUpdateReport{
		State:   "succeeded",
		Version: "1.2.3",
		Message: "updated",
	})

	profile := store.profiles["node-1"]
	if profile == nil {
		t.Fatal("expected node profile to exist")
	}
	if profile.AgentUpdate != nil {
		t.Fatalf("expected pending update to be cleared, got %+v", profile.AgentUpdate)
	}
	if profile.AgentUpdateState != "succeeded" {
		t.Fatalf("expected update state succeeded, got %q", profile.AgentUpdateState)
	}
	if profile.AgentUpdateTargetVersion != "1.2.3" {
		t.Fatalf("expected target version 1.2.3, got %q", profile.AgentUpdateTargetVersion)
	}
	if profile.AgentUpdateMessage != "updated" {
		t.Fatalf("expected success message to persist, got %q", profile.AgentUpdateMessage)
	}
}

func TestApplyAgentUpdateReportSetsLeaseForActiveStates(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState: "pending",
			},
		},
		nodes: map[string]NodeState{},
	}

	store.ApplyAgentUpdateReport("node-1", AgentUpdateReport{
		State:   "updating",
		Version: "1.2.3",
		Message: "downloading",
	})

	profile := store.profiles["node-1"]
	if profile.AgentUpdate == nil {
		t.Fatal("expected active update instruction to remain queued during updating state")
	}
	if profile.AgentUpdateLeaseUntil <= time.Now().Unix() {
		t.Fatalf("expected active lease to be extended, got %d", profile.AgentUpdateLeaseUntil)
	}
}

func TestStoreUpdateAutoCompletesAgentUpdateWhenTargetVersionReported(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState:         "restarting",
				AgentUpdateTargetVersion: "1.2.3",
				AgentUpdateLeaseUntil:    time.Now().Add(5 * time.Minute).Unix(),
			},
		},
		nodes:           map[string]NodeState{},
		alerted:         map[string]alertState{},
		offlineSessions: map[string]OfflineSessionState{},
		testHistory:     map[string]map[string]*TestHistoryEntry{},
		loginAttempts:   map[string]*loginAttempt{},
	}

	reconciled := store.Update(metrics.NodeStats{
		NodeID:       "node-1",
		NodeName:     "node-1",
		Hostname:     "node-1",
		OS:           "linux",
		Arch:         "amd64",
		AgentVersion: "1.2.3",
		Timestamp:    time.Now().Unix(),
	})
	if !reconciled {
		t.Fatal("expected matching target version to auto-complete queued update")
	}

	profile := store.profiles["node-1"]
	if profile.AgentUpdate != nil {
		t.Fatalf("expected queued update to be cleared, got %+v", profile.AgentUpdate)
	}
	if profile.AgentUpdateState != "succeeded" {
		t.Fatalf("expected auto-complete state succeeded, got %q", profile.AgentUpdateState)
	}
	if profile.AgentUpdateLeaseUntil != 0 {
		t.Fatalf("expected lease to be cleared, got %d", profile.AgentUpdateLeaseUntil)
	}
	if !strings.Contains(profile.AgentUpdateMessage, "自动完成更新任务收口") {
		t.Fatalf("unexpected auto-complete message: %q", profile.AgentUpdateMessage)
	}
}

func TestApplyAgentUpdateReportClearsPendingTaskOnDisableReject(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings: initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		profiles: map[string]*NodeProfile{
			"node-1": {
				TestIntervalSec: defaultTestIntervalSec,
				AgentUpdate: &AgentUpdateInstruction{
					Version:     "1.2.3",
					DownloadURL: "https://example.com/agent",
				},
				AgentUpdateState: "pending",
			},
		},
		nodes: map[string]NodeState{},
	}

	store.ApplyAgentUpdateReport("node-1", AgentUpdateReport{
		State:   "failed",
		Version: "1.2.3",
		Message: "当前 Agent 已禁用远程更新",
	})

	profile := store.profiles["node-1"]
	if profile.AgentUpdate != nil {
		t.Fatalf("expected pending update to be cleared after disable reject, got %+v", profile.AgentUpdate)
	}
	if profile.AgentUpdateMessage != "当前 Agent 已禁用远程更新" {
		t.Fatalf("unexpected reject message: %q", profile.AgentUpdateMessage)
	}
}

func TestResolveAgentUpdateSupportedRejectsDisabledOrDockerNodes(t *testing.T) {
	t.Parallel()

	if resolveAgentUpdateSupported(metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "docker",
		DockerManagedUpdate: false,
		AgentUpdateDisabled: false,
	}) {
		t.Fatal("expected docker deploy mode to disable agent self update")
	}

	if !resolveAgentUpdateSupported(metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "docker",
		DockerManagedUpdate: true,
		AgentUpdateDisabled: false,
	}) {
		t.Fatal("expected docker managed agent node to allow background update")
	}

	if resolveAgentUpdateSupported(metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "binary",
		AgentUpdateDisabled: true,
	}) {
		t.Fatal("expected disable-update agent to reject remote update")
	}
}

func TestResolveAgentUpdateModeReturnsDockerManagedWhenAvailable(t *testing.T) {
	t.Parallel()

	mode := resolveAgentUpdateMode(metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "docker",
		DockerManagedUpdate: true,
	})
	if mode != "docker-managed" {
		t.Fatalf("expected docker-managed mode, got %q", mode)
	}
}

func TestResolveAgentUpdateViewUsesUnsupportedReasonWhenMessageIsEmpty(t *testing.T) {
	t.Parallel()

	supported, mode, _, _, message := resolveAgentUpdateView(&NodeProfile{}, metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "docker",
		DockerManagedUpdate: false,
		AgentUpdateDisabled: false,
	})
	if supported {
		t.Fatal("expected docker unmanaged node to be unsupported")
	}
	if mode != "docker" {
		t.Fatalf("expected docker mode, got %q", mode)
	}
	if message == "" || !strings.Contains(message, "docker.sock") {
		t.Fatalf("expected docker socket guidance, got %q", message)
	}
}
