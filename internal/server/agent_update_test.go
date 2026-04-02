package server

import (
	"testing"

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
		AgentUpdateDisabled: false,
	}) {
		t.Fatal("expected docker deploy mode to disable agent self update")
	}

	if resolveAgentUpdateSupported(metrics.NodeStats{
		OS:                  "Linux",
		DeployMode:          "binary",
		AgentUpdateDisabled: true,
	}) {
		t.Fatal("expected disable-update agent to reject remote update")
	}
}
