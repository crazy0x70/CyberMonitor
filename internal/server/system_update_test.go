package server

import (
	"context"
	"testing"
	"time"

	"cyber_monitor/internal/updater"
)

func TestSystemUpdateManagerStartResetsUpdatingAfterSuccess(t *testing.T) {
	t.Parallel()

	manager := newSystemUpdateManager("1.0.0")
	info := updater.ReleaseInfo{
		CurrentVersion: "1.0.0",
		LatestVersion:  "1.1.0",
		HasUpdate:      true,
	}

	if err := manager.Start(info, func() error { return nil }); err != nil {
		t.Fatalf("start update: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		view := manager.View(context.Background(), false)
		if !view.Updating {
			if view.Message == "" {
				t.Fatal("expected completion message after successful update")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("expected successful update to clear updating state")
}

func TestSystemUpdateViewMarksDockerModeUnsupported(t *testing.T) {
	t.Setenv("CM_DEPLOY_MODE", "docker")

	manager := newSystemUpdateManager("1.0.0")
	view := manager.View(context.Background(), false)
	if view.Supported {
		t.Fatal("expected docker deploy mode to disable service self update")
	}
	if view.Mode != string(updater.DeployModeDocker) {
		t.Fatalf("expected mode %q, got %q", updater.DeployModeDocker, view.Mode)
	}
}
