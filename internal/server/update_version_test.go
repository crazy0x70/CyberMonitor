package server

import "testing"

func TestSettingsAndPublicSettingsExposeBuildVersion(t *testing.T) {
	t.Parallel()

	store := &Store{
		settings:     initSettings(Config{AdminUser: "admin", AdminPass: "pass"}),
		buildCommit:  "abcdef1",
		buildVersion: "1.2.3",
	}

	settingsView := store.SettingsView()
	if settingsView.Version != "1.2.3" {
		t.Fatalf("expected settings view version 1.2.3, got %q", settingsView.Version)
	}
	if settingsView.Commit != "abcdef1" {
		t.Fatalf("expected settings view commit abcdef1, got %q", settingsView.Commit)
	}

	publicSettings := store.PublicSettings()
	if publicSettings.Version != "1.2.3" {
		t.Fatalf("expected public settings version 1.2.3, got %q", publicSettings.Version)
	}
	if publicSettings.Commit != "abcdef1" {
		t.Fatalf("expected public settings commit abcdef1, got %q", publicSettings.Commit)
	}
}
