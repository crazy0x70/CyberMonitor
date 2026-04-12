package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestResolveNodeIDPrefersExplicitValueOverAllSources(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()
	explicitFileDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())
	explicitFile := filepath.Join(explicitFileDir, "node-id.txt")

	mustWriteFile(t, homeFile, "home-node\n")
	mustWriteFile(t, legacyFile, "legacy-node\n")
	mustWriteFile(t, explicitFile, "file-node\n")

	got, err := ResolveNodeID(NodeIDOptions{
		Explicit:     " explicit-node ",
		ExplicitFile: explicitFile,
		LegacyPath:   legacyFile,
	})
	if err != nil {
		t.Fatalf("ResolveNodeID() error = %v", err)
	}
	if got != "explicit-node" {
		t.Fatalf("ResolveNodeID() = %q, want %q", got, "explicit-node")
	}
}

func TestResolveNodeIDPrefersExplicitFileBeforeHomeAndLegacy(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()
	explicitFileDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())
	explicitFile := filepath.Join(explicitFileDir, "node-id.txt")

	mustWriteFile(t, homeFile, "home-node\n")
	mustWriteFile(t, legacyFile, "legacy-node\n")
	mustWriteFile(t, explicitFile, "file-node\n")

	got, err := ResolveNodeID(NodeIDOptions{
		ExplicitFile: explicitFile,
		LegacyPath:   legacyFile,
	})
	if err != nil {
		t.Fatalf("ResolveNodeID() error = %v", err)
	}
	if got != "file-node" {
		t.Fatalf("ResolveNodeID() = %q, want %q", got, "file-node")
	}
}

func TestResolveNodeIDPrefersHomeFileBeforeLegacyPath(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	mustWriteFile(t, homeFile, "home-node\n")
	mustWriteFile(t, legacyFile, "legacy-node\n")

	got, err := ResolveNodeID(NodeIDOptions{LegacyPath: legacyFile})
	if err != nil {
		t.Fatalf("ResolveNodeID() error = %v", err)
	}
	if got != "home-node" {
		t.Fatalf("ResolveNodeID() = %q, want %q", got, "home-node")
	}
	if gotHome := mustReadTrimmedFile(t, homeFile); gotHome != "home-node" {
		t.Fatalf("home file = %q, want %q", gotHome, "home-node")
	}
}

func TestResolveNodeIDMigratesLegacyFileToHome(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	mustWriteFile(t, legacyFile, "legacy-node\n")

	got, err := ResolveNodeID(NodeIDOptions{LegacyPath: legacyFile})
	if err != nil {
		t.Fatalf("ResolveNodeID() error = %v", err)
	}
	if got != "legacy-node" {
		t.Fatalf("ResolveNodeID() = %q, want %q", got, "legacy-node")
	}
	if gotHome := mustReadTrimmedFile(t, homeFile); gotHome != "legacy-node" {
		t.Fatalf("home file = %q, want %q", gotHome, "legacy-node")
	}
}

func TestResolveNodeIDReturnsErrorWhenLegacyMigrationCannotWriteHomeFile(t *testing.T) {
	baseDir := t.TempDir()
	legacyDir := t.TempDir()
	homeAsFile := filepath.Join(baseDir, "home-as-file")
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	t.Setenv("HOME", homeAsFile)
	mustWriteFile(t, homeAsFile, "not-a-directory\n")
	mustWriteFile(t, legacyFile, "legacy-node\n")

	got, err := ResolveNodeID(NodeIDOptions{LegacyPath: legacyFile})
	if err == nil {
		t.Fatalf("ResolveNodeID() error = nil, want non-nil, got nodeID=%q", got)
	}
}

func TestResolveNodeIDReturnsErrNotExistWhenNoSourceExists(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()

	t.Setenv("HOME", home)

	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	_, err := ResolveNodeID(NodeIDOptions{LegacyPath: legacyFile})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ResolveNodeID() error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestResolveOrCreateNodeIDCreatesUUIDInExplicitFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	explicitFile := filepath.Join(t.TempDir(), "node-id.txt")

	got, err := ResolveOrCreateNodeID("", explicitFile)
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeID() error = %v", err)
	}
	if _, err := uuid.Parse(got); err != nil {
		t.Fatalf("ResolveOrCreateNodeID() = %q, want valid UUID: %v", got, err)
	}
	if gotFile := mustReadTrimmedFile(t, explicitFile); gotFile != got {
		t.Fatalf("explicit file = %q, want %q", gotFile, got)
	}
}

func TestResolveOrCreateNodeIDGeneratesUUIDOnlyOnFirstCreation(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	first, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{LegacyPath: legacyFile})
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() first error = %v", err)
	}
	if _, err := uuid.Parse(first); err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() first = %q, want valid UUID: %v", first, err)
	}

	second, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{LegacyPath: legacyFile})
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() second error = %v", err)
	}
	if second != first {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() second = %q, want %q", second, first)
	}
	if gotHome := mustReadTrimmedFile(t, homeFile); gotHome != first {
		t.Fatalf("home file = %q, want %q", gotHome, first)
	}
}

func TestResolveNodeIDUsesStableDockerFingerprintWhenNoFilesExist(t *testing.T) {
	home := t.TempDir()
	hostRoot := t.TempDir()
	legacyFile := filepath.Join(t.TempDir(), "legacy-node-id")

	t.Setenv("HOME", home)
	mustWriteFile(t, filepath.Join(hostRoot, "etc", "machine-id"), "docker-host-machine-id\n")

	got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{
		IsDocker:   true,
		HostRoot:   hostRoot,
		LegacyPath: legacyFile,
	})
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v", err)
	}

	want := uuid.NewSHA1(uuid.NameSpaceURL, []byte("cybermonitor-node:docker-host-machine-id")).String()
	if got != want {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() = %q, want %q", got, want)
	}
}

func TestResolveNodeIDUsesSameDockerFingerprintAcrossResolutions(t *testing.T) {
	resolve := func(home, hostRoot, fingerprint string) string {
		t.Helper()
		legacyFile := filepath.Join(t.TempDir(), "legacy-node-id")
		t.Setenv("HOME", home)
		mustWriteFile(t, filepath.Join(hostRoot, "etc", "machine-id"), fingerprint+"\n")
		got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{
			IsDocker:   true,
			HostRoot:   hostRoot,
			LegacyPath: legacyFile,
		})
		if err != nil {
			t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v", err)
		}
		return got
	}

	first := resolve(t.TempDir(), t.TempDir(), "stable-fingerprint")
	second := resolve(t.TempDir(), t.TempDir(), "stable-fingerprint")

	if first != second {
		t.Fatalf("same docker fingerprint resolved to different node IDs: %q vs %q", first, second)
	}
}

func TestResolveNodeIDDifferentDockerFingerprintsProduceDifferentIDs(t *testing.T) {
	resolve := func(fingerprint string) string {
		t.Helper()
		t.Setenv("HOME", t.TempDir())
		hostRoot := t.TempDir()
		legacyFile := filepath.Join(t.TempDir(), "legacy-node-id")
		mustWriteFile(t, filepath.Join(hostRoot, "etc", "machine-id"), fingerprint+"\n")
		got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{
			IsDocker:   true,
			HostRoot:   hostRoot,
			LegacyPath: legacyFile,
		})
		if err != nil {
			t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v", err)
		}
		return got
	}

	first := resolve("docker-host-a")
	second := resolve("docker-host-b")

	if first == second {
		t.Fatalf("different docker fingerprints resolved to same node ID %q", first)
	}
}

func TestReadStableHostFingerprintFallsBackWhenFirstCandidateIsUnreadable(t *testing.T) {
	hostRoot := t.TempDir()

	firstCandidate := filepath.Join(hostRoot, "etc", "machine-id")
	if err := os.MkdirAll(firstCandidate, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", firstCandidate, err)
	}
	mustWriteFile(t, filepath.Join(hostRoot, "var", "lib", "dbus", "machine-id"), "dbus-machine-id\n")

	got, err := readStableHostFingerprint(hostRoot)
	if err != nil {
		t.Fatalf("readStableHostFingerprint() error = %v", err)
	}
	if got != "dbus-machine-id" {
		t.Fatalf("readStableHostFingerprint() = %q, want %q", got, "dbus-machine-id")
	}
}

func TestReadStableHostFingerprintReturnsErrNotExistWhenAllCandidatesUnavailable(t *testing.T) {
	hostRoot := t.TempDir()

	for _, path := range []string{
		filepath.Join(hostRoot, "etc", "machine-id"),
		filepath.Join(hostRoot, "var", "lib", "dbus", "machine-id"),
		filepath.Join(hostRoot, "etc", "hostname"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("os.MkdirAll(%q) error = %v", path, err)
		}
	}

	_, err := readStableHostFingerprint(hostRoot)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readStableHostFingerprint() error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestResolveOrCreateNodeIDNonDockerStillGeneratesRandomUUID(t *testing.T) {
	home := t.TempDir()
	hostRoot := t.TempDir()
	legacyFile := filepath.Join(t.TempDir(), "legacy-node-id")
	wantUUID := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	t.Setenv("HOME", home)
	mustWriteFile(t, filepath.Join(hostRoot, "etc", "machine-id"), "docker-host-machine-id\n")

	original := newRandomNodeUUID
	newRandomNodeUUID = func() (uuid.UUID, error) {
		return wantUUID, nil
	}
	defer func() {
		newRandomNodeUUID = original
	}()

	got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{
		IsDocker:   false,
		HostRoot:   hostRoot,
		LegacyPath: legacyFile,
	})
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v", err)
	}

	if got != wantUUID.String() {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() = %q, want %q", got, wantUUID.String())
	}

	fingerprintUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("cybermonitor-node:docker-host-machine-id")).String()
	if got == fingerprintUUID {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() unexpectedly used docker fingerprint UUID %q", got)
	}

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	if gotHome := mustReadTrimmedFile(t, homeFile); gotHome != wantUUID.String() {
		t.Fatalf("home file = %q, want %q", gotHome, wantUUID.String())
	}
}

func TestResolveOrCreateNodeIDPreservesLegacyValueWithoutUUIDRewrite(t *testing.T) {
	home := t.TempDir()
	legacyDir := t.TempDir()

	t.Setenv("HOME", home)

	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	legacyFile := filepath.Join(legacyDir, DefaultNodeIDFileName())

	mustWriteFile(t, legacyFile, "node-legacy-001\n")

	got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{LegacyPath: legacyFile})
	if err != nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v", err)
	}
	if got != "node-legacy-001" {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() = %q, want %q", got, "node-legacy-001")
	}
	if _, err := uuid.Parse(got); err == nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() rewrote legacy node id %q into UUID-like value", got)
	}
	if gotHome := mustReadTrimmedFile(t, homeFile); gotHome != "node-legacy-001" {
		t.Fatalf("home file = %q, want %q", gotHome, "node-legacy-001")
	}
}

func TestResolveOrCreateNodeIDReturnsErrorWhenUUIDGenerationFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	original := newRandomNodeUUID
	newRandomNodeUUID = func() (uuid.UUID, error) {
		return uuid.Nil, errors.New("random source unavailable")
	}
	defer func() {
		newRandomNodeUUID = original
	}()

	got, err := ResolveOrCreateNodeIDWithOptions(NodeIDOptions{})
	if err == nil {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = nil, want non-nil, got %q", got)
	}
	if !strings.Contains(err.Error(), "generate node uuid") {
		t.Fatalf("ResolveOrCreateNodeIDWithOptions() error = %v, want wrapped generator error", err)
	}
	homeFile := filepath.Join(home, DefaultNodeIDFileName())
	if _, statErr := os.Stat(homeFile); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("os.Stat(%q) error = %v, want %v", homeFile, statErr, os.ErrNotExist)
	}
}

func TestRegisterNodeTokenUsesBootstrapToken(t *testing.T) {
	const (
		bootstrap = "bootstrap-token"
		nodeID    = "node-random-001"
		nodeToken = "node-token-001"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-AGENT-TOKEN"); got != bootstrap {
			t.Fatalf("expected bootstrap token header, got %q", got)
		}
		if got := r.URL.Query().Get("node_id"); got != nodeID {
			t.Fatalf("expected node_id query parameter, got %q", got)
		}
		_, _ = w.Write([]byte(`{"node_id":"` + nodeID + `","agent_token":"` + nodeToken + `"}`))
	}))
	defer server.Close()

	got, err := registerNodeToken(context.Background(), server.Client(), server.URL+"/register", nodeID, bootstrap)
	if err != nil {
		t.Fatalf("register node token: %v", err)
	}
	if got != nodeToken {
		t.Fatalf("expected node token %q, got %q", nodeToken, got)
	}
}

func TestPersistAgentTokenWritesTrimmedValue(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "agent-token")
	if err := persistAgentToken(filePath, " node-token-001 \n"); err != nil {
		t.Fatalf("persist agent token: %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read persisted agent token: %v", err)
	}
	if strings.TrimSpace(string(data)) != "node-token-001" {
		t.Fatalf("expected trimmed token, got %q", string(data))
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func mustReadTrimmedFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	return strings.TrimSpace(string(data))
}
