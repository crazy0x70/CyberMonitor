package updater_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerEntrypointPreparesDataDirBeforeDroppingPrivileges(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	scriptPath := filepath.Join(root, "scripts", "docker-entrypoint.sh")

	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logPath := filepath.Join(tmpDir, "calls.log")
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	writeWrapper(t, filepath.Join(binDir, "id"), "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then\n  echo 0\n  exit 0\nfi\nexit 1\n")
	writeWrapper(t, filepath.Join(binDir, "chown"), "#!/bin/sh\nprintf 'chown %s\\n' \"$*\" >> \"$CALLS_LOG\"\nexit 0\n")
	writeWrapper(t, filepath.Join(binDir, "chmod"), "#!/bin/sh\nprintf 'chmod %s\\n' \"$*\" >> \"$CALLS_LOG\"\nexit 0\n")
	writeWrapper(t, filepath.Join(binDir, "su-exec"), "#!/bin/sh\nprintf 'su-exec %s\\n' \"$*\" >> \"$CALLS_LOG\"\nexit 0\n")

	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"CALLS_LOG="+logPath,
		"CM_DATA_DIR="+dataDir,
		"CM_DOCKER_SOCKET="+filepath.Join(tmpDir, "missing.sock"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run docker-entrypoint.sh: %v\n%s", err, output)
	}

	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("expected data dir to be created, got err: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read calls log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, dataDir) {
		t.Fatalf("expected chown call to include data dir %q, got log:\n%s", dataDir, logText)
	}
	if !strings.Contains(logText, "chmod u+rwx "+dataDir) {
		t.Fatalf("expected chmod call to make data dir writable, got log:\n%s", logText)
	}
}

func writeWrapper(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write wrapper %s: %v", path, err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
