package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// 指纹源全部存在但不可读（目录读入报非 ErrNotExist 错误）时，
// 旧实现会返回机器无关的占位符指纹（"machine-id=<unreadable>"...），
// 导致不同宿主机哈希出同一 node ID。必须退回 os.ErrNotExist → 随机 ID。
func TestReadStableHostFingerprintRejectsPlaceholderCollision(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"etc/machine-id",
		"var/lib/dbus/machine-id",
		"sys/class/dmi/id/product_uuid",
		"sys/class/dmi/id/product_serial",
		"sys/class/dmi/id/board_serial",
		"etc/hostname",
	} {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readStableHostFingerprint(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("all sources unreadable: want os.ErrNotExist, got %v", err)
	}
}

func TestReadStableHostFingerprintUsesReadableSources(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "machine-id"), []byte("  abc123  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := readStableHostFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != "machine-id=abc123" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}
