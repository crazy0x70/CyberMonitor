package metrics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHostVirtualMemory(t *testing.T) {
	hostRoot := t.TempDir()
	procDir := filepath.Join(hostRoot, "proc")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("mkdir proc: %v", err)
	}

	meminfo := `MemTotal:         524288 kB
MemFree:           65536 kB
MemAvailable:     102400 kB
Buffers:            8192 kB
Cached:            24576 kB
SReclaimable:       4096 kB
Shmem:              2048 kB
`
	if err := os.WriteFile(filepath.Join(procDir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}

	stat, ok := readHostVirtualMemory(hostRoot)
	if !ok {
		t.Fatal("expected host meminfo to be parsed")
	}

	const kib = 1024
	if got, want := stat.Total, uint64(524288*kib); got != want {
		t.Fatalf("total = %d, want %d", got, want)
	}
	if got, want := stat.Free, uint64(102400*kib); got != want {
		t.Fatalf("free = %d, want %d", got, want)
	}
	if got, want := stat.Used, uint64((524288-102400)*kib); got != want {
		t.Fatalf("used = %d, want %d", got, want)
	}
}

func TestReadBlockDeviceTotal(t *testing.T) {
	hostRoot := t.TempDir()
	sizePath := filepath.Join(hostRoot, "sys", "class", "block", "sda1")
	if err := os.MkdirAll(sizePath, 0o755); err != nil {
		t.Fatalf("mkdir block path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sizePath, "size"), []byte("39062500\n"), 0o644); err != nil {
		t.Fatalf("write size: %v", err)
	}

	if got, want := readBlockDeviceTotal(hostRoot, "/dev/sda1"), uint64(39062500*512); got != want {
		t.Fatalf("device total = %d, want %d", got, want)
	}
}

func TestApplyDeviceTotal(t *testing.T) {
	usage := filesystemUsage{
		Total: 19_500_000_000,
		Used:  5_000_000_000,
		Free:  14_500_000_000,
	}

	adjusted := applyDeviceTotal(usage, 20_000_000_000)

	if got, want := adjusted.Total, uint64(20_000_000_000); got != want {
		t.Fatalf("total = %d, want %d", got, want)
	}
	if got, want := adjusted.Used, uint64(5_000_000_000); got != want {
		t.Fatalf("used = %d, want %d", got, want)
	}
	if got, want := adjusted.Free, uint64(15_000_000_000); got != want {
		t.Fatalf("free = %d, want %d", got, want)
	}
}

func TestReadHostMounts(t *testing.T) {
	hostRoot := t.TempDir()
	mountDir := filepath.Join(hostRoot, "proc", "1")
	if err := os.MkdirAll(mountDir, 0o755); err != nil {
		t.Fatalf("mkdir mount dir: %v", err)
	}

	content := "36 29 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
	if err := os.WriteFile(filepath.Join(mountDir, "mountinfo"), []byte(content), 0o644); err != nil {
		t.Fatalf("write mountinfo: %v", err)
	}

	mounts, err := readHostMounts(hostRoot)
	if err != nil {
		t.Fatalf("read host mounts: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mount count = %d, want 1", len(mounts))
	}
	if got, want := mounts[0].Device, "/dev/sda1"; got != want {
		t.Fatalf("device = %q, want %q", got, want)
	}
	if got, want := mounts[0].Mountpoint, "/"; got != want {
		t.Fatalf("mountpoint = %q, want %q", got, want)
	}
	if got, want := mounts[0].Fstype, "ext4"; got != want {
		t.Fatalf("fstype = %q, want %q", got, want)
	}
}
