package metrics

import "testing"

func TestDetectDiskTypeReturnsEmptyWhenUndetected(t *testing.T) {
	if got := detectDiskType(nil, "/nonexistent-host-root"); got != "" {
		t.Fatalf("detectDiskType(无分区, 不存在的 hostRoot) = %q, want 空值（语言无关）", got)
	}
	ssd, hdd, nvme := detectDiskTypeFromSysfs("/nonexistent-host-root")
	if ssd || hdd || nvme {
		t.Fatalf("detectDiskTypeFromSysfs(不存在的 hostRoot) = (%v,%v,%v), want 全 false", ssd, hdd, nvme)
	}
}
