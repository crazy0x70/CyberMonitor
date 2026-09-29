package metrics

import (
	"math"
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestDetectDiskTypeReturnsEmptyWhenUndetected(t *testing.T) {
	if got := detectDiskType(nil, "/nonexistent-host-root"); got != "" {
		t.Fatalf("detectDiskType(无分区, 不存在的 hostRoot) = %q, want 空值（语言无关）", got)
	}
	ssd, hdd, nvme := detectDiskTypeFromSysfs("/nonexistent-host-root")
	if ssd || hdd || nvme {
		t.Fatalf("detectDiskTypeFromSysfs(不存在的 hostRoot) = (%v,%v,%v), want 全 false", ssd, hdd, nvme)
	}
}

func TestSanitizeNodeStatsBounds(t *testing.T) {
	badLatency := math.NaN()
	negLatency := -1.0
	stats := NodeStats{
		CPU:          CPUInfo{UsagePercent: math.NaN(), Load1: math.Inf(1), Load5: -2, Load15: 150},
		Memory:       MemInfo{UsedPercent: 120.5},
		NetSpeedMbps: math.NaN(),
		DiskIO:       DiskIO{ReadBytesPerSec: -12, WriteBytesPerSec: math.Inf(-1)},
		Network:      NetworkIO{TxBytesPerSec: math.NaN(), RxBytesPerSec: -99},
		Disk:         []DiskPartition{{UsedPercent: 250}, {UsedPercent: -1}},
		GPU: []GPUInfo{
			{UtilizationPercent: math.NaN(), MemoryUsedPercent: -5, TemperatureC: math.Inf(1), PowerW: math.Inf(1)},
			{UtilizationPercent: 130, MemoryUsedPercent: 250, PowerW: -1},
		},
		NetworkTests: []NetworkTestResult{
			{PacketLoss: 1000, LatencyMs: &badLatency},
			{PacketLoss: -5, LatencyMs: &negLatency},
		},
	}
	SanitizeNodeStats(&stats)

	if stats.CPU.UsagePercent != 0 {
		t.Errorf("CPU.UsagePercent = %v, want 0", stats.CPU.UsagePercent)
	}
	if stats.CPU.Load1 != 0 || stats.CPU.Load5 != 0 {
		t.Errorf("负值/非有限负载应归零: %+v", stats.CPU)
	}
	if stats.CPU.Load15 != 150 {
		t.Errorf("CPU.Load15 = %v, want 保持 150（负载不是百分比，不锓制超百）", stats.CPU.Load15)
	}
	if stats.Memory.UsedPercent != 100 {
		t.Errorf("Memory.UsedPercent = %v, want 100", stats.Memory.UsedPercent)
	}
	if stats.NetSpeedMbps != 0 {
		t.Errorf("NetSpeedMbps = %v, want 0", stats.NetSpeedMbps)
	}
	if stats.DiskIO.ReadBytesPerSec != 0 || stats.DiskIO.WriteBytesPerSec != 0 {
		t.Errorf("DiskIO 速率应归零: %+v", stats.DiskIO)
	}
	if stats.Network.TxBytesPerSec != 0 || stats.Network.RxBytesPerSec != 0 {
		t.Errorf("Network 速率应归零: %+v", stats.Network)
	}
	if stats.Disk[0].UsedPercent != 100 || stats.Disk[1].UsedPercent != 0 {
		t.Errorf("Disk.UsedPercent 钳制错误: %v, %v", stats.Disk[0].UsedPercent, stats.Disk[1].UsedPercent)
	}
	if stats.GPU[0].UtilizationPercent != 0 || stats.GPU[0].MemoryUsedPercent != 0 || stats.GPU[0].PowerW != 0 {
		t.Errorf("GPU[0] 非有限值应归零: %+v", stats.GPU[0])
	}
	if stats.GPU[1].UtilizationPercent != 100 || stats.GPU[1].MemoryUsedPercent != 100 {
		t.Errorf("GPU[1] 超百应钳制: %+v", stats.GPU[1])
	}
	if stats.GPU[0].TemperatureC != 0 {
		t.Errorf("GPU.TemperatureC = %v, want 0", stats.GPU[0].TemperatureC)
	}
	if stats.NetworkTests[0].PacketLoss != 100 || stats.NetworkTests[1].PacketLoss != 0 {
		t.Errorf("PacketLoss 钳制错误: %v, %v", stats.NetworkTests[0].PacketLoss, stats.NetworkTests[1].PacketLoss)
	}
	if got := stats.NetworkTests[0].LatencyMs; got == nil || *got != 0 {
		t.Errorf("NaN 延迟 = %v, want 0", got)
	}
	if got := stats.NetworkTests[1].LatencyMs; got == nil || *got != 0 {
		t.Errorf("负值延迟 = %v, want 0", got)
	}
}

func TestSanitizeNodeStatsNilAndValid(t *testing.T) {
	SanitizeNodeStats(nil)

	ok := 42.5
	stats := NodeStats{
		CPU:          CPUInfo{UsagePercent: 42.5, Load1: 1.25},
		NetworkTests: []NetworkTestResult{{PacketLoss: 12.5, LatencyMs: &ok}},
		Disk:         []DiskPartition{{UsedPercent: 99.9}},
	}
	SanitizeNodeStats(&stats)
	if stats.CPU.UsagePercent != 42.5 || stats.CPU.Load1 != 1.25 {
		t.Fatalf("合法 CPU 值被修改: %+v", stats.CPU)
	}
	if stats.NetworkTests[0].PacketLoss != 12.5 || *stats.NetworkTests[0].LatencyMs != 42.5 {
		t.Fatalf("合法探测值被修改: %+v", stats.NetworkTests[0])
	}
	if stats.Disk[0].UsedPercent != 99.9 {
		t.Fatalf("合法分区值被修改: %+v", stats.Disk[0])
	}
}

func TestParseSpeedMbps(t *testing.T) {
	tests := []struct {
		raw  string
		want float64
	}{
		{"1000\n", 1000},
		{" 2500 ", 2500},
		{"2.5", 2.5},
		{"1e3", 1000},
		{"", 0},
		{"0", 0},
		{"-1", 0},
		{"abc", 0},
		{"1x2", 0}, // 回归：旧实现剥离非数字后解析为 12
		{"nan", 0},
		{"inf", 0},
	}
	for _, tt := range tests {
		if got := parseSpeedMbps(tt.raw); got != tt.want {
			t.Errorf("parseSpeedMbps(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestIsPartitionOfCountedDisk(t *testing.T) {
	tests := []struct {
		name    string
		device  string
		counter []string
		want    bool
	}{
		{"sda1 是 sda 的分区", "sda1", []string{"sda", "sda1"}, true},
		{"sda10 是 sda 的分区", "sda10", []string{"sda", "sda10"}, true},
		{"vda1 是 vda 的分区", "vda1", []string{"vda", "vda1"}, true},
		{"xvda2 是 xvda 的分区", "xvda2", []string{"xvda", "xvda2"}, true},
		{"nvme0n1p1 是 nvme0n1 的分区", "nvme0n1p1", []string{"nvme0n1", "nvme0n1p1"}, true},
		{"nvme0n1 整盘不是分区", "nvme0n1", []string{"nvme0n1", "nvme0n1p1"}, false},
		{"mmcblk0p1 是 mmcblk0 的分区", "mmcblk0p1", []string{"mmcblk0", "mmcblk0p1"}, true},
		{"mmcblk0 整盘不是分区", "mmcblk0", []string{"mmcblk0", "mmcblk0p1"}, false},
		{"dm-0 不是分区", "dm-0", []string{"dm-0"}, false},
		{"基名不在 counters 中", "vdb9", []string{"sda"}, false},
		{"无数字结尾不是分区", "sda", []string{"sda"}, false},
		{"纯数字不是分区", "123", []string{"123"}, false},
	}
	for _, tt := range tests {
		counters := make(map[string]disk.IOCountersStat, len(tt.counter))
		for _, name := range tt.counter {
			counters[name] = disk.IOCountersStat{}
		}
		if got := isPartitionOfCountedDisk(tt.device, counters); got != tt.want {
			t.Errorf("%s: isPartitionOfCountedDisk(%q) = %v, want %v", tt.name, tt.device, got, tt.want)
		}
	}
}
