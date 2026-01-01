package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

type CPUInfo struct {
	UsagePercent float64 `json:"usage_percent"`
	Load1        float64 `json:"load1"`
	Load5        float64 `json:"load5"`
	Load15       float64 `json:"load15"`
	Model        string  `json:"model,omitempty"`
	Cores        int     `json:"cores,omitempty"`
}

type MemInfo struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type DiskPartition struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type DiskIO struct {
	ReadBytes        uint64  `json:"read_bytes"`
	WriteBytes       uint64  `json:"write_bytes"`
	ReadBytesPerSec  float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`
}

type NetworkIO struct {
	BytesSent     uint64  `json:"bytes_sent"`
	BytesRecv     uint64  `json:"bytes_recv"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
}

type NetworkTestConfig struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	IntervalSec int    `json:"interval_sec,omitempty"`
}

type NetworkTestResult struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Host       string   `json:"host"`
	Port       int      `json:"port,omitempty"`
	LatencyMs  *float64 `json:"latency_ms,omitempty"`
	PacketLoss float64  `json:"packet_loss"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
	CheckedAt  int64    `json:"checked_at"`
}

type NodeStats struct {
	NodeID       string              `json:"node_id"`
	NodeName     string              `json:"node_name"`
	NodeAlias    string              `json:"node_alias,omitempty"`
	NodeGroup    string              `json:"node_group,omitempty"`
	Hostname     string              `json:"hostname"`
	OS           string              `json:"os"`
	Arch         string              `json:"arch"`
	UptimeSec    uint64              `json:"uptime_sec"`
	Timestamp    int64               `json:"timestamp"`
	NetSpeedMbps float64             `json:"net_speed_mbps,omitempty"`
	CPU          CPUInfo             `json:"cpu"`
	Memory       MemInfo             `json:"memory"`
	Disk         []DiskPartition     `json:"disk"`
	DiskType     string              `json:"disk_type,omitempty"`
	DiskIO       DiskIO              `json:"disk_io"`
	Network      NetworkIO           `json:"network"`
	ProcessCount int                 `json:"process_count,omitempty"`
	TCPConns     int                 `json:"tcp_conns,omitempty"`
	UDPConns     int                 `json:"udp_conns,omitempty"`
	NetworkTests []NetworkTestResult `json:"network_tests,omitempty"`
}

type Collector struct {
	nodeID    string
	nodeName  string
	hostRoot  string
	netIfaces map[string]struct{}
	prevNet   *gnet.IOCountersStat
	prevDisk  *disk.IOCountersStat
	prevTime  time.Time
}

func NewCollector(nodeID, nodeName, hostRoot string, netIfaces []string) *Collector {
	filter := make(map[string]struct{})
	for _, iface := range netIfaces {
		name := strings.ToLower(strings.TrimSpace(iface))
		if name == "" {
			continue
		}
		filter[name] = struct{}{}
	}
	return &Collector{
		nodeID:    nodeID,
		nodeName:  nodeName,
		hostRoot:  hostRoot,
		netIfaces: filter,
	}
}

func (c *Collector) Collect() (NodeStats, error) {
	now := time.Now()

	cpuPercents, _ := cpu.Percent(0, false)
	usage := 0.0
	if len(cpuPercents) > 0 {
		usage = cpuPercents[0]
	}
	cpuInfos, _ := cpu.Info()
	cpuModel := ""
	if len(cpuInfos) > 0 {
		cpuModel = strings.TrimSpace(cpuInfos[0].ModelName)
	}
	coreCount, err := cpu.Counts(true)
	if err != nil || coreCount < 0 {
		coreCount = 0
	}

	loadAvg, _ := load.Avg()
	memStat, _ := mem.VirtualMemory()
	partitions, _ := disk.Partitions(false)

	diskUsage := c.collectDiskUsage(partitions)
	diskType := ""

	diskCounters, _ := disk.IOCounters()
	var diskRead, diskWrite uint64
	for _, stat := range diskCounters {
		diskRead += stat.ReadBytes
		diskWrite += stat.WriteBytes
	}

	netCounters, _ := gnet.IOCounters(true)
	netStat := sumNetCounters(netCounters, c.netIfaces)

	hostInfo, _ := host.Info()
	osLabel := runtime.GOOS
	hostname := ""
	uptime := uint64(0)
	processCount := 0
	if hostInfo != nil {
		osLabel = hostInfo.Platform + " " + hostInfo.PlatformVersion
		hostname = hostInfo.Hostname
		uptime = hostInfo.Uptime
		processCount = int(hostInfo.Procs)
	}
	if hostOS := readHostOSRelease(c.hostRoot); hostOS != "" {
		osLabel = hostOS
	}
	if hostName := readHostHostname(c.hostRoot); hostName != "" {
		hostname = hostName
	}

	tcpConns := 0
	udpConns := 0
	if conns, err := gnet.Connections("tcp"); err == nil {
		tcpConns = len(conns)
	}
	if conns, err := gnet.Connections("udp"); err == nil {
		udpConns = len(conns)
	}

	netSpeedMbps := collectNetSpeedMbps(c.netIfaces)
	stats := NodeStats{
		NodeID:    c.nodeID,
		NodeName:  c.nodeName,
		Hostname:  hostname,
		OS:        osLabel,
		Arch:      detectArch(),
		UptimeSec: uptime,
		Timestamp: now.Unix(),
		NetSpeedMbps: netSpeedMbps,
		CPU: CPUInfo{
			UsagePercent: usage,
			Load1:        valueOrZero(loadAvg).Load1,
			Load5:        valueOrZero(loadAvg).Load5,
			Load15:       valueOrZero(loadAvg).Load15,
			Model:        cpuModel,
			Cores:        coreCount,
		},
		Memory: MemInfo{
			Total:       valueOrZeroMem(memStat).Total,
			Used:        valueOrZeroMem(memStat).Used,
			Free:        valueOrZeroMem(memStat).Free,
			UsedPercent: valueOrZeroMem(memStat).UsedPercent,
		},
		Disk: diskUsage,
		DiskType: diskType,
		DiskIO: DiskIO{
			ReadBytes:  diskRead,
			WriteBytes: diskWrite,
		},
		Network: NetworkIO{
			BytesSent: netStat.BytesSent,
			BytesRecv: netStat.BytesRecv,
		},
		ProcessCount: processCount,
		TCPConns:     tcpConns,
		UDPConns:     udpConns,
	}

	// 计算速率需要前后采样差值
	if !c.prevTime.IsZero() && c.prevNet != nil && c.prevDisk != nil {
		delta := now.Sub(c.prevTime).Seconds()
		if delta > 0 {
			txDelta := diffUint64(netStat.BytesSent, c.prevNet.BytesSent)
			rxDelta := diffUint64(netStat.BytesRecv, c.prevNet.BytesRecv)
			readDelta := diffUint64(diskRead, c.prevDisk.ReadBytes)
			writeDelta := diffUint64(diskWrite, c.prevDisk.WriteBytes)
			stats.Network.TxBytesPerSec = float64(txDelta) / delta
			stats.Network.RxBytesPerSec = float64(rxDelta) / delta
			stats.DiskIO.ReadBytesPerSec = float64(readDelta) / delta
			stats.DiskIO.WriteBytesPerSec = float64(writeDelta) / delta
		}
	}

	c.prevTime = now
	c.prevNet = &netStat
	c.prevDisk = &disk.IOCountersStat{ReadBytes: diskRead, WriteBytes: diskWrite}

	return stats, nil
}

func valueOrZero(stat *load.AvgStat) *load.AvgStat {
	if stat == nil {
		return &load.AvgStat{}
	}
	return stat
}

func valueOrZeroMem(stat *mem.VirtualMemoryStat) *mem.VirtualMemoryStat {
	if stat == nil {
		return &mem.VirtualMemoryStat{}
	}
	return stat
}

func diffUint64(current, prev uint64) uint64 {
	if current >= prev {
		return current - prev
	}
	return 0
}

func sumNetCounters(stats []gnet.IOCountersStat, filter map[string]struct{}) gnet.IOCountersStat {
	var total gnet.IOCountersStat
	var matched bool
	for _, stat := range stats {
		if len(filter) > 0 {
			if _, ok := filter[strings.ToLower(stat.Name)]; !ok {
				continue
			}
			matched = true
		} else {
			if isVirtualInterface(stat.Name) {
				continue
			}
		}
		total.BytesSent += stat.BytesSent
		total.BytesRecv += stat.BytesRecv
	}
	if len(filter) > 0 && !matched {
		for _, stat := range stats {
			total.BytesSent += stat.BytesSent
			total.BytesRecv += stat.BytesRecv
		}
	}
	return total
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	virtualPrefixes := []string{
		"lo", "loopback", "docker", "veth", "br-", "virbr", "vmnet", "utun",
		"tun", "tap", "wg", "tailscale", "zt", "vboxnet", "ham", "bridge",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func collectNetSpeedMbps(filter map[string]struct{}) float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	ifaces, err := gnet.Interfaces()
	if err != nil {
		return 0
	}
	candidates := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		name := strings.ToLower(strings.TrimSpace(iface.Name))
		if name == "" {
			continue
		}
		if len(filter) > 0 {
			if _, ok := filter[name]; !ok {
				continue
			}
		} else if isVirtualInterface(name) {
			continue
		}
		candidates = append(candidates, iface.Name)
	}
	if len(filter) > 0 && len(candidates) == 0 {
		for _, iface := range ifaces {
			candidates = append(candidates, iface.Name)
		}
	}
	maxSpeed := 0.0
	for _, name := range candidates {
		if speed := readInterfaceSpeedMbps(name); speed > maxSpeed {
			maxSpeed = speed
		}
	}
	return maxSpeed
}

func readInterfaceSpeedMbps(name string) float64 {
	if name == "" {
		return 0
	}
	path := filepath.Join("/sys/class/net", name, "speed")
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return parseSpeedMbps(string(raw))
}

func parseSpeedMbps(raw string) float64 {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0
	}
	lower := strings.ToLower(value)
	multiplier := 1.0
	if strings.Contains(lower, "gb") {
		multiplier = 1000
	} else if strings.Contains(lower, "kb") {
		multiplier = 0.001
	}
	var builder strings.Builder
	for _, ch := range lower {
		if (ch >= '0' && ch <= '9') || ch == '.' {
			builder.WriteRune(ch)
		}
	}
	numStr := builder.String()
	if numStr == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(numStr, 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed * multiplier
}

func (c *Collector) collectDiskUsage(partitions []disk.PartitionStat) []DiskPartition {
	if hostRoot := strings.TrimSpace(c.hostRoot); hostRoot != "" && isDir(hostRoot) {
		if usageStat, err := disk.Usage(hostRoot); err == nil {
			return []DiskPartition{
				{
					Device:      "host-root",
					Mountpoint:  "/",
					Fstype:      usageStat.Fstype,
					Total:       usageStat.Total,
					Used:        usageStat.Used,
					Free:        usageStat.Free,
					UsedPercent: usageStat.UsedPercent,
				},
			}
		}
	}

	seen := make(map[string]struct{})
	diskUsage := make([]DiskPartition, 0, len(partitions))
	for _, p := range partitions {
		if shouldSkipPartition(p) {
			continue
		}
		if _, exists := seen[p.Mountpoint]; exists {
			continue
		}
		seen[p.Mountpoint] = struct{}{}
		usageStat, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		diskUsage = append(diskUsage, DiskPartition{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			Fstype:      p.Fstype,
			Total:       usageStat.Total,
			Used:        usageStat.Used,
			Free:        usageStat.Free,
			UsedPercent: usageStat.UsedPercent,
		})
	}
	return diskUsage
}

func shouldSkipPartition(p disk.PartitionStat) bool {
	if p.Mountpoint == "" || p.Mountpoint == "none" {
		return true
	}
	if info, err := os.Stat(p.Mountpoint); err == nil && !info.IsDir() {
		return true
	}
	ignorePrefixes := []string{
		"/proc", "/sys", "/dev", "/run", "/etc",
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet",
	}
	for _, prefix := range ignorePrefixes {
		if strings.HasPrefix(p.Mountpoint, prefix) {
			return true
		}
	}
	ignoreFS := map[string]struct{}{
		"proc": {}, "sysfs": {}, "tmpfs": {}, "devtmpfs": {}, "squashfs": {}, "overlay": {},
		"cgroup": {}, "cgroup2": {}, "devpts": {}, "mqueue": {}, "debugfs": {}, "tracefs": {},
		"fusectl": {}, "binfmt_misc": {}, "rpc_pipefs": {}, "nsfs": {},
	}
	if _, ok := ignoreFS[strings.ToLower(p.Fstype)]; ok && p.Mountpoint != "/" {
		return true
	}
	return false
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func readHostOSRelease(hostRoot string) string {
	if hostRoot == "" {
		return ""
	}
	path := filepath.Join(hostRoot, "etc", "os-release")
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	var name, version, pretty string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			pretty = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		} else if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}
	if pretty != "" {
		return pretty
	}
	if name != "" && version != "" {
		return name + " " + version
	}
	return name
}

func readHostHostname(hostRoot string) string {
	if hostRoot == "" {
		return ""
	}
	path := filepath.Join(hostRoot, "etc", "hostname")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func detectArch() string {
	arch := runtime.GOARCH
	if runtime.GOOS != "windows" {
		return arch
	}
	procArch := strings.ToUpper(strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITECTURE")))
	procArchAlt := strings.ToUpper(strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITEW6432")))
	if procArch == "ARM64" || procArchAlt == "ARM64" {
		return "arm64"
	}
	if procArch == "AMD64" || procArchAlt == "AMD64" {
		return "amd64"
	}
	if procArch == "X86" || procArchAlt == "X86" {
		return "386"
	}
	if strings.HasPrefix(procArch, "ARM") || strings.HasPrefix(procArchAlt, "ARM") {
		return "arm"
	}
	return arch
}

func detectDiskType(partitions []disk.PartitionStat, hostRoot string) string {
	hasSSD := false
	hasHDD := false
	hasNVMe := false
	found := false
	for _, part := range partitions {
		dev := strings.TrimSpace(part.Device)
		if !strings.HasPrefix(dev, "/dev/") {
			continue
		}
		block := blockDeviceName(dev)
		if block == "" {
			continue
		}
		if strings.HasPrefix(block, "nvme") {
			hasNVMe = true
			found = true
			continue
		}
		rotational, ok := readRotational(hostRoot, block)
		if !ok {
			continue
		}
		found = true
		if rotational == 0 {
			hasSSD = true
		} else {
			hasHDD = true
		}
	}
	if !found {
		sysSSD, sysHDD, sysNVMe := detectDiskTypeFromSysfs(hostRoot)
		hasSSD = hasSSD || sysSSD
		hasHDD = hasHDD || sysHDD
		hasNVMe = hasNVMe || sysNVMe
	}
	if hasNVMe {
		return "NVMe"
	}
	if hasSSD {
		return "SSD"
	}
	if hasHDD {
		return "HDD"
	}
	return "未知"
}

func detectDiskTypeFromSysfs(hostRoot string) (bool, bool, bool) {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		root = "/"
	}
	sysBlock := filepath.Join(root, "sys", "block")
	entries, err := os.ReadDir(sysBlock)
	if err != nil {
		return false, false, false
	}
	hasSSD := false
	hasHDD := false
	hasNVMe := false
	for _, entry := range entries {
		name := entry.Name()
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") {
			continue
		}
		if strings.HasPrefix(name, "nvme") {
			hasNVMe = true
			continue
		}
		rotational, ok := readRotational(hostRoot, name)
		if !ok {
			continue
		}
		if rotational == 0 {
			hasSSD = true
		} else {
			hasHDD = true
		}
	}
	return hasSSD, hasHDD, hasNVMe
}

func blockDeviceName(device string) string {
	base := filepath.Base(strings.TrimSpace(device))
	if base == "" {
		return ""
	}
	if strings.HasPrefix(base, "nvme") || strings.HasPrefix(base, "mmcblk") {
		if idx := strings.LastIndex(base, "p"); idx > 0 {
			return base[:idx]
		}
		return base
	}
	return strings.TrimRightFunc(base, func(r rune) bool {
		return r >= '0' && r <= '9'
	})
}

func readRotational(hostRoot, device string) (int, bool) {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		root = "/"
	}
	path := filepath.Join(root, "sys", "block", device, "queue", "rotational")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return value, true
}
