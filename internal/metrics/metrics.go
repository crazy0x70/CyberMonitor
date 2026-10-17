package metrics

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
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

type GPUInfo struct {
	Index              int     `json:"index"`
	ID                 string  `json:"id,omitempty"`
	Name               string  `json:"name,omitempty"`
	Vendor             string  `json:"vendor,omitempty"`
	DriverVersion      string  `json:"driver_version,omitempty"`
	UtilizationPercent float64 `json:"utilization_percent"`
	MemoryTotal        uint64  `json:"memory_total"`
	MemoryUsed         uint64  `json:"memory_used"`
	MemoryFree         uint64  `json:"memory_free"`
	MemoryUsedPercent  float64 `json:"memory_used_percent"`
	TemperatureC       float64 `json:"temperature_c,omitempty"`
	PowerW             float64 `json:"power_w,omitempty"`
}

type NetworkTestConfig struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	IntervalSec int    `json:"interval_sec,omitempty"`
	PublicOnly  bool   `json:"-"`
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
	NodeID              string              `json:"node_id"`
	NodeName            string              `json:"node_name"`
	NodeAlias           string              `json:"node_alias,omitempty"`
	NodeGroup           string              `json:"node_group,omitempty"`
	Hostname            string              `json:"hostname"`
	PublicIPv4          string              `json:"public_ipv4,omitempty"`
	PublicIPv6          string              `json:"public_ipv6,omitempty"`
	OS                  string              `json:"os,omitempty"`
	Arch                string              `json:"arch,omitempty"`
	StaticInfo          bool                `json:"static_info,omitempty"`
	StaticUpdatedAt     int64               `json:"static_updated_at,omitempty"`
	DeployMode          string              `json:"deploy_mode,omitempty"`
	DockerManagedUpdate bool                `json:"docker_managed_update,omitempty"`
	AgentVersion        string              `json:"agent_version,omitempty"`
	AgentUpdateDisabled bool                `json:"agent_update_disabled,omitempty"`
	AgentUpdateInsecure bool                `json:"agent_update_insecure,omitempty"`
	AgentRemoteUpdate   bool                `json:"agent_remote_update,omitempty"`
	UptimeSec           uint64              `json:"uptime_sec"`
	Timestamp           int64               `json:"timestamp"`
	NetSpeedMbps        float64             `json:"net_speed_mbps,omitempty"`
	CPU                 CPUInfo             `json:"cpu"`
	Memory              MemInfo             `json:"memory"`
	Disk                []DiskPartition     `json:"disk"`
	DiskType            string              `json:"disk_type,omitempty"`
	DiskIO              DiskIO              `json:"disk_io"`
	Network             NetworkIO           `json:"network"`
	GPU                 []GPUInfo           `json:"gpu,omitempty"`
	GPUCollected        bool                `json:"gpu_collected,omitempty"`
	ProcessCount        int                 `json:"process_count,omitempty"`
	TCPConns            int                 `json:"tcp_conns,omitempty"`
	UDPConns            int                 `json:"udp_conns,omitempty"`
	NetworkTestsChanged bool                `json:"network_tests_changed,omitempty"`
	NetworkTests        []NetworkTestResult `json:"network_tests,omitempty"`
}

type publicIPFamily string

const (
	defaultStaticInfoRefreshInterval = 30 * time.Minute
	defaultPublicIPRefreshInterval   = 10 * time.Minute
	defaultPublicIPRetryInterval     = time.Minute
	defaultPublicIPLookupTimeout     = 2 * time.Second

	nvidiaSMIPathRefreshInterval = 60 * time.Second
	gpuSampleRefreshInterval     = 5 * time.Second
	netFilterRefreshInterval     = 10 * time.Second
	netSpeedRefreshInterval      = 10 * time.Second
	hostHostnameRefreshInterval  = 60 * time.Second
	hostProcsRefreshInterval     = 30 * time.Second
	hostMountsRefreshInterval    = 10 * time.Second
	partitionsRefreshInterval    = 10 * time.Second

	publicIPv4Family publicIPFamily = "ipv4"
	publicIPv6Family publicIPFamily = "ipv6"
)

var defaultPublicIPv4Endpoints = []string{
	"https://api-ipv4.ip.sb/ip",
	"https://api64.ipify.org",
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://ipinfo.io",
}

var defaultPublicIPv6Endpoints = []string{
	"https://api-ipv6.ip.sb/ip",
	"https://api64.ipify.org",
	"https://icanhazip.com",
	"https://6.ipinfo.io",
}

type publicIPLookupFunc func(context.Context, publicIPFamily) (string, error)

type publicIPInfo struct {
	IPv4      string
	IPv6      string
	checkedAt time.Time
}

type collectorStaticInfo struct {
	CPUModel string
	Cores    int
	Arch     string
	OS       string
	DiskType string
}

type Collector struct {
	nodeID     string
	nodeName   string
	hostRoot   string
	netIfaces  map[string]struct{}
	prevNet    *gnet.IOCountersStat
	prevDisk   *disk.IOCountersStat
	prevTime   time.Time
	prevTCP    int
	prevUDP    int
	prevConnAt time.Time

	resolvedNetFilter    map[string]struct{}
	resolvedNetFilterAt  time.Time
	netSpeedMbps         float64
	netSpeedSampledAt    time.Time
	hostHostname         string
	hostHostnameAt       time.Time
	hostMounts           []hostMount
	hostMountsAt         time.Time
	nvidiaSMIPath        string
	nvidiaSMIPathAt      time.Time
	gpuSample            []GPUInfo
	gpuSampleStatic      bool
	gpuSampleAt          time.Time
	gpuSampleOK          bool
	bootTime             uint64
	bootTimeOK           bool
	hostProcs            int
	hostHostnameFallback string
	hostIdentityAt       time.Time
	sourceWarningsShown  map[string]struct{}
	sourceWarningsMu     sync.Mutex

	partitionsCache    []disk.PartitionStat
	partitionsCachedAt time.Time

	publicIPs               publicIPInfo
	publicIPRefreshInterval time.Duration
	publicIPLookup          publicIPLookupFunc
	publicIPsMu             sync.Mutex
	publicIPRefreshRunning  bool

	blockPartitionAttr map[string]bool
	blockDeviceTotal   map[string]uint64
	mountpointIsDir    map[string]bool

	staticInfo                collectorStaticInfo
	staticInfoInitialized     bool
	staticInfoUpdatedAt       time.Time
	staticInfoRefreshInterval time.Duration
}

func NewCollector(nodeID, nodeName, hostRoot string, netIfaces []string) *Collector {
	filter := make(map[string]struct{})
	for _, iface := range netIfaces {
		name := normalizeInterfaceName(iface)
		if name == "" {
			continue
		}
		filter[name] = struct{}{}
	}
	hostRoot = strings.TrimSpace(hostRoot)
	if hostRoot != "" && !isDir(filepath.Join(hostRoot, "proc")) && !isDir(filepath.Join(hostRoot, "sys")) {
		hostRoot = ""
	}
	collector := &Collector{
		nodeID:                    nodeID,
		nodeName:                  nodeName,
		hostRoot:                  hostRoot,
		netIfaces:                 filter,
		publicIPRefreshInterval:   defaultPublicIPRefreshInterval,
		publicIPLookup:            newPublicIPLookup(defaultPublicIPLookupTimeout),
		staticInfoRefreshInterval: defaultStaticInfoRefreshInterval,
		blockPartitionAttr:        make(map[string]bool),
		blockDeviceTotal:          make(map[string]uint64),
		mountpointIsDir:           make(map[string]bool),
	}
	_, _ = cpu.Percent(0, false)
	return collector
}

func (c *Collector) Collect() NodeStats {
	now := time.Now()

	cpuPercents, err := cpu.Percent(0, false)
	c.warnOnce("cpu.Percent", err)
	usage := 0.0
	if len(cpuPercents) > 0 {
		usage = cpuPercents[0]
	}

	loadAvg, err := load.Avg()
	c.warnOnce("load.Avg", err)
	memStat := c.collectMemoryStat()
	var partitions []disk.PartitionStat
	if strings.TrimSpace(c.hostRoot) == "" {
		if c.partitionsCachedAt.IsZero() || now.Sub(c.partitionsCachedAt) >= partitionsRefreshInterval {
			if list, err := disk.Partitions(false); err == nil {
				c.partitionsCache = list
				c.partitionsCachedAt = now
			} else {
				c.warnOnce("disk.Partitions", err)
			}
		}
		partitions = c.partitionsCache
	}
	staticInfoRefreshed := c.refreshStaticInfoAt(now, partitions)

	diskUsage := c.collectDiskUsage(now, partitions)

	diskCounters, err := disk.IOCounters()
	c.warnOnce("disk.IOCounters", err)
	diskRead, diskWrite := sumDiskIOBytesWithCache(diskCounters, c.hostRoot, c.blockPartitionAttr, c.readBlockDeviceSlaves)

	netFilter := c.resolveNetFilterAt(now)
	netCounters, err := gnet.IOCounters(true)
	c.warnOnce("net.IOCounters", err)
	netStat := sumNetCounters(netCounters, netFilter)

	hostname, uptime, processCount := c.sampleHostIdentityAt(now)
	if hostName := c.readHostHostnameAt(now); hostName != "" {
		hostname = hostName
	}
	tcpConns, udpConns := c.sampleConnectionCountsAt(now)

	netSpeedMbps := c.collectNetSpeedMbpsAt(now, netFilter, netCounters)
	publicIPs := c.currentPublicIPs(now)
	gpuStats, gpuSampled := c.collectGPUStatsAt(now, staticInfoRefreshed, nil)
	loadStat := valueOrZero(loadAvg)
	memoryStat := valueOrZero(memStat)
	stats := NodeStats{
		NodeID:          c.nodeID,
		NodeName:        c.nodeName,
		Hostname:        hostname,
		PublicIPv4:      publicIPs.IPv4,
		PublicIPv6:      publicIPs.IPv6,
		StaticInfo:      staticInfoRefreshed,
		StaticUpdatedAt: c.staticInfoUpdatedAt.Unix(),
		UptimeSec:       uptime,
		Timestamp:       now.Unix(),
		NetSpeedMbps:    netSpeedMbps,
		CPU: CPUInfo{
			UsagePercent: usage,
			Load1:        loadStat.Load1,
			Load5:        loadStat.Load5,
			Load15:       loadStat.Load15,
		},
		Memory: MemInfo{
			Total:       memoryStat.Total,
			Used:        memoryStat.Used,
			Free:        memoryStat.Free,
			UsedPercent: memoryStat.UsedPercent,
		},
		Disk: diskUsage,
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
		GPU:          gpuStats,
		GPUCollected: gpuSampled,
	}
	stats.OS = c.staticInfo.OS
	stats.Arch = c.staticInfo.Arch
	stats.CPU.Model = c.staticInfo.CPUModel
	stats.CPU.Cores = c.staticInfo.Cores
	stats.DiskType = c.staticInfo.DiskType

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
	SanitizeNodeStats(&stats)

	return stats
}

func SanitizeNodeStats(stats *NodeStats) {
	if stats == nil {
		return
	}
	stats.NetSpeedMbps = finiteNonNegative(stats.NetSpeedMbps)
	stats.CPU.UsagePercent = clampPercent(stats.CPU.UsagePercent)
	stats.CPU.Load1 = finiteNonNegative(stats.CPU.Load1)
	stats.CPU.Load5 = finiteNonNegative(stats.CPU.Load5)
	stats.CPU.Load15 = finiteNonNegative(stats.CPU.Load15)
	stats.Memory.UsedPercent = clampPercent(stats.Memory.UsedPercent)
	stats.DiskIO.ReadBytesPerSec = finiteNonNegative(stats.DiskIO.ReadBytesPerSec)
	stats.DiskIO.WriteBytesPerSec = finiteNonNegative(stats.DiskIO.WriteBytesPerSec)
	stats.Network.TxBytesPerSec = finiteNonNegative(stats.Network.TxBytesPerSec)
	stats.Network.RxBytesPerSec = finiteNonNegative(stats.Network.RxBytesPerSec)
	for i := range stats.Disk {
		stats.Disk[i].UsedPercent = clampPercent(stats.Disk[i].UsedPercent)
	}
	for i := range stats.GPU {
		stats.GPU[i].UtilizationPercent = clampPercent(stats.GPU[i].UtilizationPercent)
		stats.GPU[i].MemoryUsedPercent = clampPercent(stats.GPU[i].MemoryUsedPercent)
		stats.GPU[i].TemperatureC = finiteOrZero(stats.GPU[i].TemperatureC)
		stats.GPU[i].PowerW = finiteNonNegative(stats.GPU[i].PowerW)
	}
	for i := range stats.NetworkTests {
		stats.NetworkTests[i].PacketLoss = clampPercent(stats.NetworkTests[i].PacketLoss)
		if latency := stats.NetworkTests[i].LatencyMs; latency != nil {
			value := finiteNonNegative(*latency)
			stats.NetworkTests[i].LatencyMs = &value
		}
	}
}

func finiteOrZero(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

func finiteNonNegative(value float64) float64 {
	value = finiteOrZero(value)
	if value < 0 {
		return 0
	}
	return value
}

func (c *Collector) sampleHostIdentityAt(now time.Time) (string, uint64, int) {
	if !c.bootTimeOK {
		if bt, err := host.BootTime(); err == nil && bt > 0 {
			c.bootTime = bt
			c.bootTimeOK = true
		} else {
			c.warnOnce("host.BootTime", err)
		}
	}
	var uptime uint64
	if c.bootTimeOK {
		if secs := now.Unix() - int64(c.bootTime); secs > 0 {
			uptime = uint64(secs)
		}
	}
	if c.hostProcs <= 0 || now.Sub(c.hostIdentityAt) >= hostProcsRefreshInterval {
		if hostInfo, err := host.Info(); err == nil && hostInfo != nil {
			c.hostProcs = int(hostInfo.Procs)
			c.hostHostnameFallback = hostInfo.Hostname
			c.hostIdentityAt = now
		} else {
			c.warnOnce("host.Info", err)
		}
	}
	return c.hostHostnameFallback, uptime, c.hostProcs
}

func (c *Collector) refreshStaticInfoAt(now time.Time, partitions []disk.PartitionStat) bool {
	interval := c.staticInfoRefreshInterval
	if interval <= 0 {
		interval = defaultStaticInfoRefreshInterval
	}
	if c.staticInfoInitialized && now.Sub(c.staticInfoUpdatedAt) < interval {
		return false
	}
	if partitions == nil {
		var err error
		partitions, err = disk.Partitions(false)
		c.warnOnce("disk.Partitions", err)
	}
	next := collectorStaticInfo{
		Arch:     detectArch(),
		DiskType: detectDiskType(partitions, c.hostRoot),
	}
	next.CPUModel, next.Cores = readHostCPUInfo(c.hostRoot)
	if next.CPUModel == "" {
		cpuInfos, _ := cpu.Info()
		if len(cpuInfos) > 0 {
			next.CPUModel = strings.TrimSpace(cpuInfos[0].ModelName)
		}
	}
	if next.Cores <= 0 {
		if coreCount, err := cpu.Counts(true); err == nil && coreCount > 0 {
			next.Cores = coreCount
		}
	}
	if hostInfo, _ := host.Info(); hostInfo != nil {
		next.OS = normalizeOSLabel(hostInfo.Platform, hostInfo.PlatformVersion)
		if normalized := normalizeArch(hostInfo.KernelArch); normalized != "" {
			next.Arch = normalized
		}
	}
	if hostOS := readHostOSRelease(c.hostRoot); hostOS != "" {
		next.OS = normalizeOSLabel(hostOS, "")
	}
	c.staticInfo = next
	c.staticInfoInitialized = true
	c.staticInfoUpdatedAt = now
	return true
}

// sampleConnectionCountsAt 每 5 秒刷新一次 TCP / UDP 连接数，其余 tick 复用上次结果。
func (c *Collector) sampleConnectionCountsAt(now time.Time) (int, int) {
	if c.prevConnAt.IsZero() || now.Sub(c.prevConnAt) >= 5*time.Second {
		c.prevTCP, c.prevUDP = readConnectionCounts()
		c.prevConnAt = now
	}
	return c.prevTCP, c.prevUDP
}

func (c *Collector) warnOnce(source string, err error) {
	if err == nil {
		return
	}
	c.sourceWarningsMu.Lock()
	defer c.sourceWarningsMu.Unlock()
	if c.sourceWarningsShown == nil {
		c.sourceWarningsShown = make(map[string]struct{})
	}
	if _, shown := c.sourceWarningsShown[source]; shown {
		return
	}
	c.sourceWarningsShown[source] = struct{}{}
	log.Printf("指标源 %s 采集失败: %v", source, err)
}

func (c *Collector) resolveNetFilterAt(now time.Time) map[string]struct{} {
	if len(c.netIfaces) > 0 {
		return c.netIfaces
	}
	if !c.resolvedNetFilterAt.IsZero() && now.Sub(c.resolvedNetFilterAt) < netFilterRefreshInterval {
		return c.resolvedNetFilter
	}
	if counters, err := gnet.IOCounters(true); err == nil {
		c.resolvedNetFilter = buildDefaultInterfaceFilter(counters, c.readInterfaceMasterName, c.isAggregatingMaster, c.readInterfaceLowerName)
		c.resolvedNetFilterAt = now
	}
	return c.resolvedNetFilter
}

func (c *Collector) collectNetSpeedMbpsAt(now time.Time, filter map[string]struct{}, netCounters []gnet.IOCountersStat) float64 {
	if !c.netSpeedSampledAt.IsZero() && now.Sub(c.netSpeedSampledAt) < netSpeedRefreshInterval {
		return c.netSpeedMbps
	}
	c.netSpeedMbps = collectNetSpeedMbps(c.hostRoot, filter, netCounters)
	c.netSpeedSampledAt = now
	return c.netSpeedMbps
}

func (c *Collector) readHostHostnameAt(now time.Time) string {
	if c.hostHostnameAt.IsZero() || now.Sub(c.hostHostnameAt) >= hostHostnameRefreshInterval {
		c.hostHostname = readHostHostname(c.hostRoot)
		c.hostHostnameAt = now
	}
	return c.hostHostname
}

func (c *Collector) currentPublicIPs(now time.Time) publicIPInfo {
	c.publicIPsMu.Lock()
	defer c.publicIPsMu.Unlock()
	refreshInterval := c.publicIPRefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = defaultPublicIPRefreshInterval
	}
	retryInterval := refreshInterval
	if c.publicIPs.IPv4 == "" && c.publicIPs.IPv6 == "" && retryInterval > defaultPublicIPRetryInterval {
		retryInterval = defaultPublicIPRetryInterval
	}
	if !c.publicIPs.checkedAt.IsZero() && now.Sub(c.publicIPs.checkedAt) < retryInterval {
		return c.publicIPs
	}
	if c.publicIPLookup == nil {
		c.publicIPs.checkedAt = now
		return c.publicIPs
	}
	if c.publicIPRefreshRunning {
		return c.publicIPs
	}
	c.publicIPRefreshRunning = true
	go c.refreshPublicIPs()
	return c.publicIPs
}

func (c *Collector) refreshPublicIPs() {
	defer func() {
		c.publicIPsMu.Lock()
		c.publicIPRefreshRunning = false
		c.publicIPsMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), publicIPLookupTotalBudget(defaultPublicIPLookupTimeout))
	defer cancel()
	type lookupResult struct {
		family publicIPFamily
		ip     string
	}

	familiesToCheck := []publicIPFamily{publicIPv4Family, publicIPv6Family}
	results := make(chan lookupResult, len(familiesToCheck))
	for _, family := range familiesToCheck {
		go func(family publicIPFamily) {
			normalized, err := c.lookupPublicIPAt(ctx, family)
			if err != nil {
				c.warnOnce("publicIP."+string(family), err)
			}
			if err != nil || normalized == "" {
				results <- lookupResult{family: family}
				return
			}
			results <- lookupResult{family: family, ip: normalized}
		}(family)
	}

	next := publicIPInfo{checkedAt: time.Now()}
	for range len(familiesToCheck) {
		result := <-results
		switch result.family {
		case publicIPv4Family:
			next.IPv4 = result.ip
		case publicIPv6Family:
			next.IPv6 = result.ip
		}
	}
	c.publicIPsMu.Lock()
	defer c.publicIPsMu.Unlock()
	if next.IPv4 == "" {
		next.IPv4 = c.publicIPs.IPv4
	}
	if next.IPv6 == "" {
		next.IPv6 = c.publicIPs.IPv6
	}
	c.publicIPs = next
}

func (c *Collector) lookupPublicIPAt(ctx context.Context, family publicIPFamily) (string, error) {
	if c == nil || c.publicIPLookup == nil {
		return "", nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	value, err := c.publicIPLookup(ctx, family)
	if err != nil {
		return "", err
	}
	return normalizePublicIPAddress(family, value), nil
}

func newPublicIPLookup(timeout time.Duration) publicIPLookupFunc {
	if timeout <= 0 {
		timeout = defaultPublicIPLookupTimeout
	}
	return func(ctx context.Context, family publicIPFamily) (string, error) {
		return lookupPublicIPAddress(ctx, family, timeout, defaultPublicIPEndpointsForFamily(family))
	}
}

func defaultPublicIPEndpointsForFamily(family publicIPFamily) []string {
	switch family {
	case publicIPv6Family:
		return defaultPublicIPv6Endpoints
	default:
		return defaultPublicIPv4Endpoints
	}
}

func publicIPLookupTotalBudget(perEndpoint time.Duration) time.Duration {
	maxEndpoints := len(defaultPublicIPv4Endpoints)
	if n := len(defaultPublicIPv6Endpoints); n > maxEndpoints {
		maxEndpoints = n
	}
	return perEndpoint * time.Duration(maxEndpoints)
}

func lookupPublicIPAddress(
	ctx context.Context,
	family publicIPFamily,
	timeout time.Duration,
	endpoints []string,
) (string, error) {
	if len(endpoints) == 0 {
		return "", nil
	}
	if timeout <= 0 {
		timeout = defaultPublicIPLookupTimeout
	}
	network := "tcp4"
	if family == publicIPv6Family {
		network = "tcp6"
	}

	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(callCtx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(callCtx, network, addr)
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	var lastErr error
	for _, endpoint := range endpoints {
		reqCtx, cancel := context.WithTimeout(baseCtx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "CyberMonitor-Agent")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			cancel()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= http.StatusMultipleChoices {
			lastErr = fmt.Errorf("endpoint %s: HTTP %d", endpoint, resp.StatusCode)
			continue
		}
		if normalized := extractPublicIPAddress(family, string(body)); normalized != "" {
			return normalized, nil
		}
		lastErr = fmt.Errorf("endpoint %s: 响应无法解析为公网 IP", endpoint)
	}
	return "", lastErr
}

func extractPublicIPAddress(family publicIPFamily, raw string) string {
	if normalized := normalizePublicIPAddress(family, raw); normalized != "" {
		return normalized
	}

	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	return normalizePublicIPAddress(family, payload.IP)
}

func normalizePublicIPAddress(family publicIPFamily, raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	switch family {
	case publicIPv4Family:
		if !addr.Is4() {
			return ""
		}
	case publicIPv6Family:
		if !addr.Is6() || addr.Is4In6() {
			return ""
		}
	default:
		return ""
	}
	return addr.String()
}

func (c *Collector) collectMemoryStat() *mem.VirtualMemoryStat {
	memStat, err := mem.VirtualMemory()
	c.warnOnce("mem.VirtualMemory", err)
	return memStat
}

func valueOrZero[T any](val *T) *T {
	if val == nil {
		var zero T
		return &zero
	}
	return val
}

func diffUint64(current, prev uint64) uint64 {
	if current >= prev {
		return current - prev
	}
	return 0
}

func sumNetCounters(stats []gnet.IOCountersStat, filter map[string]struct{}) gnet.IOCountersStat {
	var total gnet.IOCountersStat
	for _, stat := range stats {
		if !shouldCollectInterface(stat.Name, filter) {
			continue
		}
		total.BytesSent += stat.BytesSent
		total.BytesRecv += stat.BytesRecv
	}
	return total
}

func shouldCollectInterface(name string, filter map[string]struct{}) bool {
	normalized := normalizeInterfaceName(name)
	if normalized == "" {
		return false
	}
	if len(filter) > 0 {
		_, ok := filter[normalized]
		return ok
	}
	return !isVirtualInterface(normalized)
}

func buildDefaultInterfaceFilter(
	stats []gnet.IOCountersStat,
	readMaster func(string) string,
	isAggregatingMaster func(string) bool,
	readLower func(string) string,
) map[string]struct{} {
	if len(stats) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(stats))
	for _, stat := range stats {
		if name := normalizeInterfaceName(stat.Name); name != "" {
			known[name] = struct{}{}
		}
	}
	resolved := make(map[string]struct{}, len(stats))
	for _, stat := range stats {
		if shouldIgnoreDefaultInterface(stat.Name, readMaster, isAggregatingMaster, readLower, known) {
			continue
		}
		name := normalizeInterfaceName(stat.Name)
		if name == "" {
			continue
		}
		resolved[name] = struct{}{}
	}
	if len(resolved) == 0 {
		return nil
	}
	return resolved
}

func shouldIgnoreDefaultInterface(
	name string,
	readMaster func(string) string,
	isAggregatingMaster func(string) bool,
	readLower func(string) string,
	knownInterfaces map[string]struct{},
) bool {
	normalized := normalizeInterfaceName(name)
	if normalized == "" {
		return true
	}
	if isVirtualInterface(normalized) {
		return true
	}
	if readMaster != nil && len(knownInterfaces) > 0 {
		master := normalizeInterfaceName(readMaster(name))
		if _, inCounters := knownInterfaces[master]; inCounters && isAggregatingMaster(master) {
			return true
		}
	}
	if readLower != nil && len(knownInterfaces) > 0 {
		lower := normalizeInterfaceName(readLower(name))
		if lower != "" {
			if _, inCounters := knownInterfaces[lower]; inCounters {
				return true
			}
		}
	}
	return false
}

func (c *Collector) isAggregatingMaster(master string) bool {
	if runtime.GOOS != "linux" || master == "" {
		return false
	}
	base := hostSysPath(c.hostRoot, "class", "net", canonicalInterfaceName(master))
	for _, marker := range []string{"bridge", "bonding"} {
		if info, err := os.Stat(filepath.Join(base, marker)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func isVirtualInterface(name string) bool {
	lower := normalizeInterfaceName(name)
	virtualPrefixes := []string{
		"lo", "loopback", "docker", "veth", "br-", "virbr", "vmnet", "utun",
		"tun", "tap", "wg", "tailscale", "zt", "vboxnet", "ham", "bridge",
		"awdl", "llw",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func normalizeInterfaceName(name string) string {
	return strings.ToLower(canonicalInterfaceName(name))
}

func canonicalInterfaceName(name string) string {
	trimmed := strings.TrimSpace(name)
	if idx := strings.Index(trimmed, "@"); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func hostSysPath(hostRoot string, rel ...string) string {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root, "sys"}, rel...)...)
}

func (c *Collector) readInterfaceMasterName(name string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	ifaceName := canonicalInterfaceName(name)
	if ifaceName == "" {
		return ""
	}
	target, err := os.Readlink(hostSysPath(c.hostRoot, "class", "net", ifaceName, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// readInterfaceLowerName 返回叠加设备（VLAN/macvlan 等子接口）的下层设备名。
// 判定完全基于 sysfs 的 iflink/ifindex 关系，与接口命名无关：iflink != ifindex
// 说明该接口挂在下层设备之上。物理口与聚合主口（bridge/bond）自身 iflink == ifindex，
// 返回 ""。非 Linux 一律返回 ""。
func (c *Collector) readInterfaceLowerName(name string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	ifaceName := canonicalInterfaceName(name)
	if ifaceName == "" {
		return ""
	}
	base := hostSysPath(c.hostRoot, "class", "net", ifaceName)
	iflink, iflinkErr := readSysfsInt(filepath.Join(base, "iflink"))
	ifindex, ifindexErr := readSysfsInt(filepath.Join(base, "ifindex"))
	if iflinkErr == nil && ifindexErr == nil {
		if iflink == ifindex {
			return ""
		}
		if parent := c.lookupInterfaceByIfindex(iflink); parent != "" {
			return parent
		}
	}
	// 兜底：内核 >= 4.11 提供的 lower_<parent> 符号链接。
	return readInterfaceLowerLinkName(base)
}

// lookupInterfaceByIfindex 把 ifindex 映射回 /sys/class/net 下的接口名。
func (c *Collector) lookupInterfaceByIfindex(ifindex int) string {
	dir := hostSysPath(c.hostRoot, "class", "net")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		raw, err := readSysfsInt(filepath.Join(dir, entry.Name(), "ifindex"))
		if err != nil {
			continue
		}
		if raw == ifindex {
			return entry.Name()
		}
	}
	return ""
}

// readInterfaceLowerLinkName 从 lower_<parent> 符号链接解析下层设备名。
func readInterfaceLowerLinkName(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "lower_") {
			continue
		}
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		return filepath.Base(target)
	}
	return ""
}

func readSysfsInt(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(raw)))
}

func collectNetSpeedMbps(hostRoot string, filter map[string]struct{}, netCounters []gnet.IOCountersStat) float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	maxSpeed := 0.0
	for _, stat := range netCounters {
		if !shouldCollectInterface(stat.Name, filter) {
			continue
		}
		if speed := readInterfaceSpeedMbps(hostRoot, stat.Name); speed > maxSpeed {
			maxSpeed = speed
		}
	}
	return maxSpeed
}

func readInterfaceSpeedMbps(hostRoot, name string) float64 {
	if name == "" {
		return 0
	}
	raw, err := os.ReadFile(hostSysPath(hostRoot, "class", "net", canonicalInterfaceName(name), "speed"))
	if err != nil {
		return 0
	}
	return parseSpeedMbps(string(raw))
}

func parseSpeedMbps(raw string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed <= 0 {
		return 0
	}
	return parsed
}

func sumDiskIOBytesWithCache(counters map[string]disk.IOCountersStat, hostRoot string, partitionAttr map[string]bool, readSlaves func(string) []string) (uint64, uint64) {
	var read, write uint64
	for name, stat := range counters {
		if isVirtualBlockDevice(name, hostRoot, partitionAttr) {
			continue
		}
		if isPartitionOfCountedDisk(name, counters) {
			continue
		}
		if isAggregatingBlockDevice(name, counters, readSlaves) {
			continue
		}
		read += stat.ReadBytes
		write += stat.WriteBytes
	}
	return read, write
}

// isAggregatingBlockDevice 判断 name 是否为「叠加块设备」——即其底层成员整盘
// 同时出现在本次 counters 中。dm-*（LVM/LUKS）与 md*（MD RAID）自身与其底层整盘
// 都会被 /proc/diskstats 计入，直接相加会把吞吐放大约 2~3 倍。方向与网卡侧相反：
// 保留物理盘、丢弃聚合设备（sda+dm-0 → 只计 sda；sdb+sdc+md0 → 只计 sdb 与 sdc）。
//
// 仅当能读到非空 slaves 且其全部成员都在 counters 中时才排除；slaves 为空、读取失败
// （容器无 /sys）或成员不全在 counters 中时一律保守返回 false（照常计入），避免误删
// 真实物理盘或孤立的叠加设备（例如 counters 只有 dm-0 时必须计 dm-0）。
func isAggregatingBlockDevice(name string, counters map[string]disk.IOCountersStat, readSlaves func(string) []string) bool {
	if readSlaves == nil || len(counters) == 0 {
		return false
	}
	slaves := readSlaves(name)
	if len(slaves) == 0 {
		return false
	}
	for _, slave := range slaves {
		if _, exists := counters[slave]; !exists {
			return false
		}
	}
	return true
}

func isPartitionOfCountedDisk(name string, counters map[string]disk.IOCountersStat) bool {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	if i == 0 || i == len(name) {
		return false
	}
	switch name[i-1] {
	case 'p', 's': // p 分隔样式：nvme0n1p1 / mmcblk0p1
		if _, exists := counters[name[:i-1]]; exists {
			return true
		}
	}
	// ponytail: 数字结尾样式（sda1/vda3/xvda2）靠“基名在 counters 中”判别，
	// md12+md126 这类多位数设备族同名碰撞会误判，容器无 /sys 场景几乎不遇，
	// 遇到时需读 sysfs 分区属性。
	_, exists := counters[name[:i]]
	return exists
}

func isVirtualBlockDevice(name, hostRoot string, partitionAttr map[string]bool) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	normalized := strings.TrimSpace(name)
	if strings.HasPrefix(normalized, "loop") || strings.HasPrefix(normalized, "ram") || strings.HasPrefix(normalized, "zram") {
		return true
	}
	if isPartition, ok := partitionAttr[normalized]; ok {
		return isPartition
	}
	_, err := os.Stat(hostSysPath(hostRoot, "class", "block", normalized, "partition"))
	isPartition := err == nil
	partitionAttr[normalized] = isPartition
	return isPartition
}

// readBlockDeviceSlaves 返回叠加块设备（dm-*/md* 等）在 sysfs 下的底层成员设备名。
// dm（LVM/LUKS）与 md（MD RAID）的成员会出现在 class/block/<name>/slaves 下。
// 目录不存在、读取失败或非 Linux 时一律返回 nil——调用方据此保守处理，不排除任何设备，
// 从而在容器无 /sys 场景下避免误删真实物理盘。注入该函数即可让测试脱离宿主机 /sys。
func (c *Collector) readBlockDeviceSlaves(name string) []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	deviceName := strings.TrimSpace(name)
	if deviceName == "" {
		return nil
	}
	entries, err := os.ReadDir(hostSysPath(c.hostRoot, "class", "block", deviceName, "slaves"))
	if err != nil {
		return nil
	}
	slaves := make([]string, 0, len(entries))
	for _, entry := range entries {
		if slave := strings.TrimSpace(entry.Name()); slave != "" {
			slaves = append(slaves, slave)
		}
	}
	return slaves
}

func (c *Collector) collectDiskUsage(now time.Time, partitions []disk.PartitionStat) []DiskPartition {
	if hostUsage := c.collectHostDiskUsage(now); len(hostUsage) > 0 {
		return hostUsage
	}

	if hostRoot := strings.TrimSpace(c.hostRoot); hostRoot != "" && isDir(hostRoot) {
		if usageStat, err := statFilesystemUsage(hostRoot); err == nil {
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

	candidates := make([]mountCandidate, 0, len(partitions))
	for _, p := range partitions {
		candidates = append(candidates, mountCandidate{
			Device:     p.Device,
			Mountpoint: p.Mountpoint,
			Fstype:     p.Fstype,
			StatPath:   p.Mountpoint,
			ReadOnly:   slices.Contains(p.Opts, "ro"),
		})
	}
	return collectPartitionUsageCached(candidates, c.mountpointIsDir, c.blockDeviceTotal)
}

type filesystemUsage struct {
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
	Fstype      string
}

type hostMount struct {
	Device     string
	Mountpoint string
	Fstype     string
	ReadOnly   bool
}

type mountCandidate struct {
	Device     string
	Mountpoint string
	Fstype     string
	StatPath   string
	ReadOnly   bool
}

func (c *Collector) collectHostDiskUsage(now time.Time) []DiskPartition {
	hostRoot := strings.TrimSpace(c.hostRoot)
	if hostRoot == "" || !isDir(hostRoot) {
		return nil
	}

	mounts, err := c.readHostMountsAt(now)
	if err != nil || len(mounts) == 0 {
		return nil
	}

	candidates := make([]mountCandidate, 0, len(mounts))
	for _, mount := range mounts {
		candidates = append(candidates, mountCandidate{
			Device:     mount.Device,
			Mountpoint: mount.Mountpoint,
			Fstype:     mount.Fstype,
			StatPath:   resolveHostMountPath(hostRoot, mount.Mountpoint),
			ReadOnly:   mount.ReadOnly,
		})
	}
	return collectPartitionUsageCached(candidates, c.mountpointIsDir, c.blockDeviceTotal)
}

func (c *Collector) readHostMountsAt(now time.Time) ([]hostMount, error) {
	if !c.hostMountsAt.IsZero() && now.Sub(c.hostMountsAt) < hostMountsRefreshInterval {
		return c.hostMounts, nil
	}
	mounts, err := readHostMounts(c.hostRoot)
	if err != nil {
		return nil, err
	}
	c.hostMounts = mounts
	c.hostMountsAt = now
	return mounts, nil
}

var apfsContainerDevicePattern = regexp.MustCompile(`^(/dev/disk\d+)(?:s\d+)+$`)

func apfsContainerDevice(fstype, device string) string {
	if !strings.EqualFold(strings.TrimSpace(fstype), "apfs") {
		return device
	}
	if match := apfsContainerDevicePattern.FindStringSubmatch(device); match != nil {
		return match[1]
	}
	return device
}

func collectPartitionUsageCached(candidates []mountCandidate, mountpointDirCache map[string]bool, blockTotalCache map[string]uint64) []DiskPartition {
	seenMountpoints := make(map[string]struct{})
	seenDevices := make(map[string]struct{})
	apfsEntryIndex := make(map[string]int)
	diskUsage := make([]DiskPartition, 0, len(candidates))
	for _, candidate := range candidates {
		device := strings.TrimSpace(candidate.Device)
		if device == "" {
			continue
		}
		if shouldSkipPartition(disk.PartitionStat{
			Device:     device,
			Mountpoint: candidate.Mountpoint,
			Fstype:     candidate.Fstype,
		}, mountpointDirCache) {
			continue
		}
		// B-06：只读挂载（ISO、只读镜像卷等）不参与总硬盘口径；只读的根分区
		// 仍保留（系统盘本身可能被以 ro 挂载）。
		if candidate.ReadOnly && candidate.Mountpoint != "/" {
			continue
		}
		if _, exists := seenMountpoints[candidate.Mountpoint]; exists {
			continue
		}
		deviceKey := apfsContainerDevice(candidate.Fstype, device)
		if device != "none" {
			if _, exists := seenDevices[deviceKey]; exists {
				if index, ok := apfsEntryIndex[deviceKey]; ok && candidate.Mountpoint == "/" && diskUsage[index].Mountpoint != "/" {
					diskUsage[index].Device = deviceKey
					diskUsage[index].Mountpoint = candidate.Mountpoint
				}
				continue
			}
		}

		usageStat, err := statFilesystemUsage(candidate.StatPath)
		if err != nil {
			continue
		}
		seenMountpoints[candidate.Mountpoint] = struct{}{}
		if device != "none" {
			seenDevices[deviceKey] = struct{}{}
		}
		if candidate.Fstype != "" {
			usageStat.Fstype = candidate.Fstype
		}
		total := resolvePartitionTotalCached(device, usageStat.Total, blockTotalCache)
		if usageStat.Used > total {
			total = usageStat.Total
		} else if total != usageStat.Total {
			usageStat.UsedPercent = percentOf(usageStat.Used, total)
		}
		usageStat.Total = total

		entryDevice := device
		if deviceKey != device {
			entryDevice = deviceKey
			apfsEntryIndex[deviceKey] = len(diskUsage)
		}
		diskUsage = append(diskUsage, DiskPartition{
			Device:      entryDevice,
			Mountpoint:  candidate.Mountpoint,
			Fstype:      usageStat.Fstype,
			Total:       usageStat.Total,
			Used:        usageStat.Used,
			Free:        usageStat.Free,
			UsedPercent: usageStat.UsedPercent,
		})
	}
	return diskUsage
}

func resolvePartitionTotalCached(device string, statTotal uint64, totalCache map[string]uint64) (total uint64) {
	if sysfsBlockName(device) == "" {
		return statTotal
	}
	if totalCache != nil {
		if cached, ok := totalCache[device]; ok {
			return cached
		}
	}
	defer func() {
		if totalCache != nil {
			totalCache[device] = total
		}
	}()
	if size := readBlockDeviceSizeBytes(sysfsBlockName(device)); size > 0 {
		return size
	}
	if resolved, err := filepath.EvalSymlinks(device); err == nil {
		if name := sysfsBlockName(resolved); name != "" {
			if size := readBlockDeviceSizeBytes(name); size > 0 {
				return size
			}
		}
	}
	return statTotal
}

func sysfsBlockName(device string) string {
	device = strings.TrimSpace(device)
	if !strings.HasPrefix(device, "/dev/") {
		return ""
	}
	name := strings.Trim(strings.TrimPrefix(device, "/dev/"), "/")
	if name == "" {
		return ""
	}
	return name
}

func readBlockDeviceSizeBytes(name string) uint64 {
	data, err := os.ReadFile(filepath.Join("/sys/class/block", name, "size"))
	if err != nil {
		return 0
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return sectors * 512
}

var skipMountPrefixes = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/run/user",
	"/run/credentials",
	"/var/run",
	"/etc",
	"/snap",
	"/var/snap",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/containers",
	"/var/lib/kubelet",
	"/var/lib/flatpak",
	// B-06：macOS 只读镜像卷与系统卷（根分区已代表整个 APFS 容器，由
	// apfsContainerDevice 去重，跳过 /System/Volumes/* 不会少算用户数据）。
	"/Library/Developer/CoreSimulator",
	"/System/Volumes",
}

var skipFilesystems = map[string]struct{}{
	"proc":        {},
	"sysfs":       {},
	"tmpfs":       {},
	"devtmpfs":    {},
	"squashfs":    {},
	"overlay":     {},
	"aufs":        {},
	"ramfs":       {},
	"autofs":      {},
	"securityfs":  {},
	"pstore":      {},
	"hugetlbfs":   {},
	"configfs":    {},
	"cgroup":      {},
	"cgroup2":     {},
	"devpts":      {},
	"mqueue":      {},
	"debugfs":     {},
	"tracefs":     {},
	"fusectl":     {},
	"binfmt_misc": {},
	"rpc_pipefs":  {},
	"nsfs":        {},
	"bpf":         {},
	"lxcfs":       {},
	"nfs":         {},
	"nfs4":        {},
	"cifs":        {},
	"smbfs":       {},
	"smb2":        {},
	"9p":          {},
	"virtiofs":    {},
	"afs":         {},
	"ceph":        {},
	"cephfs":      {},
	"glusterfs":   {},
	"lustre":      {},
	"gfs":         {},
	"gfs2":        {},
	"ocfs2":       {},
	"beegfs":      {},
	"sshfs":       {},
	"fdescfs":     {},
	// B-06：虚拟 / 只读文件系统（devicefs 挂载在 CoreDevice 下、nullfs、
	// iso9660 与 udf 光盘镜像）不参与「服务器总硬盘」口径。
	"devicefs": {},
	"nullfs":   {},
	"iso9660":  {},
	"udf":      {},
}

func shouldSkipPartition(p disk.PartitionStat, mountpointDirCache map[string]bool) bool {
	if p.Mountpoint == "" || p.Mountpoint == "none" {
		return true
	}
	if isDir, ok := mountpointDirCache[p.Mountpoint]; ok {
		if !isDir {
			return true
		}
	} else if info, err := os.Stat(p.Mountpoint); err == nil && !info.IsDir() {
		mountpointDirCache[p.Mountpoint] = false
		return true
	} else if err == nil {
		mountpointDirCache[p.Mountpoint] = true
	}
	mountpoint := filepath.Clean(strings.TrimSpace(p.Mountpoint))
	for _, prefix := range skipMountPrefixes {
		if mountpoint == prefix || strings.HasPrefix(mountpoint, prefix+"/") {
			return true
		}
	}
	fstype := strings.ToLower(p.Fstype)
	if _, ok := skipFilesystems[fstype]; ok && p.Mountpoint != "/" {
		return true
	}
	if strings.HasPrefix(fstype, "fuse.") {
		return true
	}
	return false
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func percentOf(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return (float64(used) / float64(total)) * 100
}

func resolveHostMountPath(hostRoot, mountpoint string) string {
	cleaned := filepath.Clean("/" + strings.TrimSpace(strings.TrimPrefix(mountpoint, "/")))
	if cleaned == "/" {
		return hostRoot
	}
	return filepath.Join(hostRoot, strings.TrimPrefix(cleaned, "/"))
}

func readHostMounts(hostRoot string) ([]hostMount, error) {
	paths := []string{
		filepath.Join(hostRoot, "proc", "1", "mountinfo"),
		filepath.Join(hostRoot, "proc", "self", "mountinfo"),
		filepath.Join(hostRoot, "proc", "mounts"),
	}
	var lastErr error
	for _, path := range paths {
		mounts, err := readMountFile(path)
		if err == nil && len(mounts) > 0 {
			return mounts, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return nil, lastErr
}

func readMountFile(path string) ([]hostMount, error) {
	if strings.HasSuffix(path, "mountinfo") {
		return parseMountInfoFile(path)
	}
	return parseProcMountsFile(path)
}

// mountOptionsReadOnly 判断挂载选项字段（逗号分隔，如 "rw,relatime"）中是否
// 含精确的 ro token；避免命中 rootcontext= 这类前缀。
func mountOptionsReadOnly(options string) bool {
	for _, opt := range strings.Split(options, ",") {
		if strings.TrimSpace(opt) == "ro" {
			return true
		}
	}
	return false
}

func parseMountInfoFile(path string) ([]hostMount, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	mounts := make([]hostMount, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 2 {
			continue
		}
		mount := hostMount{
			Device:     decodeMountField(right[1]),
			Mountpoint: decodeMountField(left[4]),
			Fstype:     decodeMountField(right[0]),
		}
		// B-06：第 6 列为挂载选项（rw / ro,relatime …），从中识别只读挂载。
		if len(left) >= 6 {
			mount.ReadOnly = mountOptionsReadOnly(decodeMountField(left[5]))
		}
		mounts = append(mounts, mount)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func parseProcMountsFile(path string) ([]hostMount, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	mounts := make([]hostMount, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 3 {
			continue
		}
		mount := hostMount{
			Device:     decodeMountField(fields[0]),
			Mountpoint: decodeMountField(fields[1]),
			Fstype:     decodeMountField(fields[2]),
		}
		// B-06：第 4 列为挂载选项（rw / ro,relatime …），从中识别只读挂载。
		if len(fields) >= 4 {
			mount.ReadOnly = mountOptionsReadOnly(decodeMountField(fields[3]))
		}
		mounts = append(mounts, mount)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func decodeMountField(value string) string {
	if !strings.ContainsRune(value, '\\') {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) && isOctalDigit(value[i+1]) && isOctalDigit(value[i+2]) && isOctalDigit(value[i+3]) {
			decoded, err := strconv.ParseUint(value[i+1:i+4], 8, 8)
			if err == nil {
				builder.WriteByte(byte(decoded))
				i += 3
				continue
			}
		}
		builder.WriteByte(value[i])
	}
	return builder.String()
}

func isOctalDigit(value byte) bool {
	return value >= '0' && value <= '7'
}

func readHostOSRelease(hostRoot string) string {
	if hostRoot == "" {
		return ""
	}
	file, err := openHostRootFile(hostRoot, filepath.Join("etc", "os-release"))
	if err != nil {
		file, err = openHostRootFile(hostRoot, filepath.Join("usr", "lib", "os-release"))
	}
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

func openHostRootFile(hostRoot, relativePath string) (*os.File, error) {
	root := filepath.Clean(strings.TrimSpace(hostRoot))
	if root == "" || root == "." {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(root, filepath.Clean(relativePath))
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		if filepath.IsAbs(target) {
			path = filepath.Join(root, strings.TrimPrefix(filepath.Clean(target), string(filepath.Separator)))
		} else {
			path = filepath.Join(filepath.Dir(path), target)
		}
	}
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	return os.Open(path)
}

func readHostCPUInfo(hostRoot string) (string, int) {
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		return "", 0
	}
	file, err := os.Open(filepath.Join(root, "proc", "cpuinfo"))
	if err != nil {
		return "", 0
	}
	defer file.Close()

	model := ""
	hardware := ""
	cores := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Join(strings.Fields(value), " ")
		switch key {
		case "processor":
			cores++
		case "model name", "cpu model":
			if model == "" && value != "" {
				model = value
			}
		case "hardware":
			if hardware == "" && value != "" {
				hardware = value
			}
		}
	}
	if model == "" {
		model = hardware
	}
	return model, cores
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

func normalizeArch(value string) string {
	arch := strings.ToLower(strings.TrimSpace(value))
	if arch == "" {
		return ""
	}
	switch arch {
	case "x86_64", "x64", "amd64":
		return "amd64"
	case "i386", "i686", "x86":
		return "386"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l", "arm":
		return "arm"
	default:
		return arch
	}
}

func normalizeOSLabel(platform, version string) string {
	name := strings.TrimSpace(platform)
	if name == "" {
		return ""
	}
	lower := strings.ToLower(name)
	if lower == "darwin" || lower == "macos" || lower == "mac os" || lower == "osx" || lower == "os x" {
		if strings.TrimSpace(version) != "" {
			return "macOS " + strings.TrimSpace(version)
		}
		return "macOS"
	}
	if strings.TrimSpace(version) != "" && !strings.Contains(name, version) {
		return name + " " + strings.TrimSpace(version)
	}
	return name
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

	return ""
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

var lookupNVIDIASMIPath = defaultLookupNVIDIASMIPath

func defaultLookupNVIDIASMIPath() string {
	path, err := exec.LookPath("nvidia-smi")
	if err != nil {
		return ""
	}
	return path
}

type gpuSampler func(path string, includeStatic bool) ([]GPUInfo, error)

// gpuSamplerForOS 返回当前平台的 GPU 采样器，以及该采样器是否依赖 nvidia-smi 路径。
// macOS 不存在 nvidia-smi，改用 IOKit（ioreg）读取 Apple GPU。
func gpuSamplerForOS() (gpuSampler, bool) {
	if runtime.GOOS == "darwin" {
		return runDarwinGPUSample, false
	}
	return runNVIDIAGPUSample, true
}

func (c *Collector) collectGPUStatsAt(
	now time.Time,
	includeStatic bool,
	sampler gpuSampler,
) ([]GPUInfo, bool) {
	needsNVIDIAPath := false
	if sampler == nil {
		sampler, needsNVIDIAPath = gpuSamplerForOS()
	}
	if needsNVIDIAPath {
		if c.nvidiaSMIPathAt.IsZero() || now.Sub(c.nvidiaSMIPathAt) >= nvidiaSMIPathRefreshInterval {
			c.nvidiaSMIPath = lookupNVIDIASMIPath()
			c.nvidiaSMIPathAt = now
		}
		if c.nvidiaSMIPath == "" {
			return nil, true
		}
	}
	fresh := !c.gpuSampleAt.IsZero() && now.Sub(c.gpuSampleAt) < gpuSampleRefreshInterval
	if fresh && (!includeStatic || c.gpuSampleStatic) {
		return c.gpuSample, c.gpuSampleOK
	}
	gpus, err := sampler(c.nvidiaSMIPath, includeStatic)
	if err != nil {
		c.warnOnce("gpu", err)
		c.gpuSample = nil
		c.gpuSampleStatic = includeStatic
		c.gpuSampleAt = now
		c.gpuSampleOK = false
		return nil, false
	}
	c.gpuSample = gpus
	c.gpuSampleStatic = includeStatic
	c.gpuSampleAt = now
	c.gpuSampleOK = true
	return gpus, true
}

func runNVIDIAGPUSample(path string, includeStatic bool) ([]GPUInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx,
		path,
		"--query-gpu=index,uuid,name,driver_version,utilization.gpu,memory.total,memory.used,memory.free,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("采样失败: %w", err)
	}
	gpus, err := parseNVIDIAGPUStats(string(output), includeStatic)
	if err != nil {
		return nil, fmt.Errorf("输出解析失败: %w", err)
	}
	return gpus, nil
}

func parseNVIDIAGPUStats(raw string, includeStatic bool) ([]GPUInfo, error) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	gpus := make([]GPUInfo, 0, len(records))
	for _, record := range records {
		if len(record) < 10 {
			continue
		}
		index, ok := parseOptionalInt(record[0])
		if !ok {
			continue
		}
		totalMiB, _ := parseOptionalFloat(record[5])
		usedMiB, _ := parseOptionalFloat(record[6])
		freeMiB, _ := parseOptionalFloat(record[7])
		gpu := GPUInfo{
			Index:              index,
			ID:                 cleanGPUText(record[1], 128),
			UtilizationPercent: clampPercent(parseOptionalFloatZero(record[4])),
			MemoryTotal:        mibToBytes(totalMiB),
			MemoryUsed:         mibToBytes(usedMiB),
			MemoryFree:         mibToBytes(freeMiB),
			TemperatureC:       parseOptionalFloatZero(record[8]),
			PowerW:             parseOptionalFloatZero(record[9]),
		}
		if gpu.MemoryTotal > 0 {
			gpu.MemoryUsedPercent = clampPercent(float64(gpu.MemoryUsed) * 100 / float64(gpu.MemoryTotal))
		}
		if includeStatic {
			gpu.Name = cleanGPUText(record[2], 160)
			gpu.Vendor = "NVIDIA"
			gpu.DriverVersion = cleanGPUText(record[3], 64)
		}
		gpus = append(gpus, gpu)
	}
	return gpus, nil
}

// runDarwinGPUSample 通过 IOKit 读取 Apple GPU。macOS 没有 nvidia-smi，
// 但 IOAccelerator 节点在无需 root 的情况下就暴露了利用率与显存占用。
func runDarwinGPUSample(_ string, includeStatic bool) ([]GPUInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-r", "-d", "1", "-c", "IOAccelerator").Output()
	if err != nil {
		return nil, fmt.Errorf("采样失败: %w", err)
	}
	gpus, err := parseDarwinGPUStats(string(output), includeStatic)
	if err != nil {
		return nil, fmt.Errorf("输出解析失败: %w", err)
	}
	return gpus, nil
}

// parseDarwinGPUStats 解析 ioreg 文本输出。每个 "+-o " 开头的行为一个加速器节点，
// 节点属性以 key = value 形式跟随其后。统一内存机型没有独立显存，
// 因此只上报 MemoryUsed（"In use system memory"），MemoryTotal 保持 0 以免伪造容量。
func parseDarwinGPUStats(raw string, includeStatic bool) ([]GPUInfo, error) {
	var (
		gpus    []GPUInfo
		current *GPUInfo
	)
	flush := func() {
		if current == nil {
			return
		}
		current.Index = len(gpus)
		gpus = append(gpus, *current)
		current = nil
	}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "+-o ") {
			flush()
			current = &GPUInfo{}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := splitIORegProperty(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "PerformanceStatistics":
			forEachIORegInlinePair(value, func(innerKey, innerValue string) {
				switch innerKey {
				case "Device Utilization %":
					current.UtilizationPercent = clampPercent(parseOptionalFloatZero(innerValue))
				case "In use system memory":
					current.MemoryUsed = uint64(math.Max(parseOptionalFloatZero(innerValue), 0))
				}
			})
		case "model":
			if includeStatic {
				current.Name = cleanGPUText(unquoteIORegValue(value), 160)
				current.Vendor = "Apple"
			}
		}
	}
	flush()
	return gpus, nil
}

// forEachIORegInlinePair 遍历 ioreg 内联字典 {"key"=value,...} 的键值对。
// 内联字典的写法没有 " = " 空格，因此不能复用 splitIORegProperty。
func forEachIORegInlinePair(raw string, visit func(key, value string)) {
	body := strings.TrimSpace(raw)
	body = strings.TrimPrefix(body, "{")
	body = strings.TrimSuffix(body, "}")
	for _, part := range strings.Split(body, ",") {
		eq := strings.Index(part, "=")
		if eq <= 0 {
			continue
		}
		key := unquoteIORegValue(part[:eq])
		if key == "" {
			continue
		}
		visit(key, strings.TrimSpace(part[eq+1:]))
	}
}

// splitIORegProperty 拆分 ioreg 的 "key" = value 行。返回的 value 保留原始形态，
// 由调用方按需去掉引号。PerformanceStatistics 这类嵌套字典不在此处理。
func splitIORegProperty(line string) (string, string, bool) {
	eq := strings.Index(line, " = ")
	if eq <= 0 {
		return "", "", false
	}
	key := unquoteIORegValue(strings.TrimSpace(line[:eq]))
	value := strings.TrimSpace(line[eq+3:])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func unquoteIORegValue(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return value[1 : len(value)-1]
	}
	return value
}

func parseOptionalInt(raw string) (int, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "N/A") || strings.Contains(strings.ToLower(value), "not supported") {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseOptionalFloatZero(raw string) float64 {
	value, ok := parseOptionalFloat(raw)
	if !ok {
		return 0
	}
	return value
}

func parseOptionalFloat(raw string) (float64, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimSuffix(value, "%")
	value = strings.TrimSuffix(value, "W")
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "N/A") || strings.Contains(strings.ToLower(value), "not supported") {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func mibToBytes(value float64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value * 1024 * 1024)
}

func clampPercent(value float64) float64 {
	switch {
	case math.IsNaN(value), math.IsInf(value, 0):
		return 0
	case value < 0:
		return 0
	case value > 100:
		return 100
	default:
		return value
	}
}

func cleanGPUText(raw string, maxLen int) string {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "N/A") || strings.Contains(strings.ToLower(value), "not supported") {
		return ""
	}
	value = strings.Join(strings.Fields(value), " ")
	if maxLen > 0 {
		runes := []rune(value)
		if len(runes) > maxLen {
			value = string(runes[:maxLen])
		}
	}
	return value
}
