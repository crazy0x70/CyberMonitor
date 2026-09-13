package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/netguard"
)

const (
	defaultTCPPort = 80
	// icmpTimeout 必须覆盖 ping 完整运行时长（pingSampleCount 个包 ×
	// 每包等待 2s + 发送间隔）：3s 预算会在命令打出汇总行前杀进程，
	// 已成功的 reply 被错误改判为 100% 丢包——监控恰恰在丢包/高延迟
	// 目标上触发此路径。代价：探测时长可能主导采集轮次，interval 小于
	// 探测时长时实际采样周期取探测时长。
	icmpTimeout              = 8 * time.Second
	tcpTimeout               = 3 * time.Second
	publicProbeLookupTimeout = 2 * time.Second
	pingSampleCount          = 3
	maxNetTestWorkers        = 16
)

var (
	pingLossRegex           = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss`)
	pingTxRxRegex           = regexp.MustCompile(`(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received`)
	pingWindowsCountRegex   = regexp.MustCompile(`(?is)sent\s*=\s*(\d+).*received\s*=\s*(\d+)`)
	pingChineseCountRegex   = regexp.MustCompile(`(?is)已发送\s*=\s*(\d+).*已接收\s*=\s*(\d+)`)
	pingWindowsAverageRegex = regexp.MustCompile(`Average\s*=\s*(\d+(?:\.\d+)?)\s*ms`)
	pingUnixAverageRegex    = regexp.MustCompile(`=\s*(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)`)
	pingGenericMSRegex      = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
	pingCountRegexes        = []*regexp.Regexp{pingTxRxRegex, pingWindowsCountRegex, pingChineseCountRegex}
)

// ParseNetTests 解析逗号分隔的网络测试目标列表。单项支持形式：
//
//	host[:port]                按端口推断 tcp / icmp
//	icmp:host / tcp:host[:port]
//	名称@host[:port] / 名称@icmp:host / 名称@tcp:host[:port]
//	名称 icmp:host / 名称 tcp:host[:port]（名称与目标以空白分隔）
//
// IPv6 必须使用方括号：tcp:[2001:db8::1]:443、icmp:[2001:db8::1]。
// 无法解析的单项记录日志并跳过，不影响其余目标。
func ParseNetTests(raw string) []metrics.NetworkTestConfig {
	items := strings.Split(raw, ",")
	results := make([]metrics.NetworkTestConfig, 0, len(items))
	for _, item := range items {
		config, ok := parseNetTestItem(item)
		if ok {
			results = append(results, config)
		}
	}
	return results
}

func parseNetTestItem(item string) (metrics.NetworkTestConfig, bool) {
	target := strings.TrimSpace(item)
	if target == "" {
		return metrics.NetworkTestConfig{}, false
	}

	name, target := splitNamedTarget(target)
	// “名称 + 空白 + 目标”形式：主机名不含空白，首个空白前一定是名称。
	if name == "" {
		if idx := strings.IndexAny(target, " \t"); idx > 0 {
			name = strings.TrimSpace(target[:idx])
			target = strings.TrimSpace(target[idx+1:])
		}
	}
	kind, target := splitNetTestType(target)
	host, port := splitHostPort(target)
	if host == "" {
		log.Printf("忽略无法解析的网络测试目标 %q: host 为空（IPv6 请使用方括号，如 tcp:[::1]:443）", item)
		return metrics.NetworkTestConfig{}, false
	}
	if err := validateProbeHost(host); err != nil {
		log.Printf("忽略无法解析的网络测试目标 %q: %v", item, err)
		return metrics.NetworkTestConfig{}, false
	}

	kind, port = normalizeNetTestTarget(kind, port)
	if name == "" {
		name = host
	}

	return metrics.NetworkTestConfig{
		Name: name,
		Type: kind,
		Host: host,
		Port: port,
	}, true
}

func splitNamedTarget(value string) (string, string) {
	name, target, ok := strings.Cut(value, "@")
	if !ok {
		return "", value
	}
	return strings.TrimSpace(name), strings.TrimSpace(target)
}

func splitNetTestType(value string) (string, string) {
	kind, target, ok := cutNetTestTypePrefix(value)
	if !ok {
		return "", value
	}
	return kind, target
}

func normalizeNetTestTarget(kind string, port int) (string, int) {
	if kind == "" {
		if port > 0 {
			kind = "tcp"
		} else {
			kind = "icmp"
		}
	}
	if kind == "icmp" {
		return kind, 0
	}
	if port == 0 {
		port = defaultTCPPort
	}
	return kind, port
}

func cutNetTestTypePrefix(value string) (kind, target string, ok bool) {
	prefix, rest, found := strings.Cut(strings.TrimSpace(value), ":")
	if !found {
		return "", "", false
	}
	switch strings.ToLower(strings.TrimSpace(prefix)) {
	case "icmp", "tcp":
		return strings.ToLower(strings.TrimSpace(prefix)), strings.TrimSpace(rest), true
	default:
		return "", "", false
	}
}

func RunNetworkTests(ctx context.Context, configs []metrics.NetworkTestConfig) []metrics.NetworkTestResult {
	if len(configs) == 0 {
		return nil
	}
	results := make([]metrics.NetworkTestResult, len(configs))
	var wg sync.WaitGroup
	workers := maxNetTestWorkers
	if len(configs) < workers {
		workers = len(configs)
	}
	sem := make(chan struct{}, workers)

	for i, cfg := range configs {
		sem <- struct{}{}
		wg.Add(1)
		go func(index int, config metrics.NetworkTestConfig) {
			defer func() {
				<-sem
				wg.Done()
			}()
			defer func() {
				// 探测路径 panic 不得杀死整个 agent：以 error 结果占位。
				if rec := recover(); rec != nil {
					log.Printf("网络测试 %s panic 已恢复: %v", config.Name, rec)
					results[index] = metrics.NetworkTestResult{
						Name:       config.Name,
						Type:       config.Type,
						Host:       config.Host,
						Port:       config.Port,
						PacketLoss: 100,
						Status:     "error",
						Error:      fmt.Sprintf("panic: %v", rec),
						CheckedAt:  time.Now().Unix(),
					}
				}
			}()
			results[index] = runSingleNetworkTest(ctx, config, time.Now, testTCP, pingHost)
		}(i, cfg)
	}

	wg.Wait()
	return results
}

func runSingleNetworkTest(
	ctx context.Context,
	config metrics.NetworkTestConfig,
	now func() time.Time,
	tcpProbe func(context.Context, string, int) (*float64, string, string),
	icmpProbe func(context.Context, string) (*float64, float64, string, string),
) metrics.NetworkTestResult {
	result := metrics.NetworkTestResult{
		Name:   config.Name,
		Type:   config.Type,
		Host:   config.Host,
		Port:   config.Port,
		Status: "error",
	}

	probeHosts, err := resolveNetworkTestProbeHost(ctx, config)
	if err != nil {
		result.Error = err.Error()
		result.PacketLoss = 100
		result.CheckedAt = now().Unix()
		return result
	}

	switch config.Type {
	case "tcp":
		latency, status, errText := probeTCPCandidates(ctx, probeHosts, config.Port, tcpProbe)
		result.LatencyMs = latency
		result.Status = status
		if status == "ok" {
			result.PacketLoss = 0
		} else {
			result.PacketLoss = 100
		}
		result.Error = errText
	default:
		latency, loss, status, errText := probeICMPCandidates(ctx, probeHosts, icmpProbe)
		result.LatencyMs = latency
		result.PacketLoss = loss
		result.Status = status
		result.Error = errText
	}

	result.CheckedAt = now().Unix()
	return result
}

func resolveNetworkTestProbeHost(ctx context.Context, config metrics.NetworkTestConfig) ([]string, error) {
	if config.PublicOnly {
		return resolvePublicProbeHost(ctx, config.Host)
	}
	host := strings.TrimSpace(config.Host)
	if err := validateProbeHost(host); err != nil {
		return nil, err
	}
	return []string{host}, nil
}

func testTCP(ctx context.Context, host string, port int) (*float64, string, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: tcpTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, "timeout", err.Error()
		}
		return nil, "error", err.Error()
	}
	_ = conn.Close()
	latency := float64(time.Since(start).Nanoseconds()) / 1e6
	return &latency, "ok", ""
}

// pingPathOnce caches the resolved ping binary path (also when it is not
// installed), so repeated ICMP tests do not rescan PATH.
var pingPathOnce = sync.OnceValue(func() string {
	path, err := exec.LookPath("ping")
	if err != nil {
		return ""
	}
	return path
})

func pingHost(ctx context.Context, host string) (*float64, float64, string, string) {
	if err := validateProbeHost(host); err != nil {
		return nil, 100, "error", err.Error()
	}

	ctx, cancel := context.WithTimeout(ctx, icmpTimeout)
	defer cancel()

	pingPath := pingPathOnce()
	if pingPath == "" {
		return nil, 100, "error", "ping 命令不可用"
	}

	cmd := newPingCommand(ctx, pingPath, host)

	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		return nil, 100, "error", err.Error()
	}

	latency, loss, status, parseErr := parsePingOutput(string(output))
	if parseErr == "" && err != nil {
		parseErr = err.Error()
	}
	if err != nil && (loss == 0 || latency == nil) {
		loss = 100
	}
	if err != nil && status == "ok" {
		status = "error"
	}

	return latency, loss, status, parseErr
}

// probeICMPCandidates 依次尝试全部已验证地址，取首个成功结果；全部
// 失败时返回最后一次结果（与 probeTCPCandidates 对称，多 A 记录/双栈
// 场景不再被首个地址单点拖死）。
func probeICMPCandidates(ctx context.Context, hosts []string, probe func(context.Context, string) (*float64, float64, string, string)) (*float64, float64, string, string) {
	// 全部候选共享单项总预算：候选逐一尝试的最坏耗时不超过单地址路径，
	// 排在前面的地址用不完的预算留给后续候选。
	ctx, cancel := context.WithTimeout(ctx, icmpTimeout)
	defer cancel()
	var latency *float64
	var loss float64
	var status, errText string
	for _, host := range hosts {
		latency, loss, status, errText = probe(ctx, host)
		if status == "ok" {
			return latency, loss, status, ""
		}
	}
	return latency, loss, status, errText
}

// probeTCPCandidates 依次尝试全部已验证地址，取首个成功结果；全部
// 失败时返回最后一次错误。
func probeTCPCandidates(ctx context.Context, hosts []string, port int, probe func(context.Context, string, int) (*float64, string, string)) (*float64, string, string) {
	var latency *float64
	var status, errText string
	for _, host := range hosts {
		latency, status, errText = probe(ctx, host, port)
		if status == "ok" {
			return latency, status, ""
		}
	}
	return latency, status, errText
}

func validateProbeHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("host 不能为空")
	}
	if len(host) > 253 {
		return errors.New("host 超长（>253 字节）")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
		if !isValidDNSLabel(label) {
			return errors.New("host 格式无效")
		}
	}
	return nil
}

type probeLookupFunc func(context.Context, string) ([]net.IP, error)

const maxProbeCandidates = 4

func resolvePublicProbeHost(ctx context.Context, host string) ([]string, error) {
	return resolvePublicProbeHostWithResolver(ctx, host, lookupProbeHostIPs)
}

func resolvePublicProbeHostWithResolver(ctx context.Context, host string, lookup probeLookupFunc) ([]string, error) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		if err := validatePublicProbeIP(ip); err != nil {
			return nil, err
		}
		return []string{canonicalProbeIP(ip)}, nil
	}
	name := normalizeProbeHostname(host)
	if err := validateProbeHost(name); err != nil {
		return nil, err
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") || !strings.Contains(name, ".") {
		return nil, errors.New("远程网络测试不允许使用本地或内网主机名")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if lookup == nil {
		lookup = lookupProbeHostIPs
	}
	lookupCtx, cancel := context.WithTimeout(ctx, publicProbeLookupTimeout)
	defer cancel()
	ips, err := lookup(lookupCtx, name)
	if err != nil {
		return nil, fmt.Errorf("解析远程网络测试主机失败: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("解析远程网络测试主机失败: empty address set")
	}
	// 任一被采纳的地址非法即整体失败（防 rebinding；封顶后未检查的
	// 地址不会被探测）；返回全部已验证地址供 TCP 探测依次尝试（双栈
	// 主机首个地址不可达不应整体失败），封顶 maxProbeCandidates 防超
	// 大地址集拖死 worker。
	seen := make(map[string]struct{}, len(ips))
	resolved := make([]string, 0, len(ips))
	for _, ip := range ips {
		if err := validatePublicProbeIP(ip); err != nil {
			return nil, err
		}
		literal := canonicalProbeIP(ip)
		if _, dup := seen[literal]; dup {
			continue
		}
		seen[literal] = struct{}{}
		resolved = append(resolved, literal)
		if len(resolved) == maxProbeCandidates {
			break
		}
	}
	return resolved, nil
}

var lookupProbeHostIPs probeLookupFunc = defaultLookupProbeHostIPs

func defaultLookupProbeHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

func validatePublicProbeIP(ip net.IP) error {
	if !netguard.IsAllowedPublicIP(ip) {
		return errors.New("远程网络测试不允许使用本地或内网地址")
	}
	return nil
}

func canonicalProbeIP(ip net.IP) string {
	addr, ok := netguard.AddrFromIP(ip)
	if !ok {
		return strings.TrimSpace(ip.String())
	}
	return addr.String()
}

func normalizeProbeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-':
		default:
			return false
		}
	}
	return true
}

func newPingCommand(ctx context.Context, pingPath string, host string) *exec.Cmd {
	count := strconv.Itoa(pingSampleCount)
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx, pingPath, "-n", count, "-w", "2000", host)
	case "darwin":
		return exec.CommandContext(ctx, pingPath, "-c", count, "-W", "2000", host)
	default:
		return exec.CommandContext(ctx, pingPath, "-c", count, "-W", "2", host)
	}
}

func parsePingOutput(output string) (*float64, float64, string, string) {
	packetLoss := parsePacketLoss(output)
	latency := parsePingLatency(output)
	status, loss := resolvePingStatus(output, packetLoss, latency)
	return latency, loss, status, ""
}

func resolvePingStatus(output string, packetLoss float64, latency *float64) (string, float64) {
	if strings.Contains(output, "100%") || strings.Contains(strings.ToLower(output), "timeout") {
		packetLoss = 100
	}
	switch {
	case packetLoss >= 100:
		return "timeout", 100
	case latency == nil:
		return "error", packetLoss
	default:
		return "ok", packetLoss
	}
}

func parsePacketLoss(output string) float64 {
	loss, ok := parsePacketLossPercent(output)
	if ok && loss != 0 {
		return loss
	}
	for _, pattern := range pingCountRegexes {
		if countLoss, matched := parsePacketLossCounts(output, pattern); matched {
			return countLoss
		}
	}
	if ok {
		return loss
	}
	return 0
}

func parsePacketLossPercent(output string) (float64, bool) {
	matches := pingLossRegex.FindStringSubmatch(output)
	if len(matches) <= 1 {
		return 0, false
	}
	loss, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, false
	}
	return loss, true
}

func parsePacketLossCounts(output string, pattern *regexp.Regexp) (float64, bool) {
	if pattern == nil {
		return 0, false
	}
	matches := pattern.FindStringSubmatch(output)
	if len(matches) <= 2 {
		return 0, false
	}
	return packetLossFromCounts(matches[1], matches[2]), true
}

func parsePingLatency(output string) *float64 {
	if runtime.GOOS == "windows" {
		return parseLatencyFromPattern(output, pingWindowsAverageRegex, 1)
	}
	if latency := parseLatencyFromPattern(output, pingUnixAverageRegex, 2); latency != nil {
		return latency
	}
	matches := pingGenericMSRegex.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil
	}
	return parseLatencySubmatch(matches[len(matches)-1], 1)
}

func parseLatencyFromPattern(output string, pattern *regexp.Regexp, index int) *float64 {
	if pattern == nil {
		return nil
	}
	return parseLatencySubmatch(pattern.FindStringSubmatch(output), index)
}

func parseLatencySubmatch(matches []string, index int) *float64 {
	if len(matches) <= index {
		return nil
	}
	latency, err := strconv.ParseFloat(matches[index], 64)
	if err != nil {
		return nil
	}
	return &latency
}

func packetLossFromCounts(sentText, receivedText string) float64 {
	sent, err := strconv.Atoi(sentText)
	if err != nil || sent <= 0 {
		return 0
	}
	received, err := strconv.Atoi(receivedText)
	if err != nil {
		return 0
	}
	return float64(sent-received) / float64(sent) * 100
}

func splitHostPort(value string) (string, int) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", 0
	}

	if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]") {
		if host, port, err := net.SplitHostPort(trimmed); err == nil {
			parsed, _ := strconv.Atoi(port)
			return host, parsed
		}
		return strings.Trim(trimmed, "[]"), 0
	}

	// 无括号的裸 IPv6（如 ::1、2001:db8::1）不含端口：整体视为主机，
	// 避免被"最后一个冒号后是端口"的启发式拆坏。
	if strings.Count(trimmed, ":") > 1 {
		return trimmed, 0
	}

	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon == -1 {
		return trimmed, 0
	}
	if lastColon == len(trimmed)-1 {
		return strings.TrimSuffix(trimmed, ":"), 0
	}

	portPart := trimmed[lastColon+1:]
	if port, err := strconv.Atoi(portPart); err == nil {
		return trimmed[:lastColon], port
	}

	return trimmed, 0
}
