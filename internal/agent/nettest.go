package agent

import (
	"context"
	"errors"
	"fmt"
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
	defaultTCPPort           = 80
	icmpTimeout              = 3 * time.Second
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
	kind, target := splitNetTestType(target)
	host, port := splitHostPort(target)
	if host == "" {
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
	tcpProbe func(string, int) (*float64, string, string),
	icmpProbe func(context.Context, string) (*float64, float64, string, string),
) metrics.NetworkTestResult {
	result := metrics.NetworkTestResult{
		Name:   config.Name,
		Type:   config.Type,
		Host:   config.Host,
		Port:   config.Port,
		Status: "error",
	}

	probeHost, err := resolveNetworkTestProbeHost(ctx, config)
	if err != nil {
		result.Error = err.Error()
		result.CheckedAt = now().Unix()
		return result
	}

	switch config.Type {
	case "tcp":
		latency, status, errText := tcpProbe(probeHost, config.Port)
		result.LatencyMs = latency
		result.Status = status
		if status == "ok" {
			result.PacketLoss = 0
		} else {
			result.PacketLoss = 100
		}
		result.Error = errText
	default:
		latency, loss, status, errText := icmpProbe(ctx, probeHost)
		result.LatencyMs = latency
		result.PacketLoss = loss
		result.Status = status
		result.Error = errText
	}

	result.CheckedAt = now().Unix()
	return result
}

func resolveNetworkTestProbeHost(ctx context.Context, config metrics.NetworkTestConfig) (string, error) {
	if config.PublicOnly {
		return resolvePublicProbeHost(ctx, config.Host)
	}
	host := strings.TrimSpace(config.Host)
	if err := validateProbeHost(host); err != nil {
		return "", err
	}
	return host, nil
}

func testTCP(host string, port int) (*float64, string, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, tcpTimeout)
	if err != nil {
		return nil, "error", err.Error()
	}
	_ = conn.Close()
	latency := float64(time.Since(start).Nanoseconds()) / 1e6
	return &latency, "ok", ""
}

func pingHost(ctx context.Context, host string) (*float64, float64, string, string) {
	if err := validateProbeHost(host); err != nil {
		return nil, 100, "error", err.Error()
	}

	ctx, cancel := context.WithTimeout(ctx, icmpTimeout)
	defer cancel()

	pingPath, err := exec.LookPath("ping")
	if err != nil {
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

func validateProbeHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("host 不能为空")
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

func validatePublicProbeHost(ctx context.Context, host string) error {
	_, err := resolvePublicProbeHostWithResolver(ctx, host, lookupProbeHostIPs)
	return err
}

func validatePublicProbeHostWithResolver(ctx context.Context, host string, lookup probeLookupFunc) error {
	_, err := resolvePublicProbeHostWithResolver(ctx, host, lookup)
	return err
}

func resolvePublicProbeHost(ctx context.Context, host string) (string, error) {
	return resolvePublicProbeHostWithResolver(ctx, host, lookupProbeHostIPs)
}

func resolvePublicProbeHostWithResolver(ctx context.Context, host string, lookup probeLookupFunc) (string, error) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		if err := validatePublicProbeIP(ip); err != nil {
			return "", err
		}
		return canonicalProbeIP(ip), nil
	}
	name := normalizeProbeHostname(host)
	if err := validateProbeHost(name); err != nil {
		return "", err
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") || !strings.Contains(name, ".") {
		return "", errors.New("远程网络测试不允许使用本地或内网主机名")
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
		return "", fmt.Errorf("解析远程网络测试主机失败: %w", err)
	}
	if len(ips) == 0 {
		return "", errors.New("解析远程网络测试主机失败: empty address set")
	}
	resolved := ""
	for _, ip := range ips {
		if err := validatePublicProbeIP(ip); err != nil {
			return "", err
		}
		if resolved == "" {
			resolved = canonicalProbeIP(ip)
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
