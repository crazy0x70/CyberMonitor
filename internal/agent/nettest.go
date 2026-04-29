package agent

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
)

const (
	defaultTCPPort  = 80
	icmpTimeout     = 3 * time.Second
	tcpTimeout      = 3 * time.Second
	pingSampleCount = 3
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

	for i, cfg := range configs {
		wg.Add(1)
		go func(index int, config metrics.NetworkTestConfig) {
			defer wg.Done()
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

	switch config.Type {
	case "tcp":
		latency, status, errText := tcpProbe(config.Host, config.Port)
		result.LatencyMs = latency
		result.Status = status
		if status == "ok" {
			result.PacketLoss = 0
		} else {
			result.PacketLoss = 100
		}
		result.Error = errText
	default:
		latency, loss, status, errText := icmpProbe(ctx, config.Host)
		result.LatencyMs = latency
		result.PacketLoss = loss
		result.Status = status
		result.Error = errText
	}

	result.CheckedAt = now().Unix()
	return result
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
