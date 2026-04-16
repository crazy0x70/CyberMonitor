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
)

func ParseNetTests(raw string) []metrics.NetworkTestConfig {
	items := strings.Split(raw, ",")
	results := make([]metrics.NetworkTestConfig, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}

		name := ""
		if left, right, ok := strings.Cut(trimmed, "@"); ok {
			name = strings.TrimSpace(left)
			trimmed = strings.TrimSpace(right)
		}

		typePrefix := ""
		if kind, target, ok := cutNetTestTypePrefix(trimmed); ok {
			typePrefix = kind
			trimmed = target
		}

		host, port := splitHostPort(trimmed)
		if host == "" {
			continue
		}
		if typePrefix == "" {
			if port > 0 {
				typePrefix = "tcp"
			} else {
				typePrefix = "icmp"
			}
		}
		if typePrefix == "icmp" {
			port = 0
		}
		if typePrefix == "tcp" && port == 0 {
			port = defaultTCPPort
		}

		if name == "" {
			name = host
		}

		results = append(results, metrics.NetworkTestConfig{
			Name: name,
			Type: typePrefix,
			Host: host,
			Port: port,
		})
	}
	return results
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

	var cmd *exec.Cmd
	count := strconv.Itoa(pingSampleCount)
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, pingPath, "-n", count, "-w", "2000", host)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, pingPath, "-c", count, "-W", "2000", host)
	} else {
		cmd = exec.CommandContext(ctx, pingPath, "-c", count, "-W", "2", host)
	}

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

func parsePingOutput(output string) (*float64, float64, string, string) {
	status := "ok"
	packetLoss := 0.0
	var latency *float64
	lowerOutput := strings.ToLower(output)

	if matches := pingLossRegex.FindStringSubmatch(output); len(matches) > 1 {
		if loss, err := strconv.ParseFloat(matches[1], 64); err == nil {
			packetLoss = loss
		}
	}
	if packetLoss == 0 {
		if matches := pingTxRxRegex.FindStringSubmatch(output); len(matches) > 2 {
			packetLoss = packetLossFromCounts(matches[1], matches[2])
		}
	}
	if packetLoss == 0 {
		if matches := pingWindowsCountRegex.FindStringSubmatch(output); len(matches) > 2 {
			packetLoss = packetLossFromCounts(matches[1], matches[2])
		}
	}
	if packetLoss == 0 {
		if matches := pingChineseCountRegex.FindStringSubmatch(output); len(matches) > 2 {
			packetLoss = packetLossFromCounts(matches[1], matches[2])
		}
	}

	if strings.Contains(output, "100%") || strings.Contains(lowerOutput, "timeout") {
		status = "timeout"
		packetLoss = 100
	}

	if runtime.GOOS == "windows" {
		if matches := pingWindowsAverageRegex.FindStringSubmatch(output); len(matches) > 1 {
			if lat, err := strconv.ParseFloat(matches[1], 64); err == nil {
				latency = &lat
			}
		}
	} else {
		if matches := pingUnixAverageRegex.FindStringSubmatch(output); len(matches) > 2 {
			if lat, err := strconv.ParseFloat(matches[2], 64); err == nil {
				latency = &lat
			}
		}
		if latency == nil {
			matches := pingGenericMSRegex.FindAllStringSubmatch(output, -1)
			if len(matches) > 0 {
				if lat, err := strconv.ParseFloat(matches[len(matches)-1][1], 64); err == nil {
					latency = &lat
				}
			}
		}
	}

	if packetLoss >= 100 {
		status = "timeout"
	} else if latency == nil && packetLoss > 0 {
		status = "error"
	} else if latency == nil {
		status = "error"
	}

	return latency, packetLoss, status, ""
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
