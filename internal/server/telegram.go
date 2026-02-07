package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type telegramUpdateResponse struct {
	Ok          bool             `json:"ok"`
	Result      []telegramUpdate `json:"result"`
	Description string           `json:"description,omitempty"`
}

type telegramSendResponse struct {
	Ok          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

type telegramUpdate struct {
	UpdateID int64            `json:"update_id"`
	Message  *telegramMessage `json:"message"`
}

type telegramMessage struct {
	MessageID int64         `json:"message_id"`
	Text      string        `json:"text"`
	From      *telegramUser `json:"from"`
	Chat      *telegramChat `json:"chat"`
}

type telegramUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username,omitempty"`
}

type telegramChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type,omitempty"`
}

func startTelegramBot(ctx context.Context, store *Store) {
	go func() {
		client := &http.Client{Timeout: 12 * time.Second}
		var offset int64
		var lastToken string
		var lastUserKey string
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			token, userIDs := store.TelegramSettings()
			userIDs = normalizeTelegramUserIDs(userIDs)
			if token == "" || len(userIDs) == 0 {
				time.Sleep(2 * time.Second)
				continue
			}
			userKey := buildTelegramUserKey(userIDs)
			if token != lastToken {
				offset = 0
				lastToken = token
				lastUserKey = userKey
				if err := setTelegramCommands(token); err != nil {
					log.Printf("Telegram 菜单设置失败: %v", err)
				}
			} else if userKey != lastUserKey {
				lastUserKey = userKey
			}

			updates, err := fetchTelegramUpdates(client, token, offset)
			if err != nil {
				log.Printf("Telegram 轮询失败: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			allowed := make(map[int64]struct{}, len(userIDs))
			for _, id := range userIDs {
				allowed[id] = struct{}{}
			}
			for _, update := range updates {
				if update.UpdateID >= offset {
					offset = update.UpdateID + 1
				}
				if update.Message == nil || update.Message.From == nil || update.Message.Chat == nil {
					continue
				}
				if update.Message.Chat.Type != "" && update.Message.Chat.Type != "private" {
					continue
				}
				if !isAllowedTelegramUser(allowed, update.Message.From.ID, update.Message.Chat.ID) {
					continue
				}
				command := strings.TrimSpace(update.Message.Text)
				if command == "" {
					continue
				}
				reply := handleTelegramCommand(command, store)
				if reply == "" {
					continue
				}
				if err := sendTelegramMessage(token, update.Message.Chat.ID, reply); err != nil {
					log.Printf("Telegram 回复失败: %v", err)
				}
			}
			time.Sleep(900 * time.Millisecond)
		}
	}()
}

func fetchTelegramUpdates(client *http.Client, token string, offset int64) ([]telegramUpdate, error) {
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	if err := validateTelegramToken(token); err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("timeout", "10")
	values.Set("allowed_updates", "[\"message\"]")
	if offset > 0 {
		values.Set("offset", fmt.Sprintf("%d", offset))
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?%s", token, values.Encode())
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("请求更新失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("更新响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload telegramUpdateResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析更新失败: %w", err)
	}
	if !payload.Ok {
		return nil, errors.New(formatTelegramError(payload.Description, "更新返回失败"))
	}
	return payload.Result, nil
}

func sendTelegramAlert(token string, userIDs []int64, siteTitle string, events []AlertEvent) {
	if token == "" || len(userIDs) == 0 || len(events) == 0 {
		return
	}
	message := buildAlertMessage(siteTitle, events)
	for _, err := range sendTelegramMessageToUsers(token, userIDs, message) {
		log.Printf("Telegram 告警发送失败: %v", err)
	}
}

func sendTelegramRecovery(token string, userIDs []int64, siteTitle string, events []AlertEvent) {
	if token == "" || len(userIDs) == 0 || len(events) == 0 {
		return
	}
	message := buildRecoveryMessage(siteTitle, events)
	for _, err := range sendTelegramMessageToUsers(token, userIDs, message) {
		log.Printf("Telegram 恢复通知发送失败: %v", err)
	}
}

func sendTelegramTest(token string, userIDs []int64, siteTitle string) []string {
	message := fmt.Sprintf("【%s】Telegram 告警测试 %s", normalizeSiteTitle(siteTitle), time.Now().Format("2006-01-02 15:04:05"))
	return sendTelegramMessageToUsers(token, userIDs, message)
}

func sendTelegramMessageToUsers(token string, userIDs []int64, text string) []string {
	ids := normalizeTelegramUserIDs(userIDs)
	if token == "" || len(ids) == 0 || strings.TrimSpace(text) == "" {
		return nil
	}
	var errs []string
	for _, id := range ids {
		if err := sendTelegramMessage(token, id, text); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func sendTelegramMessage(token string, userID int64, text string) error {
	if err := validateTelegramToken(token); err != nil {
		return err
	}
	if userID <= 0 {
		return errors.New("telegram 用户 ID 无效")
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("telegram 消息为空")
	}
	payload := map[string]any{
		"chat_id": userID,
		"text":    text,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram 消息编码失败: %w", err)
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("telegram 请求创建失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram 发送失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result telegramSendResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("telegram 响应解析失败: %w", err)
	}
	if !result.Ok {
		return errors.New(formatTelegramError(result.Description, "telegram 发送失败"))
	}
	return nil
}

func handleTelegramCommand(command string, store *Store) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}
	cmd := parts[0]
	if idx := strings.Index(cmd, "@"); idx > 0 {
		cmd = cmd[:idx]
	}
	switch cmd {
	case "/start", "/help":
		return buildTelegramHelp()
	case "/cmall":
		return buildTelegramAllStats(store)
	case "/server":
		return buildTelegramServerList(store)
	case "/status":
		if len(parts) < 2 {
			return "用法: /status 服务器ID"
		}
		return buildTelegramServerStatus(store, parts[1])
	case "/alarmson":
		return handleTelegramAlarmToggle(store, parts, true)
	case "/alarmsoff":
		return handleTelegramAlarmToggle(store, parts, false)
	case "/ai":
		return handleTelegramAICommand(command, store)
	default:
		return buildTelegramHelp()
	}
}

func buildTelegramHelp() string {
	return strings.Join([]string{
		"已启用 CyberMonitor 告警机器人",
		"可用命令：",
		"/cmall 查看所有服务器统计",
		"/server 查看服务器列表",
		"/status <服务器ID> 查看服务器状态",
		"/alarmson <服务器ID> 开启告警",
		"/alarmsoff <服务器ID> 关闭告警",
		"/ai <问题> AI 运维查询",
	}, "\n")
}

func handleTelegramAICommand(command string, store *Store) string {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		return "用法: /ai 你的问题"
	}
	query := strings.TrimSpace(strings.Join(parts[1:], " "))
	if query == "" {
		return "用法: /ai 你的问题"
	}
	if enabled, serverID, message, ok := parseAIAlertToggle(query, store); ok {
		return toggleAlertForServer(store, serverID, enabled)
	} else if message != "" {
		return message
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	answer, err := runAIQuery(ctx, store, query)
	if err != nil {
		return fmt.Sprintf("AI 查询失败: %s", err.Error())
	}
	return answer
}

func handleTelegramAlarmToggle(store *Store, parts []string, enabled bool) string {
	if len(parts) < 2 {
		if enabled {
			return "用法: /alarmson 服务器ID"
		}
		return "用法: /alarmsoff 服务器ID"
	}
	serverID := strings.TrimSpace(parts[1])
	if serverID == "" {
		if enabled {
			return "用法: /alarmson 服务器ID"
		}
		return "用法: /alarmsoff 服务器ID"
	}
	return toggleAlertForServer(store, serverID, enabled)
}

func toggleAlertForServer(store *Store, serverID string, enabled bool) string {
	_, display, ok := store.UpdateAlertEnabledByServerID(serverID, enabled)
	if !ok {
		return fmt.Sprintf("未找到服务器: %s", serverID)
	}
	action := "已开启"
	if !enabled {
		action = "已关闭"
	}
	if strings.TrimSpace(display) == "" {
		display = serverID
	}
	return fmt.Sprintf("%s告警：%s （%s）", action, display, serverID)
}

func parseAIAlertToggle(query string, store *Store) (bool, string, string, bool) {
	query = strings.TrimSpace(query)
	if query == "" {
		return false, "", "", false
	}
	enableKeywords := []string{"开启告警", "打开告警", "启用告警", "恢复告警", "开告警"}
	disableKeywords := []string{"关闭告警", "禁用告警", "停用告警", "关掉告警", "关告警", "关停告警"}
	enabled := false
	recognized := false
	for _, word := range enableKeywords {
		if strings.Contains(query, word) {
			enabled = true
			recognized = true
			break
		}
	}
	if !recognized {
		for _, word := range disableKeywords {
			if strings.Contains(query, word) {
				enabled = false
				recognized = true
				break
			}
		}
	}
	if !recognized {
		return false, "", "", false
	}
	nodes := store.Snapshot()
	for _, node := range nodes {
		if node.ServerID != "" && strings.Contains(query, node.ServerID) {
			return enabled, node.ServerID, "", true
		}
	}
	matched := make([]string, 0, 1)
	for _, node := range nodes {
		display := resolveNodeDisplayNameForAI(node)
		if display == "" || display == "未命名节点" {
			continue
		}
		if strings.Contains(query, display) {
			if node.ServerID != "" {
				matched = append(matched, node.ServerID)
			}
		}
	}
	if len(matched) == 1 {
		return enabled, matched[0], "", true
	}
	if len(matched) > 1 {
		return false, "", "匹配到多个服务器，请使用服务器ID 进行操作", false
	}
	return false, "", "未识别服务器ID，请使用 /alarmson 或 /alarmsoff 服务器ID", false
}

func buildTelegramAllStats(store *Store) string {
	nodes := store.Snapshot()
	total := len(nodes)
	if total == 0 {
		return "暂无服务器数据"
	}
	online := 0
	offline := 0
	cpuSum := 0.0
	memSum := 0.0
	for _, node := range nodes {
		if node.Status == "offline" {
			offline++
		} else {
			online++
		}
		cpuSum += node.Stats.CPU.UsagePercent
		memSum += node.Stats.Memory.UsedPercent
	}
	avgCPU := cpuSum / float64(total)
	avgMem := memSum / float64(total)
	return fmt.Sprintf(
		"服务器统计\n总数: %d\n在线: %d\n离线: %d\n平均CPU: %.1f%%\n平均内存: %.1f%%\n统计时间: %s",
		total,
		online,
		offline,
		avgCPU,
		avgMem,
		time.Now().Format("2006-01-02 15:04:05"),
	)
}

func buildTelegramServerList(store *Store) string {
	nodes := store.Snapshot()
	if len(nodes) == 0 {
		return "暂无服务器数据"
	}
	online := make([]NodeView, 0)
	offline := make([]NodeView, 0)
	for _, node := range nodes {
		if node.Status == "offline" {
			offline = append(offline, node)
		} else {
			online = append(online, node)
		}
	}
	sort.Slice(online, func(i, j int) bool {
		return resolveTelegramDisplay(online[i]) < resolveTelegramDisplay(online[j])
	})
	sort.Slice(offline, func(i, j int) bool {
		return resolveTelegramDisplay(offline[i]) < resolveTelegramDisplay(offline[j])
	})
	lines := []string{"服务器列表：", "在线服务器："}
	if len(online) == 0 {
		lines = append(lines, "• 无")
	} else {
		for _, node := range online {
			display := resolveTelegramDisplay(node)
			lines = append(lines, fmt.Sprintf("• %s （%s）", display, node.ServerID))
		}
	}
	lines = append(lines, "", "离线服务器：")
	if len(offline) == 0 {
		lines = append(lines, "• 无")
	} else {
		for _, node := range offline {
			display := resolveTelegramDisplay(node)
			lines = append(lines, fmt.Sprintf("• %s （%s）", display, node.ServerID))
		}
	}
	return strings.Join(lines, "\n")
}

func buildTelegramServerStatus(store *Store, serverID string) string {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "用法: /status 服务器ID"
	}
	nodes := store.Snapshot()
	for _, node := range nodes {
		if node.ServerID != serverID {
			continue
		}
		statusLabel := "在线"
		if node.Status == "offline" {
			statusLabel = "离线"
		}
		display := resolveTelegramDisplay(node)
		lastSeen := formatTelegramTime(node.LastSeen)
		firstSeen := formatTelegramTime(node.FirstSeen)
		uptime := formatAlertDuration(int64(node.Stats.UptimeSec))
		hostName := strings.TrimSpace(node.Stats.Hostname)
		if hostName == "" {
			hostName = strings.TrimSpace(node.Stats.NodeName)
		}
		if hostName == "" {
			hostName = strings.TrimSpace(node.Stats.NodeID)
		}
		network := node.Stats.Network
		uplinkRate := formatTelegramRate(network.TxBytesPerSec)
		downlinkRate := formatTelegramRate(network.RxBytesPerSec)
		uplinkTotal := formatTelegramBytes(float64(network.BytesSent))
		downlinkTotal := formatTelegramBytes(float64(network.BytesRecv))
		linkSpeed := formatTelegramLinkSpeed(node)
		detail := []string{
			"服务器状态",
			fmt.Sprintf("ID: %s", node.ServerID),
			fmt.Sprintf("名称: %s", display),
			fmt.Sprintf("状态: %s", statusLabel),
			fmt.Sprintf("系统: %s / %s", node.Stats.OS, node.Stats.Arch),
			fmt.Sprintf("CPU: %.1f%%", node.Stats.CPU.UsagePercent),
			fmt.Sprintf("内存: %.1f%%", node.Stats.Memory.UsedPercent),
			fmt.Sprintf("网速: ↑ %s / ↓ %s", uplinkRate, downlinkRate),
			fmt.Sprintf("累计流量: ↑ %s / ↓ %s", uplinkTotal, downlinkTotal),
			fmt.Sprintf("带宽: %s", linkSpeed),
			fmt.Sprintf("运行时长: %s", uptime),
			fmt.Sprintf("最后上报: %s", lastSeen),
			fmt.Sprintf("首次上线: %s", firstSeen),
			fmt.Sprintf("主机名: %s", hostName),
		}
		if node.Status == "offline" {
			offlineFor := formatAlertDuration(int64(time.Since(time.Unix(node.LastSeen, 0)).Seconds()))
			detail = append(detail, fmt.Sprintf("离线时长: %s", offlineFor))
		}
		return strings.Join(detail, "\n")
	}
	return fmt.Sprintf("未找到服务器: %s", serverID)
}

func setTelegramCommands(token string) error {
	if err := validateTelegramToken(token); err != nil {
		return err
	}
	commands := []map[string]string{
		{"command": "cmall", "description": "查看所有服务器统计"},
		{"command": "server", "description": "查看服务器列表"},
		{"command": "status", "description": "查看服务器状态 /status 服务器ID"},
		{"command": "alarmson", "description": "开启告警 /alarmson 服务器ID"},
		{"command": "alarmsoff", "description": "关闭告警 /alarmsoff 服务器ID"},
		{"command": "ai", "description": "AI 运维 /ai 你的问题"},
		{"command": "help", "description": "查看可用命令"},
	}
	payload := map[string]any{"commands": commands}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram 菜单编码失败: %w", err)
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", token)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("telegram 菜单请求创建失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram 菜单设置失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram 菜单响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result telegramSendResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("telegram 菜单响应解析失败: %w", err)
	}
	if !result.Ok {
		return errors.New(formatTelegramError(result.Description, "telegram 菜单设置失败"))
	}
	return nil
}

func buildTelegramUserKey(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, 0, len(sorted))
	for _, id := range sorted {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ",")
}

func isAllowedTelegramUser(allowed map[int64]struct{}, fromID, chatID int64) bool {
	if _, ok := allowed[fromID]; !ok {
		return false
	}
	if _, ok := allowed[chatID]; !ok {
		return false
	}
	return true
}

func resolveTelegramDisplay(node NodeView) string {
	if value := strings.TrimSpace(node.Alias); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.NodeName); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.Hostname); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.NodeID); value != "" {
		return value
	}
	return "未命名节点"
}

func formatTelegramTime(value int64) string {
	if value <= 0 {
		return "--"
	}
	return time.Unix(value, 0).Format("2006-01-02 15:04:05")
}

func formatTelegramBytes(value float64) string {
	if value < 0 {
		value = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	unitIndex := 0
	for value >= 1024 && unitIndex < len(units)-1 {
		value /= 1024
		unitIndex++
	}
	if value >= 100 {
		return fmt.Sprintf("%.0f %s", value, units[unitIndex])
	}
	if value >= 10 {
		return fmt.Sprintf("%.1f %s", value, units[unitIndex])
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIndex])
}

func formatTelegramRate(value float64) string {
	return fmt.Sprintf("%s/s", formatTelegramBytes(value))
}

func formatTelegramLinkSpeed(node NodeView) string {
	if node.NetSpeedMbps > 0 {
		return fmt.Sprintf("%d Mbps", node.NetSpeedMbps)
	}
	if node.Stats.NetSpeedMbps > 0 {
		if node.Stats.NetSpeedMbps >= 100 {
			return fmt.Sprintf("%.0f Mbps", node.Stats.NetSpeedMbps)
		}
		return fmt.Sprintf("%.1f Mbps", node.Stats.NetSpeedMbps)
	}
	return "--"
}

func formatTelegramError(description, fallback string) string {
	if strings.TrimSpace(description) == "" {
		return fallback
	}
	return description
}

func validateTelegramToken(token string) error {
	value := strings.TrimSpace(token)
	if value == "" {
		return errors.New("telegram token 不能为空")
	}
	if strings.ContainsAny(value, " \t\r\n/") {
		return errors.New("telegram token 格式不正确")
	}
	if len(value) < 10 || len(value) > 128 {
		return errors.New("telegram token 格式不正确")
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("telegram token 格式不正确")
	}
	return nil
}
