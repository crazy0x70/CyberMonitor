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
		var lastUserID int64
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			token, userID := store.TelegramSettings()
			if token == "" || userID <= 0 {
				time.Sleep(2 * time.Second)
				continue
			}
			if token != lastToken || userID != lastUserID {
				offset = 0
				lastToken = token
				lastUserID = userID
			}

			updates, err := fetchTelegramUpdates(client, token, offset)
			if err != nil {
				log.Printf("Telegram 轮询失败: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			for _, update := range updates {
				if update.UpdateID >= offset {
					offset = update.UpdateID + 1
				}
				if update.Message == nil || update.Message.From == nil || update.Message.Chat == nil {
					continue
				}
				if update.Message.From.ID != userID || update.Message.Chat.ID != userID {
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
				if err := sendTelegramMessage(token, userID, reply); err != nil {
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

func sendTelegramAlert(token string, userID int64, siteTitle string, events []AlertEvent) {
	if token == "" || userID <= 0 || len(events) == 0 {
		return
	}
	if err := sendTelegramMessage(token, userID, buildAlertMessage(siteTitle, events)); err != nil {
		log.Printf("Telegram 告警发送失败: %v", err)
	}
}

func sendTelegramRecovery(token string, userID int64, siteTitle string, events []AlertEvent) {
	if token == "" || userID <= 0 || len(events) == 0 {
		return
	}
	if err := sendTelegramMessage(token, userID, buildRecoveryMessage(siteTitle, events)); err != nil {
		log.Printf("Telegram 恢复通知发送失败: %v", err)
	}
}

func sendTelegramTest(token string, userID int64, siteTitle string) error {
	message := fmt.Sprintf("【%s】Telegram 告警测试 %s", normalizeSiteTitle(siteTitle), time.Now().Format("2006-01-02 15:04:05"))
	return sendTelegramMessage(token, userID, message)
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
	var result telegramUpdateResponse
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
	switch parts[0] {
	case "/cmall":
		return buildTelegramAllStats(store)
	case "/server":
		return buildTelegramServerList(store)
	case "/status":
		if len(parts) < 2 {
			return "用法: /status 服务器ID"
		}
		return buildTelegramServerStatus(store, parts[1])
	default:
		return "支持命令：/cmall /server /status <服务器ID>"
	}
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
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Status == nodes[j].Status {
			return resolveTelegramDisplay(nodes[i]) < resolveTelegramDisplay(nodes[j])
		}
		return nodes[i].Status != "offline"
	})
	lines := []string{"服务器列表："}
	for _, node := range nodes {
		display := resolveTelegramDisplay(node)
		status := "在线"
		if node.Status == "offline" {
			status = "离线"
		}
		lines = append(lines, fmt.Sprintf("• %s %s（%s）", node.ServerID, display, status))
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
		detail := []string{
			"服务器状态",
			fmt.Sprintf("ID: %s", node.ServerID),
			fmt.Sprintf("名称: %s", display),
			fmt.Sprintf("状态: %s", statusLabel),
			fmt.Sprintf("系统: %s / %s", node.Stats.OS, node.Stats.Arch),
			fmt.Sprintf("CPU: %.1f%%", node.Stats.CPU.UsagePercent),
			fmt.Sprintf("内存: %.1f%%", node.Stats.Memory.UsedPercent),
			fmt.Sprintf("运行时长: %s", uptime),
			fmt.Sprintf("最后上报: %s", lastSeen),
			fmt.Sprintf("首次上线: %s", firstSeen),
			fmt.Sprintf("节点ID: %s", node.Stats.NodeID),
		}
		if node.Status == "offline" {
			offlineFor := formatAlertDuration(int64(time.Since(time.Unix(node.LastSeen, 0)).Seconds()))
			detail = append(detail, fmt.Sprintf("离线时长: %s", offlineFor))
		}
		return strings.Join(detail, "\n")
	}
	return fmt.Sprintf("未找到服务器: %s", serverID)
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
