package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	telegramSendConcurrency = 4
	telegramPollIdleDelay   = 2 * time.Second
	telegramAIWindow        = time.Minute
	telegramAILimit         = 3
)

var telegramSendFunc = sendTelegramMessage

// telegramBackoffCap 限制 429 Retry-After 的生效上限，防止异常大值
// 把轮询挂起过久。
const telegramBackoffCap = time.Minute

// telegramBackoffDelay 依据结构化 API 错误决定退避时长，不嗅探错误文本
// （响应 body 或下游错误里出现 "401" 字样会误判档位）。
func telegramBackoffDelay(err error) time.Duration {
	var apiErr *telegramAPIError
	if err != nil && errors.As(err, &apiErr) {
		switch {
		case apiErr.statusCode == 429:
			if apiErr.retryAfter > 0 {
				return min(apiErr.retryAfter, telegramBackoffCap)
			}
			return 8 * time.Second
		case apiErr.permanent():
			return 30 * time.Second
		}
	}
	return telegramPollIdleDelay
}

func telegramRequestErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Err != nil {
			return urlErr.Err.Error()
		}
		if urlErr.Op != "" {
			return urlErr.Op
		}
	}
	return err.Error()
}

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
		// menuSetupPending 与 token 变更解耦：菜单设置失败只重试
		// setTelegramCommands，不得触发 offset 重置（会把 Telegram
		// 未确认 update 重新投递，造成命令重复执行）。
		menuSetupPending := false
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			token, userIDs := store.TelegramSettings()
			userIDs = normalizeTelegramUserIDs(userIDs)
			if token == "" || len(userIDs) == 0 {
				if !waitTelegramPoll(ctx, 2*time.Second) {
					return
				}
				continue
			}
			if token != lastToken {
				offset = 0
				lastToken = token
				menuSetupPending = true
			}
			if menuSetupPending {
				if err := setTelegramCommands(ctx, token); err != nil {
					log.Printf("Telegram 菜单设置失败，将自动重试: %v", err)
				} else {
					menuSetupPending = false
				}
			}

			updates, err := fetchTelegramUpdates(ctx, client, token, offset)
			if err != nil {
				log.Printf("Telegram 轮询失败: %v", err)
				if !waitTelegramPoll(ctx, telegramBackoffDelay(err)) {
					return
				}
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
				reply := handleTelegramCommand(ctx, command, store, update.Message.From.ID, update.Message.Chat.ID)
				if reply == "" {
					continue
				}
				if err := sendTelegramMessage(ctx, token, update.Message.Chat.ID, reply); err != nil {
					log.Printf("Telegram 回复失败: %v", err)
				}
			}
			if !waitTelegramPoll(ctx, telegramPollIdleDelay) {
				return
			}
		}
	}()
}

func waitTelegramPoll(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func fetchTelegramUpdates(ctx context.Context, client *http.Client, token string, offset int64) ([]telegramUpdate, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("请求更新失败: %s", telegramRequestErrorMessage(err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求更新失败: %s", telegramRequestErrorMessage(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := readResponseBodyLimited(resp.Body)
		apiErr := &telegramAPIError{
			statusCode: resp.StatusCode,
			err:        fmt.Errorf("更新响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body))),
		}
		if seconds, parseErr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); parseErr == nil && seconds > 0 {
			apiErr.retryAfter = time.Duration(seconds) * time.Second
		}
		return nil, apiErr
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

func sendTelegramAlert(token string, userIDs []int64, siteTitle string, events []AlertEvent) bool {
	return sendTelegramEventNotice(token, userIDs, siteTitle, events, buildAlertMessage, "告警")
}

func sendTelegramRecovery(token string, userIDs []int64, siteTitle string, events []AlertEvent) bool {
	return sendTelegramEventNotice(token, userIDs, siteTitle, events, buildRecoveryMessage, "恢复通知")
}

// telegramMessageLimit 是 sendMessage 文本上限（4096，Telegram 按 UTF-16
// 计）的字节口径余量：批量离线超限时 API 返回 400 属永久失败，告警会
// 静默丢失，必须分片。
const telegramMessageLimit = 4000

// splitTelegramMessage 把消息按行分片到字节上限内，超长单行按 rune 边界
// 硬切（字节数 ≤ UTF-16 单元数，口径保守安全）。
func splitTelegramMessage(text string, limit int) []string {
	if len(text) <= limit {
		return []string{text}
	}
	var chunks []string
	current := ""
	flush := func() {
		if current != "" {
			chunks = append(chunks, current)
			current = ""
		}
	}
	for _, line := range strings.Split(text, "\n") {
		candidate := line
		if current != "" {
			candidate = current + "\n" + line
		}
		switch {
		case len(candidate) <= limit:
			current = candidate
		case len(line) > limit:
			flush()
			for len(line) > limit {
				cut := limit
				for cut > 0 && !utf8.RuneStart(line[cut]) {
					cut--
				}
				if cut == 0 {
					// 非法 UTF-8（无 RuneStart）兜底：按字节硬切，
					// 保证循环必然推进。
					cut = limit
				}
				chunks = append(chunks, line[:cut])
				line = line[cut:]
			}
			current = line
		default:
			flush()
			current = line
		}
	}
	flush()
	return chunks
}

func sendTelegramEventNotice(token string, userIDs []int64, siteTitle string, events []AlertEvent, build func(string, []AlertEvent) string, label string) bool {
	if token == "" || len(userIDs) == 0 || len(events) == 0 {
		return true
	}
	var errs []string
	for _, chunk := range splitTelegramMessage(build(siteTitle, events), telegramMessageLimit) {
		errs = append(errs, sendTelegramMessageToUsers(token, userIDs, chunk)...)
	}
	for _, err := range errs {
		log.Printf("Telegram %s发送失败: %v", label, err)
	}
	return len(errs) == 0
}

func sendTelegramTest(token string, userIDs []int64, siteTitle string) []string {
	message := fmt.Sprintf("【%s】Telegram 告警测试 %s", normalizeSiteTitle(siteTitle), time.Now().Format("2006-01-02 15:04:05"))
	return sendTelegramMessageToUsers(token, userIDs, message)
}

// telegramAPIError 携带 Bot API 的 HTTP 状态码与 429 Retry-After：退避
// 决策与"配置类永久失败"判定都基于结构化字段。permanent 表示无效 token、
// chat 不存在、bot 被拉黑等不可重试失败，告警投递中跳过重臂。
type telegramAPIError struct {
	statusCode int
	retryAfter time.Duration
	err        error
}

func (e *telegramAPIError) Error() string { return e.err.Error() }
func (e *telegramAPIError) Unwrap() error { return e.err }

func (e *telegramAPIError) permanent() bool {
	return e.statusCode == 400 || e.statusCode == 401 || e.statusCode == 403 || e.statusCode == 404
}

func sendTelegramMessageToUsers(token string, userIDs []int64, text string) []string {
	ids := normalizeTelegramUserIDs(userIDs)
	if token == "" || len(ids) == 0 || strings.TrimSpace(text) == "" {
		return nil
	}
	errCh := make(chan string, len(ids))
	sem := make(chan struct{}, telegramSendConcurrency)
	var wg sync.WaitGroup
	for _, id := range ids {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := telegramSendFunc(context.Background(), token, id, text); err != nil {
				var apiErr *telegramAPIError
				if errors.As(err, &apiErr) && apiErr.permanent() {
					log.Printf("Telegram 收件人 %d 不可达，跳过该收件人: %v", id, err)
					return
				}
				errCh <- err.Error()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var errs []string
	for err := range errCh {
		errs = append(errs, err)
	}
	sort.Strings(errs)
	return errs
}

func telegramBotAPICall(ctx context.Context, client *http.Client, token, method string, payload any, label string) (telegramSendResponse, error) {
	if err := validateTelegramToken(token); err != nil {
		return telegramSendResponse{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return telegramSendResponse{}, fmt.Errorf("telegram %s编码失败: %w", label, err)
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return telegramSendResponse{}, fmt.Errorf("telegram %s请求创建失败: %s", label, telegramRequestErrorMessage(err))
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return telegramSendResponse{}, fmt.Errorf("telegram %s发送失败: %s", label, telegramRequestErrorMessage(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := readResponseBodyLimited(resp.Body)
		// 4xx（permanent()）属配置类永久失败，重试无意义；豁免后不触发
		// 告警重臂，避免向其余收件人重发风暴。
		return telegramSendResponse{}, &telegramAPIError{
			statusCode: resp.StatusCode,
			err:        fmt.Errorf("telegram %s响应错误: %d %s", label, resp.StatusCode, strings.TrimSpace(string(body))),
		}
	}
	var result telegramSendResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return telegramSendResponse{}, fmt.Errorf("telegram %s响应解析失败: %w", label, err)
	}
	if !result.Ok {
		return telegramSendResponse{}, errors.New(formatTelegramError(result.Description, "telegram "+label+"失败"))
	}
	return result, nil
}

func sendTelegramMessage(ctx context.Context, token string, userID int64, text string) error {
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
	_, err := telegramBotAPICall(ctx, nil, token, "sendMessage", payload, "消息")
	return err
}

func handleTelegramCommand(ctx context.Context, command string, store *Store, userID, chatID int64) string {
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
		return handleTelegramAICommand(ctx, command, store, userID, chatID)
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

func handleTelegramAICommand(ctx context.Context, command string, store *Store, userID, chatID int64) string {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		return "用法: /ai 你的问题"
	}
	query := strings.TrimSpace(strings.Join(parts[1:], " "))
	if query == "" {
		return "用法: /ai 你的问题"
	}
	if enabled, serverID, ok := parseAIAlertToggle(query, store); ok {
		return toggleAlertForServer(store, serverID, enabled)
	}
	rateKey := fmt.Sprintf("telegram-ai:%d:%d", userID, chatID)
	if !store.allowAgentRate(rateKey, telegramAIWindow, telegramAILimit, time.Now(), false) {
		return "AI 查询过于频繁，请稍后再试"
	}
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
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

// parseAIAlertToggle 仅当 /ai 查询同时包含告警开关词且节点可被唯一
// 识别（服务器ID 或显示名恰命中一个）时才视为开关命令；其余情况
// （如"怎么恢复告警服务"）一律返回 false，交给 AI 回答，避免关键词
// 劫持提问或误触发状态变更。
func parseAIAlertToggle(query string, store *Store) (bool, string, bool) {
	query = strings.TrimSpace(query)
	if query == "" {
		return false, "", false
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
		return false, "", false
	}
	nodes := store.Snapshot()
	matched := 0
	serverID := ""
	for _, node := range nodes {
		if node.ServerID != "" && strings.Contains(query, node.ServerID) {
			matched++
			serverID = node.ServerID
		}
	}
	if matched == 0 {
		for _, node := range nodes {
			display := resolveNodeDisplayName(node)
			if display == "" || display == "未命名节点" {
				continue
			}
			if strings.Contains(query, display) && node.ServerID != "" {
				matched++
				serverID = node.ServerID
			}
		}
	}
	if matched == 1 {
		return enabled, serverID, true
	}
	return false, "", false
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
		return resolveNodeDisplayName(online[i]) < resolveNodeDisplayName(online[j])
	})
	sort.Slice(offline, func(i, j int) bool {
		return resolveNodeDisplayName(offline[i]) < resolveNodeDisplayName(offline[j])
	})
	lines := []string{"服务器列表：", "在线服务器："}
	if len(online) == 0 {
		lines = append(lines, "• 无")
	} else {
		for _, node := range online {
			display := resolveNodeDisplayName(node)
			lines = append(lines, fmt.Sprintf("• %s （%s）", display, node.ServerID))
		}
	}
	lines = append(lines, "", "离线服务器：")
	if len(offline) == 0 {
		lines = append(lines, "• 无")
	} else {
		for _, node := range offline {
			display := resolveNodeDisplayName(node)
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
		display := resolveNodeDisplayName(node)
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

func setTelegramCommands(ctx context.Context, token string) error {
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
	_, err := telegramBotAPICall(ctx, nil, token, "setMyCommands", payload, "菜单")
	return err
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
