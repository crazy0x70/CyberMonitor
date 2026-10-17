package server

// F5 渠道通知：统一的多渠道发送入口。
//
// 每个渠道类型一个 Notifier 实现（notify_telegram.go、notify_feishu.go、
// notify_bark.go、notify_slack.go、notify_dingtalk.go、notify_wecom.go、
// notify_email.go），由 newNotifier 按 NotifyChannel.Type 构造。所有 HTTP 渠道在
// 生产环境统一走 sharedWebhookClient（SSRF 防护、不跟随重定向），出站 URL 先经
// validateWebhookURL 静态校验；邮件渠道复用 restrictedCallbackDialContext
// 受限拨号器。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// notifySendTimeout 是单次渠道发送的外层时限（文档定稿 15s）；HTTP 请求本身
// 仍受 sharedWebhookClient 的客户端级超时约束。
const notifySendTimeout = 15 * time.Second

// 测试接缝（生产实现见默认值）：notifySendHTTP 绑定 SSRF 防护客户端；
// notifyValidateWebhookURL 绑定静态 webhook/端点校验。测试替换后可指向本地
// httptest.Server（绕开私网地址拒绝），仅影响渠道发送路径。
var (
	notifySendHTTP = func(req *http.Request) (*http.Response, error) {
		return sharedWebhookClient().Do(req)
	}
	notifyValidateWebhookURL = validateWebhookURL
)

// NotifyMessage 是一次通知投递的载荷：Text 为已组装好的纯文本消息（含标题行）。
// 各渠道 Notifier 自行处理转义、长度切分与签名。
type NotifyMessage struct {
	Text string
}

// Notifier 是单个通知渠道的发送器。
type Notifier interface {
	Send(ctx context.Context, msg NotifyMessage) error
}

// newNotifier 按 NotifyChannel.Type 构造发送器（F5 定稿的 7 种类型全部支持）。
func newNotifier(ch NotifyChannel) (Notifier, error) {
	switch normalizeNotifyChannelType(ch.Type) {
	case notifyChannelTypeTelegram:
		return newTelegramNotifier(ch)
	case notifyChannelTypeFeishu:
		return newFeishuNotifier(ch)
	case notifyChannelTypeBark:
		return newBarkNotifier(ch)
	case notifyChannelTypeSlack:
		return newSlackNotifier(ch)
	case notifyChannelTypeDingtalk:
		return newDingtalkNotifier(ch)
	case notifyChannelTypeWecom:
		return newWecomNotifier(ch)
	case notifyChannelTypeEmail:
		return newEmailNotifier(ch)
	default:
		return nil, fmt.Errorf("通知渠道类型 %q 的发送暂未支持", strings.TrimSpace(ch.Type))
	}
}

// dispatchChannelNotices 把一批事件按渠道逐个投递：每个渠道只发它尚未送达的
// 事件（owedAlertEvents），返回渠道 ID → 是否全部成功。日志不输出 token 或
// webhook 全文（错误文案由各 Notifier 保证脱敏）。
func dispatchChannelNotices(channels []NotifyChannel, siteTitle string, events []AlertEvent, build func(string, []AlertEvent) string, label string) map[string]bool {
	results := make(map[string]bool, len(channels))
	for _, channel := range channels {
		owed := owedAlertEvents(events, channel.ID)
		if len(owed) == 0 {
			results[channel.ID] = true
			continue
		}
		notifier, err := newNotifier(channel)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
			err = notifier.Send(ctx, NotifyMessage{Text: build(siteTitle, owed)})
			cancel()
		}
		if err != nil {
			log.Printf("%s发送失败（渠道 %s）: %v", label, channel.ID, err)
			results[channel.ID] = false
			continue
		}
		results[channel.ID] = true
	}
	return results
}

func allChannelNoticesOK(results map[string]bool) bool {
	for _, ok := range results {
		if !ok {
			return false
		}
	}
	return true
}

// notifyChannelDisplayName 返回渠道展示名（名称缺省时退回类型名）。
func notifyChannelDisplayName(channel NotifyChannel) string {
	if name := strings.TrimSpace(channel.Name); name != "" {
		return name
	}
	return strings.TrimSpace(channel.Type)
}

// sendChannelTestMessage 向未保存的渠道草稿发送测试消息（测试推送接口使用）。
// 调用方负责先用同 ID 的已存渠道补齐空 secret。
func sendChannelTestMessage(ctx context.Context, channel NotifyChannel, siteTitle string) error {
	if strings.TrimSpace(channel.ID) == "" {
		return errors.New("渠道缺少 id")
	}
	notifier, err := newNotifier(channel)
	if err != nil {
		return err
	}
	message := fmt.Sprintf("【%s】通知渠道测试·%s %s",
		normalizeSiteTitle(siteTitle),
		notifyChannelDisplayName(channel),
		time.Now().Format("2006-01-02 15:04:05"),
	)
	return notifier.Send(ctx, NotifyMessage{Text: message})
}

// splitNotifyTitleBody 把已组装的消息拆为标题（首行）与正文（其余行，去掉首部
// 空行）。正文为空时回退为标题本身（单行消息场景，例如测试推送）。bark /
// slack / dingtalk / email 渠道按此拆分。
func splitNotifyTitleBody(text string) (title, body string) {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	title = strings.TrimSpace(lines[0])
	if len(lines) > 1 {
		body = strings.TrimSpace(strings.Join(lines[1:], "\n"))
	}
	if body == "" {
		body = title
	}
	return title, body
}

// splitNotifyList 解析逗号分隔的列表配置（email to、dingtalk at_mobiles、
// wecom mentioned_mobiles）：修剪空白、丢弃空项、保序去重。
func splitNotifyList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var values []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		values = append(values, part)
	}
	return values
}

// postNotifyJSON 以 JSON POST 投递到指定端点并返回（状态码, 响应体）。状态码
// ≥300 视为失败。错误文案不携带目标 URL（含 webhook 查询参数），响应样本限长。
func postNotifyJSON(ctx context.Context, endpoint string, payload any) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("告警消息编码失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("告警请求创建失败: %s", telegramRequestErrorMessage(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifySendHTTP(req)
	if err != nil {
		return 0, nil, fmt.Errorf("告警发送失败: %s", telegramRequestErrorMessage(err))
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, body, fmt.Errorf("webhook 响应错误: %d %s", resp.StatusCode, sampleNotifyBody(body))
	}
	return resp.StatusCode, body, nil
}

// sampleNotifyBody 返回限长的响应体样本，供错误文案引用。按 rune 截断前 120
// 个字符（B-09：按字节截断会切断多字节 UTF-8 序列，中文响应体会变成乱码）。
func sampleNotifyBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if runes := []rune(text); len(runes) > 120 {
		text = string(runes[:120]) + "…"
	}
	return text
}
