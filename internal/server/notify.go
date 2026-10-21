package server

// F5 渠道通知：统一的多渠道发送入口。
//
// 每个渠道类型一个 Notifier 实现（notify_telegram.go、notify_feishu.go、
// notify_bark.go、notify_slack.go、notify_dingtalk.go、notify_wecom.go、
// notify_email.go），由 newNotifier 按 NotifyChannel.Type 构造。所有 HTTP 渠道在
// 生产环境默认走 sharedWebhookClient（SSRF 防护、不跟随重定向），出站 URL 先经
// validateWebhookURL 静态校验；邮件渠道默认复用 restrictedCallbackDialContext
// 受限拨号器。
//
// 渠道 Config["allow_private"] == "true" 时改用 allow-private 版客户端与校验：
// 放行私网/环回目标（涵盖 fake-ip 代理把 api.day.app 等解析到 198.18.0.0/15
// 的场景，以及 Bark/Telegram 自建服务与内网 SMTP），默认关闭时行为不变。

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
	"unicode/utf8"
)

// notifySendTimeout 是单次渠道发送的外层时限（文档定稿 15s）；HTTP 请求本身
// 仍受 sharedWebhookClient 的客户端级超时约束。
const notifySendTimeout = 15 * time.Second

// notifyPrivateTargetHint 在拒绝内网目标时随错误一并返回，指引管理员按渠道开启
// “允许内网地址”（fake-ip 代理与内网自建服务都需要它）。
const notifyPrivateTargetHint = "如果服务器使用 Clash/Surge 等 fake-ip 代理，或目标是内网自建服务，请在该渠道中开启“允许内网地址”"

// 测试接缝（生产实现见默认值）：notifySendHTTP 绑定 SSRF 防护客户端；
// notifyValidateWebhookURL 绑定静态 webhook/端点校验。测试替换后可指向本地
// httptest.Server（绕开私网地址拒绝），仅影响渠道发送路径。
// AllowPrivate 版是渠道开启“允许内网地址”后的对应实现；未开启的渠道仍只走
// 受限版，保证现有测试只需替换受限版接缝。
var (
	notifySendHTTP = func(req *http.Request) (*http.Response, error) {
		return sharedWebhookClient().Do(req)
	}
	notifySendHTTPAllowPrivate = func(req *http.Request) (*http.Response, error) {
		return sharedWebhookClientAllowPrivate().Do(req)
	}
	notifyValidateWebhookURL             = validateWebhookURL
	notifyValidateWebhookURLAllowPrivate = validateWebhookURLAllowPrivate
)

// notifyChannelAllowsPrivate 返回渠道是否显式开启“允许内网地址”：Config 里
// allow_private 的值必须精确为 "true"；缺省、false、TRUE、带空白等任何其他写法
// 一律视为关闭，与前端只认字符串 "true" 的契约保持一致。
func notifyChannelAllowsPrivate(ch NotifyChannel) bool {
	return ch.Config["allow_private"] == "true"
}

// notifyValidateChannelURL 按渠道开关选静态校验，并把内网拒绝改写为带指引的
// 中文文案（其他错误原样返回，不携带 webhook 全文）。
func notifyValidateChannelURL(ch NotifyChannel, raw string) error {
	if notifyChannelAllowsPrivate(ch) {
		return decorateNotifyPrivateTargetError(notifyValidateWebhookURLAllowPrivate(raw))
	}
	return decorateNotifyPrivateTargetError(notifyValidateWebhookURL(raw))
}

// notifySendHTTPFor 按渠道开关选发送客户端并装饰内网拒绝错误。allowPrivate 由
// 构造时从渠道配置解析（见各 new*Notifier），与静态校验使用同一个开关。
func notifySendHTTPFor(allowPrivate bool, req *http.Request) (*http.Response, error) {
	send := notifySendHTTP
	if allowPrivate {
		send = notifySendHTTPAllowPrivate
	}
	resp, err := send(req)
	if err != nil {
		return nil, decorateNotifyPrivateTargetError(err)
	}
	return resp, nil
}

// decorateNotifyPrivateTargetError 把内网/保留地址的拒绝错误改写为对管理员有
// 指引意义的文案；只针对 privateTargetError 这一确定性拒绝，不影响普通网络
// 错误的原样透出，也不回显 webhook 全文或 secret。
func decorateNotifyPrivateTargetError(err error) error {
	if err == nil {
		return nil
	}
	var target *privateTargetError
	if !errors.As(err, &target) {
		return err
	}
	return fmt.Errorf("目标 %s 是内网/保留地址，已被安全策略拒绝。%s", target.target(), notifyPrivateTargetHint)
}

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

// splitNotifyTextByBytes 按行贪心打包文本，保证每个分片不超过 limit 字节：不丢
// 行内容，尽量保留空行（markdown 段落依赖空行）；空行正好落在分片边界、两侧都
// 没有余量时不会单独生成一个纯空片。单行本身超限时按 rune 硬切且不切断多字节
// 序列。输入为空白时返回 nil。
func splitNotifyTextByBytes(text string, limit int) []string {
	return splitNotifyText(text, limit, func(s string) int { return len(s) }, utf8.RuneLen)
}

// splitNotifyTextByRunes 与 splitNotifyTextByBytes 相同，但按 rune 数计量
// （Slack 的 block 文本上限按字符而非字节）。
func splitNotifyTextByRunes(text string, limit int) []string {
	return splitNotifyText(text, limit, utf8.RuneCountInString, func(rune) int { return 1 })
}

// splitNotifyText 是上面两个函数的共用实现：measure 返回整段文本的长度，
// runeWeight 返回单个 rune 的长度贡献（两者必须按同一单位计量）。
func splitNotifyText(text string, limit int, measure func(string) int, runeWeight func(rune) int) []string {
	if limit <= 0 || strings.TrimSpace(text) == "" {
		return nil
	}
	if measure(text) <= limit {
		return []string{text}
	}
	separator := measure("\n")
	chunks := make([]string, 0, measure(text)/limit+1)
	current := ""
	currentLen := 0
	hasCurrent := false
	flush := func() {
		// 只保留有内容的行组：纯空行分片本身不携带信息，也不会丢行内容。
		if hasCurrent && strings.TrimSpace(current) != "" {
			chunks = append(chunks, current)
		}
		current = ""
		currentLen = 0
		hasCurrent = false
	}
	for _, line := range strings.Split(text, "\n") {
		lineLen := measure(line)
		if hasCurrent && currentLen+separator+lineLen <= limit {
			current += "\n" + line
			currentLen += separator + lineLen
			continue
		}
		flush()
		if lineLen <= limit {
			current, currentLen, hasCurrent = line, lineLen, true
			continue
		}
		// 单行超限：先按 rune 硬切成不超过 limit 的片段，最后一片留作 current，
		// 让后续行还能继续追加，避免碎片化。硬切路径同样不能产生纯空白片：
		// 例如“内容 + 大量空格 + 内容”会切出整片空格，不能直接 append。
		parts := hardSplitNotifyLine(line, limit, runeWeight)
		for _, part := range parts[:len(parts)-1] {
			if strings.TrimSpace(part) != "" {
				chunks = append(chunks, part)
			}
		}
		last := parts[len(parts)-1]
		if strings.TrimSpace(last) == "" {
			current, currentLen, hasCurrent = "", 0, false
			continue
		}
		current, currentLen, hasCurrent = last, measure(last), true
	}
	flush()
	if len(chunks) == 0 {
		return nil
	}
	return chunks
}

// hardSplitNotifyLine 把超限单行按 rune 切成每段不超过 limit 的片段，绝不切断
// 多字节字符。若单个 rune 的权重本身就超过 limit（只可能出现在极小 limit 的调用
// 中），仍保留该 rune，避免丢内容。
func hardSplitNotifyLine(line string, limit int, runeWeight func(rune) int) []string {
	var parts []string
	for line != "" {
		cut := 0
		used := 0
		for cut < len(line) {
			r, size := utf8.DecodeRuneInString(line[cut:])
			weight := runeWeight(r)
			if used+weight > limit {
				break
			}
			used += weight
			cut += size
		}
		if cut == 0 {
			_, size := utf8.DecodeRuneInString(line)
			cut = size
		}
		parts = append(parts, line[:cut])
		line = line[cut:]
	}
	return parts
}

// truncateNotifyRunes 把 text 按 rune 截到不超过 limit 个字符（截断时末尾加 …，
// 总长仍 ≤ limit），不切断多字节字符。
func truncateNotifyRunes(text string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

// truncateNotifyBytes 把 text 按 rune 截到不超过 limit 字节（截断时末尾加 …），
// 不切断多字节字符。
func truncateNotifyBytes(text string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(text) <= limit {
		return text
	}
	const ellipsis = "…"
	budget := limit - len(ellipsis)
	withEllipsis := budget >= 0
	if !withEllipsis {
		budget = limit
	}
	var truncated strings.Builder
	for _, r := range text {
		if truncated.Len()+utf8.RuneLen(r) > budget {
			break
		}
		truncated.WriteRune(r)
	}
	if withEllipsis {
		truncated.WriteString(ellipsis)
	}
	return truncated.String()
}

// postNotifyJSON 以 JSON POST 投递到指定端点并返回（状态码, 响应体）。allowPrivate
// 决定走受限还是 allow-private 发送客户端。状态码 ≥300 视为失败。错误文案不
// 携带目标 URL（含 webhook 查询参数），响应样本限长。
func postNotifyJSON(ctx context.Context, endpoint string, payload any, allowPrivate bool) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("告警消息编码失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("告警请求创建失败: %s", telegramRequestErrorMessage(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifySendHTTPFor(allowPrivate, req)
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
