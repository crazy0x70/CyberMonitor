package server

// telegram 渠道发送器（F5）：POST {api_endpoint}/bot{token}/sendMessage，
// parse_mode=HTML、文本 HTML 转义、4000 字切分、成功条件响应 ok==true。
// 发送走 SSRF 防护客户端（notifySendHTTP），不跟随重定向。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

type telegramNotifier struct {
	endpoint string
	token    string
	threadID string
	chatIDs  []int64
}

func newTelegramNotifier(ch NotifyChannel) (Notifier, error) {
	token := strings.TrimSpace(ch.Secrets["bot_token"])
	if err := validateTelegramToken(token); err != nil {
		return nil, err
	}
	chatIDs := parseNotifyChatIDs(ch.Config["chat_ids"])
	if len(chatIDs) == 0 {
		return nil, errors.New("telegram chat_ids 未配置")
	}
	endpoint := strings.TrimSpace(ch.Config["api_endpoint"])
	if endpoint == "" {
		endpoint = defaultTelegramAPIEndpoint
	} else if err := notifyValidateWebhookURL(endpoint); err != nil {
		return nil, errors.New("telegram api_endpoint 无效")
	}
	threadID := strings.TrimSpace(ch.Config["message_thread_id"])
	if threadID != "" {
		if value, err := strconv.ParseInt(threadID, 10, 64); err != nil || value <= 0 {
			return nil, errors.New("telegram message_thread_id 需为正整数")
		}
	}
	return &telegramNotifier{
		endpoint: strings.TrimRight(endpoint, "/"),
		token:    token,
		threadID: threadID,
		chatIDs:  chatIDs,
	}, nil
}

func (n *telegramNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	text := msg.Text
	if strings.TrimSpace(text) == "" {
		return errors.New("telegram 消息为空")
	}
	var errs []string
	for _, chunk := range splitTelegramMessage(text, telegramMessageLimit, telegramEscapedRuneLen) {
		errs = append(errs, n.sendChunkToUsers(ctx, telegramEscapeHTML(chunk))...)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// sendChunkToUsers 并发投递单个分片（沿用 Bot 路径的并发度与语义：400/401/403/404
// 视为收件人永久不可达，跳过该收件人；其余错误聚合返回）。
func (n *telegramNotifier) sendChunkToUsers(ctx context.Context, text string) []string {
	errCh := make(chan string, len(n.chatIDs))
	sem := make(chan struct{}, telegramSendConcurrency)
	var wg sync.WaitGroup
	for _, id := range n.chatIDs {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := n.sendMessage(ctx, id, text); err != nil {
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

func (n *telegramNotifier) sendMessage(ctx context.Context, chatID int64, text string) error {
	if chatID <= 0 {
		return errors.New("telegram 用户 ID 无效")
	}
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if n.threadID != "" {
		value, _ := strconv.ParseInt(n.threadID, 10, 64)
		payload["message_thread_id"] = value
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram 消息编码失败: %w", err)
	}
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", n.endpoint, n.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("telegram 请求创建失败: %s", telegramRequestErrorMessage(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifySendHTTP(req)
	if err != nil {
		return fmt.Errorf("telegram 发送失败: %s", telegramRequestErrorMessage(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := readResponseBodyLimited(resp.Body)
		return &telegramAPIError{
			statusCode: resp.StatusCode,
			err:        fmt.Errorf("telegram 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body))),
		}
	}
	var result telegramSendResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("telegram 响应解析失败: %w", err)
	}
	if !result.Ok {
		return errors.New(formatTelegramError(result.Description, "telegram 消息失败"))
	}
	return nil
}

// telegramEscapeHTML 转义 Telegram HTML 模式保留的三个字符（& < >）。
func telegramEscapeHTML(text string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(text)
}

// telegramEscapedRuneLen 返回单个 rune 经 HTML 转义后的字节长度，供按转义后
// 长度切分消息使用。
func telegramEscapedRuneLen(r rune) int {
	switch r {
	case '&':
		return len("&amp;")
	case '<':
		return len("&lt;")
	case '>':
		return len("&gt;")
	default:
		return utf8.RuneLen(r)
	}
}

// splitTelegramMessage 按权重函数把长文本切分为不超过 limit 的分片：优先按换行
// 断开，单行超限再按 rune 硬切（不切断多字节字符）。权重函数返回单个 rune 的
// 长度贡献（telegram 渠道传入转义后长度，保证 HTML 实体不会把分片撑爆上限）。
func splitTelegramMessage(text string, limit int, weight func(rune) int) []string {
	if measureWeightedLen(text, weight) <= limit {
		return []string{text}
	}
	var chunks []string
	current := ""
	currentLen := 0
	flush := func() {
		if current != "" {
			chunks = append(chunks, current)
			current = ""
			currentLen = 0
		}
	}
	for _, line := range strings.Split(text, "\n") {
		lineLen := measureWeightedLen(line, weight)
		joiner := 0
		if current != "" {
			joiner = weight('\n')
		}
		switch {
		case currentLen+joiner+lineLen <= limit:
			if current != "" {
				current += "\n"
			}
			current += line
			currentLen += joiner + lineLen
		case lineLen > limit:
			flush()
			for len(line) > 0 {
				cut := 0
				used := 0
				for cut < len(line) {
					r, size := utf8.DecodeRuneInString(line[cut:])
					w := weight(r)
					if used+w > limit {
						break
					}
					used += w
					cut += size
				}
				if cut == 0 {
					// 单 rune 转义后仍超限（理论上不可达）：按字节兜底，避免死循环。
					cut = 1
				}
				chunks = append(chunks, line[:cut])
				line = line[cut:]
			}
		default:
			flush()
			current = line
			currentLen = lineLen
		}
	}
	flush()
	return chunks
}

func measureWeightedLen(text string, weight func(rune) int) int {
	total := 0
	for _, r := range text {
		total += weight(r)
	}
	return total
}
