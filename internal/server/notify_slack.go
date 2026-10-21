package server

// slack 渠道发送器（F5）：POST {"text":fallback,"blocks":[header+section(mrkdwn)]}；
// 成功条件 HTTP 200 且响应体为 ok。单条消息的 header plain_text 限 150 字符、
// section mrkdwn 限 3000 字符、blocks 限 50 个，超出时按行拆成多条消息依次发送
// （每条重复 header），避免整批告警被 Slack 拒绝。发送默认走 SSRF 防护客户端
// （notifySendHTTP），不跟随重定向；Config["allow_private"]==true 时改用
// allow-private 客户端。

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	// slackHeaderRuneLimit 是 header block plain_text 的字符上限。
	slackHeaderRuneLimit = 150
	// slackSectionRuneLimit 是 section block mrkdwn 的字符上限。
	slackSectionRuneLimit = 3000
	// slackMaxBlocks 是单条消息的 block 上限（1 个 header + 若干 section）。
	slackMaxBlocks = 50
	// slackFallbackTextRuneLimit 是 payload.text（fallback 预览文本）的字符上限。
	slackFallbackTextRuneLimit = 40000
)

// slackBlockText 是 block 内的文本对象；header 块用 plain_text，section 块用
// mrkdwn。
type slackBlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type string          `json:"type"`
	Text *slackBlockText `json:"text,omitempty"`
}

// slackPayload 是一条 Slack 消息的载荷（text 为 fallback）。
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

type slackNotifier struct {
	webhook      string
	allowPrivate bool
}

func newSlackNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("slack webhook 未配置")
	}
	if err := notifyValidateChannelURL(ch, webhook); err != nil {
		return nil, err
	}
	return &slackNotifier{webhook: webhook, allowPrivate: notifyChannelAllowsPrivate(ch)}, nil
}

func (n *slackNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	title, body := splitNotifyTitleBody(msg.Text)
	if title == "" {
		return errors.New("slack 消息为空")
	}
	payloads := slackMessages(
		truncateNotifyRunes(title, slackHeaderRuneLimit),
		strings.TrimSpace(msg.Text),
		splitNotifyTextByRunes(body, slackSectionRuneLimit),
	)
	total := len(payloads)
	for index, payload := range payloads {
		status, respBody, err := postNotifyJSON(ctx, n.webhook, payload, n.allowPrivate)
		if err == nil && (status != 200 || strings.TrimSpace(string(respBody)) != "ok") {
			err = errors.New("slack 响应异常: " + sampleNotifyBody(respBody))
		}
		if err == nil {
			continue
		}
		// 已发送的条数不回滚，但整体必须判为失败，避免“部分成功”掩盖丢内容。
		if total > 1 {
			return fmt.Errorf("slack 第 %d/%d 条消息发送失败: %w", index+1, total, err)
		}
		return err
	}
	return nil
}

// slackMessages 把 header 与正文分片组装成若干条消息：每条 1 个 header block 加
// 最多 slackMaxBlocks-1 个 section，超出部分拆到后续消息（每条重复 header）。
// 能装进单条消息时 fallback 保留原始消息文本；拆成多条时每条用“header + 本消息
// 正文”，避免预览重复标题或丢失段落。
func slackMessages(header, original string, sections []string) []slackPayload {
	if len(sections) == 0 {
		sections = []string{header}
	}
	perMessage := slackMaxBlocks - 1
	totalMessages := (len(sections) + perMessage - 1) / perMessage
	messages := make([]slackPayload, 0, totalMessages)
	for start := 0; start < len(sections); start += perMessage {
		group := sections[start:min(start+perMessage, len(sections))]
		blocks := make([]slackBlock, 0, len(group)+1)
		blocks = append(blocks, slackBlock{
			Type: "header",
			Text: &slackBlockText{Type: "plain_text", Text: header},
		})
		for _, section := range group {
			blocks = append(blocks, slackBlock{
				Type: "section",
				Text: &slackBlockText{Type: "mrkdwn", Text: section},
			})
		}
		fallback := original
		if totalMessages > 1 {
			fallback = header + "\n" + strings.Join(group, "\n")
		}
		messages = append(messages, slackPayload{
			Text:   truncateNotifyRunes(fallback, slackFallbackTextRuneLimit),
			Blocks: blocks,
		})
	}
	return messages
}
