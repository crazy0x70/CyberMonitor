package server

// 企业微信渠道发送器（F5）：POST {"msgtype":"markdown","markdown":{"content":…}}，
// content ≤4096 字节、超出截断；成功条件 errcode==0。mentioned_mobiles 以
// “@手机号” 追加到 markdown 内容末尾（企业微信 markdown 类型在 content 中
// @手机号 即可触发提醒）。发送走 SSRF 防护客户端（notifySendHTTP），不跟随重定向。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// wecomMarkdownByteLimit 是企业微信 markdown 消息 content 的字节上限。
const wecomMarkdownByteLimit = 4096

type wecomNotifier struct {
	webhook          string
	mentionedMobiles []string
}

func newWecomNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("企业微信 webhook 未配置")
	}
	if err := notifyValidateWebhookURL(webhook); err != nil {
		return nil, err
	}
	return &wecomNotifier{
		webhook:          webhook,
		mentionedMobiles: splitNotifyList(ch.Config["mentioned_mobiles"]),
	}, nil
}

func (n *wecomNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return errors.New("企业微信消息为空")
	}
	content := text
	if len(n.mentionedMobiles) > 0 {
		mentions := make([]string, 0, len(n.mentionedMobiles))
		for _, mobile := range n.mentionedMobiles {
			mentions = append(mentions, "@"+mobile)
		}
		content += "\n\n" + strings.Join(mentions, " ")
	}
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"content": truncateWecomMarkdownContent(content)},
	}
	_, respBody, err := postNotifyJSON(ctx, n.webhook, payload)
	if err != nil {
		return err
	}
	var wecomResp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(respBody, &wecomResp); err != nil {
		return errors.New("企业微信响应非 JSON，投递结果未知")
	}
	if wecomResp.ErrCode != 0 {
		return fmt.Errorf("企业微信返回错误 errcode=%d: %s", wecomResp.ErrCode, strings.TrimSpace(wecomResp.ErrMsg))
	}
	return nil
}

// truncateWecomMarkdownContent 把 content 按 rune 截断到不超过 limit 字节，
// 不切断多字节字符。
func truncateWecomMarkdownContent(content string) string {
	if len(content) <= wecomMarkdownByteLimit {
		return content
	}
	var truncated strings.Builder
	for _, r := range content {
		if truncated.Len()+utf8.RuneLen(r) > wecomMarkdownByteLimit {
			break
		}
		truncated.WriteRune(r)
	}
	return truncated.String()
}
