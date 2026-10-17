package server

// slack 渠道发送器（F5）：POST {"text":fallback,"blocks":[header+section(mrkdwn)]}；
// 成功条件 HTTP 200 且响应体为 ok。发送走 SSRF 防护客户端（notifySendHTTP），
// 不跟随重定向。

import (
	"context"
	"errors"
	"strings"
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

type slackNotifier struct {
	webhook string
}

func newSlackNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("slack webhook 未配置")
	}
	if err := notifyValidateWebhookURL(webhook); err != nil {
		return nil, err
	}
	return &slackNotifier{webhook: webhook}, nil
}

func (n *slackNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	title, body := splitNotifyTitleBody(msg.Text)
	if title == "" {
		return errors.New("slack 消息为空")
	}
	payload := struct {
		Text   string       `json:"text"`
		Blocks []slackBlock `json:"blocks"`
	}{
		// text 为 fallback：纯文本客户端与通知预览使用完整消息。
		Text: strings.TrimSpace(msg.Text),
		Blocks: []slackBlock{
			{Type: "header", Text: &slackBlockText{Type: "plain_text", Text: title}},
			{Type: "section", Text: &slackBlockText{Type: "mrkdwn", Text: body}},
		},
	}
	status, respBody, err := postNotifyJSON(ctx, n.webhook, payload)
	if err != nil {
		return err
	}
	if status != 200 || strings.TrimSpace(string(respBody)) != "ok" {
		return errors.New("slack 响应异常: " + sampleNotifyBody(respBody))
	}
	return nil
}
