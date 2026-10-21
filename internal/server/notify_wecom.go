package server

// 企业微信渠道发送器（F5）：POST {"msgtype":"markdown","markdown":{"content":…}}，
// content ≤4096 字节，超出时按行拆成多条消息依次发送（每条都带标题行），不再
// 截断丢内容；成功条件 errcode==0。mentioned_mobiles 以 “@手机号” 追加到最后一条
// 消息（企业微信 markdown 类型在 content 中 @手机号 即可触发提醒）。发送默认走
// SSRF 防护客户端（notifySendHTTP），不跟随重定向；Config["allow_private"]==true
// 时改用 allow-private 客户端。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// wecomMarkdownByteLimit 是企业微信 markdown 消息 content 的字节上限。
	wecomMarkdownByteLimit = 4096
	// wecomTitleByteLimit 是每条消息重复携带的标题行字节上限：标题过长时按 rune
	// 截断（完整标题在限内时原样保留），避免挤占正文空间。
	wecomTitleByteLimit = 1024
	// wecomMentionReserveMinBytes 是给 @手机号 预留追加位置后正文仍应保留的最小
	// 字节数；预留会把正文挤得更小时就不预留，改为单独补一条 mentions 消息。
	wecomMentionReserveMinBytes = 256
)

type wecomNotifier struct {
	webhook          string
	mentionedMobiles []string
	allowPrivate     bool
}

func newWecomNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("企业微信 webhook 未配置")
	}
	if err := notifyValidateChannelURL(ch, webhook); err != nil {
		return nil, err
	}
	mentioned := splitNotifyList(ch.Config["mentioned_mobiles"])
	if mentions := wecomMentionText(mentioned); len(mentions) > wecomMarkdownByteLimit {
		return nil, fmt.Errorf("企业微信 @手机号 列表过长（%d 字节），单条消息上限 %d 字节", len(mentions), wecomMarkdownByteLimit)
	}
	return &wecomNotifier{
		webhook:          webhook,
		mentionedMobiles: mentioned,
		allowPrivate:     notifyChannelAllowsPrivate(ch),
	}, nil
}

func (n *wecomNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return errors.New("企业微信消息为空")
	}
	title, body, singleLine := splitWecomTitleBody(text)
	contents, err := wecomMessageContents(title, body, singleLine, n.mentionText())
	if err != nil {
		return err
	}
	total := len(contents)
	for index, content := range contents {
		err := n.sendMarkdown(ctx, content)
		if err == nil {
			continue
		}
		// 已发送的条数不回滚（与 Telegram 分片语义一致），但整体必须判为失败，
		// 重试允许重复投递。
		if total > 1 {
			return fmt.Errorf("企业微信第 %d/%d 条消息发送失败: %w", index+1, total, err)
		}
		return err
	}
	return nil
}

// splitWecomTitleBody 把消息拆成首行标题与其余正文。多行消息的正文保留空行
// （企业微信 markdown 段落依赖空行）；单行消息没有可重复的标题，body 返回完整
// 原文，由调用方按字节完整分片，绝不当成标题截断。
func splitWecomTitleBody(text string) (title, body string, singleLine bool) {
	lines := strings.Split(text, "\n")
	title = strings.TrimSpace(lines[0])
	if len(lines) == 1 {
		return title, text, true
	}
	return title, strings.Join(lines[1:], "\n"), false
}

// wecomMentionText 把手机号组装成 markdown 里的 @ 文本。
func wecomMentionText(mobiles []string) string {
	if len(mobiles) == 0 {
		return ""
	}
	mentions := make([]string, 0, len(mobiles))
	for _, mobile := range mobiles {
		mentions = append(mentions, "@"+mobile)
	}
	return strings.Join(mentions, " ")
}

func (n *wecomNotifier) mentionText() string {
	return wecomMentionText(n.mentionedMobiles)
}

// wecomMessageContents 把标题与正文组装成若干条 content，每条 ≤
// wecomMarkdownByteLimit 字节。多行消息每条都带（必要时截短的）标题行，后续消息
// 仍有上下文；单行消息不重复标题，按完整原文分片。@手机号 只追加到本次发送的
// 最后一条；最后一条放不下时作为独立消息发送，绝不把手机号切成两段。
func wecomMessageContents(title, body string, singleLine bool, mentions string) ([]string, error) {
	if singleLine {
		budget := wecomMarkdownByteLimit
		if mentions != "" && budget-(len(mentions)+len("\n\n")) >= wecomMentionReserveMinBytes {
			budget -= len(mentions) + len("\n\n")
		}
		chunks := splitNotifyTextByBytes(body, budget)
		if len(chunks) == 0 {
			chunks = []string{title}
		}
		if mentions == "" {
			return chunks, nil
		}
		last := len(chunks) - 1
		if len(chunks[last])+len("\n\n")+len(mentions) <= wecomMarkdownByteLimit {
			chunks[last] += "\n\n" + mentions
			return chunks, nil
		}
		if len(mentions) <= wecomMarkdownByteLimit {
			return append(chunks, mentions), nil
		}
		return nil, fmt.Errorf("企业微信 @手机号 列表过长（%d 字节），无法放入单条消息", len(mentions))
	}

	// 多行：标题只用于重复展示，过长时截短以免挤占正文。
	title = truncateNotifyBytes(title, wecomTitleByteLimit)
	budget := wecomMarkdownByteLimit - len(title) - len("\n")
	if mentions != "" && budget-(len(mentions)+len("\n\n")) >= wecomMentionReserveMinBytes {
		budget -= len(mentions) + len("\n\n")
	}
	chunks := splitNotifyTextByBytes(body, budget)
	contents := make([]string, 0, len(chunks)+1)
	if len(chunks) == 0 {
		contents = append(contents, title)
	}
	for _, chunk := range chunks {
		contents = append(contents, title+"\n"+chunk)
	}
	if mentions == "" {
		return contents, nil
	}
	last := contents[len(contents)-1]
	if len(last)+len("\n\n")+len(mentions) <= wecomMarkdownByteLimit {
		contents[len(contents)-1] = last + "\n\n" + mentions
		return contents, nil
	}
	if extra := title + "\n" + mentions; len(extra) <= wecomMarkdownByteLimit {
		return append(contents, extra), nil
	}
	if len(mentions) <= wecomMarkdownByteLimit {
		return append(contents, mentions), nil
	}
	return nil, fmt.Errorf("企业微信 @手机号 列表过长（%d 字节），无法放入单条消息", len(mentions))
}

// sendMarkdown 发送单条 markdown 消息，成功条件 errcode==0。
func (n *wecomNotifier) sendMarkdown(ctx context.Context, content string) error {
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"content": content},
	}
	_, respBody, err := postNotifyJSON(ctx, n.webhook, payload, n.allowPrivate)
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
