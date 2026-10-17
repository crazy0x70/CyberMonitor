package server

// 钉钉渠道发送器（F5）：配置 sign_secret 时按文档加签——ts 毫秒；
// sign = urlencode(base64(HmacSHA256(key=secret, msg=ts+"\n"+secret)))，URL 追加
// &timestamp=&sign=；body {"msgtype":"markdown","markdown":{"title","text"},
// "at":{…}}；成功条件 errcode==0。发送走 SSRF 防护客户端（notifySendHTTP），
// 不跟随重定向。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type dingtalkNotifier struct {
	webhook    string
	signSecret string
	atMobiles  []string
	atAll      bool
}

func newDingtalkNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("钉钉 webhook 未配置")
	}
	if err := notifyValidateWebhookURL(webhook); err != nil {
		return nil, err
	}
	atAll := false
	if raw := strings.TrimSpace(ch.Config["at_all"]); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, errors.New("钉钉 at_all 需为 true/false")
		}
		atAll = value
	}
	return &dingtalkNotifier{
		webhook:    webhook,
		signSecret: strings.TrimSpace(ch.Secrets["sign_secret"]),
		atMobiles:  splitNotifyList(ch.Config["at_mobiles"]),
		atAll:      atAll,
	}, nil
}

func (n *dingtalkNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return errors.New("钉钉消息为空")
	}
	title, _ := splitNotifyTitleBody(text)
	// atMobiles 为 nil 时编码为 null，钉钉期望数组；空列表显式下发。
	atMobiles := n.atMobiles
	if atMobiles == nil {
		atMobiles = []string{}
	}
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": title, "text": text},
		"at": map[string]any{
			"atMobiles": atMobiles,
			"isAtAll":   n.atAll,
		},
	}
	endpoint := dingtalkSignedWebhook(n.webhook, time.Now().UnixMilli(), n.signSecret)
	_, respBody, err := postNotifyJSON(ctx, endpoint, payload)
	if err != nil {
		return err
	}
	var dingResp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(respBody, &dingResp); err != nil {
		return errors.New("钉钉响应非 JSON，投递结果未知")
	}
	if dingResp.ErrCode != 0 {
		return fmt.Errorf("钉钉返回错误 errcode=%d: %s", dingResp.ErrCode, strings.TrimSpace(dingResp.ErrMsg))
	}
	return nil
}

// dingtalkSignedWebhook 在 webhook 上追加 timestamp 与 sign 查询参数（ts 毫秒）。
// webhook 已带查询串（含 access_token）时用 & 拼接，否则用 ?。未配置 secret 时
// 原样返回。
func dingtalkSignedWebhook(webhook string, tsMillis int64, secret string) string {
	if secret == "" {
		return webhook
	}
	separator := "?"
	if strings.Contains(webhook, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%stimestamp=%d&sign=%s", webhook, separator, tsMillis, url.QueryEscape(dingtalkSignBase64(tsMillis, secret)))
}

// dingtalkSignBase64 计算钉钉加签：HmacSHA256 的 key 为 secret，消息为
// ts+"\n"+secret（ts 为毫秒时间戳），结果 base64 编码（URL 编码在拼接时完成）。
func dingtalkSignBase64(tsMillis int64, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d\n%s", tsMillis, secret)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
