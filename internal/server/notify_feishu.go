package server

// feishu 渠道发送器（F5）：POST {"msg_type":"text","content":{"text":…}}；
// 配置了 sign_secret 时按文档签名——ts（秒）；HmacSHA256(key = ts+"\n"+secret,
// msg = 空) 后 base64，body 中加入 timestamp 和 sign；成功条件 code==0。
// 发送默认走 SSRF 防护客户端（notifySendHTTP），不跟随重定向；
// Config["allow_private"]==true 时改用 allow-private 客户端。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type feishuNotifier struct {
	webhook      string
	signSecret   string
	allowPrivate bool
}

func newFeishuNotifier(ch NotifyChannel) (Notifier, error) {
	webhook := strings.TrimSpace(ch.Secrets["webhook"])
	if webhook == "" {
		return nil, errors.New("feishu webhook 未配置")
	}
	if err := notifyValidateChannelURL(ch, webhook); err != nil {
		return nil, err
	}
	return &feishuNotifier{
		webhook:      webhook,
		signSecret:   strings.TrimSpace(ch.Secrets["sign_secret"]),
		allowPrivate: notifyChannelAllowsPrivate(ch),
	}, nil
}

func (n *feishuNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return errors.New("feishu 消息为空")
	}
	payload := map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": text},
	}
	if n.signSecret != "" {
		ts := time.Now().Unix()
		payload["timestamp"] = strconv.FormatInt(ts, 10)
		payload["sign"] = feishuSignBase64(ts, n.signSecret)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("告警消息编码失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhook, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("告警请求创建失败: %s", telegramRequestErrorMessage(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := notifySendHTTPFor(n.allowPrivate, req)
	if err != nil {
		return fmt.Errorf("告警发送失败: %s", telegramRequestErrorMessage(err))
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var feishuResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &feishuResp); err != nil {
		log.Printf("飞书 webhook 响应非 JSON: %.120s", strings.TrimSpace(string(body)))
		return errors.New("飞书响应非 JSON，投递结果未知")
	}
	if feishuResp.Code != 0 {
		return fmt.Errorf("飞书返回错误 code=%d: %s", feishuResp.Code, strings.TrimSpace(feishuResp.Msg))
	}
	return nil
}

// feishuSignBase64 计算飞书自定义机器人签名：HmacSHA256 的 key 为 ts+"\n"+secret，
// 消息为空，结果 base64 编码。ts 为秒级时间戳。
func feishuSignBase64(ts int64, secret string) string {
	mac := hmac.New(sha256.New, []byte(fmt.Sprintf("%d\n%s", ts, secret)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
