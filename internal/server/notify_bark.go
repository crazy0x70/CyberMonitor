package server

// bark 渠道发送器（F5）：POST {server_url}/push，JSON 载荷
// {device_key,title,body,group,level,sound,icon}；成功条件响应 code==200。
// 默认 server_url https://api.day.app、group「CyberMonitor」、level
// timeSensitive。发送走 SSRF 防护客户端（notifySendHTTP），不跟随重定向。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	defaultBarkServerURL = "https://api.day.app"
	defaultBarkGroup     = "CyberMonitor"
	defaultBarkLevel     = "timeSensitive"
)

// barkLevels 是文档定稿的 level 取值白名单（Bark 通知打断级别）。
var barkLevels = map[string]struct{}{
	"active":        {},
	"timeSensitive": {},
	"passive":       {},
	"critical":      {},
}

type barkNotifier struct {
	endpoint  string
	deviceKey string
	group     string
	level     string
	sound     string
	icon      string
}

func newBarkNotifier(ch NotifyChannel) (Notifier, error) {
	deviceKey := strings.TrimSpace(ch.Secrets["device_key"])
	if deviceKey == "" {
		return nil, errors.New("bark device_key 未配置")
	}
	serverURL := strings.TrimSpace(ch.Config["server_url"])
	if serverURL == "" {
		serverURL = defaultBarkServerURL
	}
	if err := notifyValidateWebhookURL(serverURL); err != nil {
		return nil, err
	}
	group := strings.TrimSpace(ch.Config["group"])
	if group == "" {
		group = defaultBarkGroup
	}
	level := strings.TrimSpace(ch.Config["level"])
	if level == "" {
		level = defaultBarkLevel
	}
	if _, ok := barkLevels[level]; !ok {
		return nil, errors.New("bark level 需为 active/timeSensitive/passive/critical")
	}
	return &barkNotifier{
		endpoint:  strings.TrimRight(serverURL, "/") + "/push",
		deviceKey: deviceKey,
		group:     group,
		level:     level,
		sound:     strings.TrimSpace(ch.Config["sound"]),
		icon:      strings.TrimSpace(ch.Config["icon"]),
	}, nil
}

func (n *barkNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	title, body := splitNotifyTitleBody(msg.Text)
	if title == "" {
		return errors.New("bark 消息为空")
	}
	payload := map[string]any{
		"device_key": n.deviceKey,
		"title":      title,
		"body":       body,
		"group":      n.group,
		"level":      n.level,
	}
	if n.sound != "" {
		payload["sound"] = n.sound
	}
	if n.icon != "" {
		payload["icon"] = n.icon
	}
	_, respBody, err := postNotifyJSON(ctx, n.endpoint, payload)
	if err != nil {
		return err
	}
	var barkResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBody, &barkResp); err != nil {
		return errors.New("bark 响应非 JSON，投递结果未知")
	}
	if barkResp.Code != http.StatusOK {
		return fmt.Errorf("bark 返回错误 code=%d: %s", barkResp.Code, strings.TrimSpace(barkResp.Message))
	}
	return nil
}
