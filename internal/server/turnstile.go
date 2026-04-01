package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func turnstileConfigured(siteKey, secretKey string) bool {
	return strings.TrimSpace(siteKey) != "" && strings.TrimSpace(secretKey) != ""
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func verifyTurnstileToken(ctx context.Context, secretKey, token, remoteIP string) error {
	secretKey = strings.TrimSpace(secretKey)
	token = strings.TrimSpace(token)
	if secretKey == "" {
		return nil
	}
	if token == "" {
		return errors.New("请先完成人机验证")
	}

	form := url.Values{}
	form.Set("secret", secretKey)
	form.Set("response", token)
	if strings.TrimSpace(remoteIP) != "" {
		form.Set("remoteip", strings.TrimSpace(remoteIP))
	}

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("Turnstile 校验请求创建失败")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.New("Turnstile 校验失败，请稍后重试")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Turnstile 校验失败：%s", resp.Status)
	}

	var payload turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return errors.New("Turnstile 校验响应无效")
	}
	if !payload.Success {
		if len(payload.ErrorCodes) > 0 {
			return fmt.Errorf("Turnstile 校验未通过：%s", strings.Join(payload.ErrorCodes, ", "))
		}
		return errors.New("Turnstile 校验未通过")
	}
	return nil
}
