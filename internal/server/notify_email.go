package server

// 邮件渠道发送器（F5）：net/smtp 投递；Subject 与发件人名用 mime.QEncoding 编码；
// 正文为 multipart/alternative（text/plain + text/html）；security 支持
// starttls（默认）/ tls（465 隐式 TLS）/ none。拨号默认复用受限拨号器
// （restrictedCallbackDialContext，SSRF 防护）；Config["allow_private"]==true 时
// 改用不限地址的普通拨号器（内网/自建 SMTP）。

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

const (
	defaultEmailPort      = 587
	emailSecurityStartTLS = "starttls"
	emailSecurityTLS      = "tls"
	emailSecurityNone     = "none"
)

// notifySMTPDialContext 是邮件渠道的拨号接缝：生产绑定受限拨号器（SSRF 防护，
// 解析后私网/环回地址拒绝），测试可替换为普通拨号器直连本地假 SMTP 服务。
var notifySMTPDialContext callbackDialContext = restrictedCallbackDialContext(defaultCallbackResolver, defaultCallbackDialer)

// notifySMTPDialContextAllowPrivate 是渠道开启“允许内网地址”后的拨号接缝：
// 不做地址判定（沿用相同的 5s 拨号超时），使内网/自建 SMTP 可达。
var notifySMTPDialContextAllowPrivate callbackDialContext = defaultCallbackDialer

type emailNotifier struct {
	host         string
	port         int
	security     string
	username     string
	password     string
	from         string
	fromName     string
	to           []string
	allowPrivate bool
}

func newEmailNotifier(ch NotifyChannel) (Notifier, error) {
	host := strings.TrimSpace(ch.Config["host"])
	if host == "" {
		return nil, errors.New("邮件服务器 host 未配置")
	}
	port := defaultEmailPort
	if raw := strings.TrimSpace(ch.Config["port"]); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("邮件服务器 port 需为 1-65535")
		}
		port = value
	}
	security := strings.ToLower(strings.TrimSpace(ch.Config["security"]))
	if security == "" {
		security = emailSecurityStartTLS
	}
	switch security {
	case emailSecurityStartTLS, emailSecurityTLS, emailSecurityNone:
	default:
		return nil, errors.New("邮件 security 需为 starttls/tls/none")
	}
	from := strings.TrimSpace(ch.Config["from"])
	if !strings.Contains(from, "@") {
		return nil, errors.New("邮件 from 未配置或无效")
	}
	recipients := splitNotifyList(ch.Config["to"])
	if len(recipients) == 0 {
		return nil, errors.New("邮件收件人 to 未配置")
	}
	for _, recipient := range recipients {
		if !strings.Contains(recipient, "@") {
			return nil, errors.New("邮件收件人 to 含无效地址")
		}
	}
	return &emailNotifier{
		host:         host,
		port:         port,
		security:     security,
		username:     strings.TrimSpace(ch.Config["username"]),
		password:     strings.TrimSpace(ch.Secrets["password"]),
		from:         from,
		fromName:     strings.TrimSpace(ch.Config["from_name"]),
		to:           recipients,
		allowPrivate: notifyChannelAllowsPrivate(ch),
	}, nil
}

func (n *emailNotifier) Send(ctx context.Context, msg NotifyMessage) error {
	subject, body := splitNotifyTitleBody(msg.Text)
	if subject == "" {
		return errors.New("邮件消息为空")
	}
	boundary, err := notifyEmailBoundary()
	if err != nil {
		return err
	}
	message := buildEmailMessage(n.from, n.fromName, n.to, subject, body, boundary)

	dial := notifySMTPDialContext
	if n.allowPrivate {
		dial = notifySMTPDialContextAllowPrivate
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(n.host, strconv.Itoa(n.port)))
	if err != nil {
		return fmt.Errorf("邮件服务器连接失败: %s", telegramRequestErrorMessage(decorateNotifyPrivateTargetError(err)))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if n.security == emailSecurityTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: n.host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("邮件 TLS 握手失败: %s", telegramRequestErrorMessage(err))
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, n.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("邮件服务器问候失败: %s", telegramRequestErrorMessage(err))
	}
	defer client.Close()
	if n.security == emailSecurityStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("邮件服务器不支持 STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: n.host}); err != nil {
			return fmt.Errorf("邮件 STARTTLS 失败: %s", telegramRequestErrorMessage(err))
		}
	}
	if n.username != "" {
		if err := client.Auth(smtp.PlainAuth("", n.username, n.password, n.host)); err != nil {
			return fmt.Errorf("邮件认证失败: %s", telegramRequestErrorMessage(err))
		}
	}
	if err := client.Mail(n.from); err != nil {
		return fmt.Errorf("邮件发件被拒绝: %s", telegramRequestErrorMessage(err))
	}
	for _, recipient := range n.to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("邮件收件被拒绝: %s", telegramRequestErrorMessage(err))
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("邮件数据通道打开失败: %s", telegramRequestErrorMessage(err))
	}
	if _, err := writer.Write(message); err != nil {
		writer.Close()
		return fmt.Errorf("邮件写入失败: %s", telegramRequestErrorMessage(err))
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("邮件提交失败: %s", telegramRequestErrorMessage(err))
	}
	// DATA 已被服务器接受（250），QUIT 失败不影响投递结果，忽略，避免重发。
	_ = client.Quit()
	return nil
}

// notifyEmailBoundary 生成随机 boundary（字母数字，header 安全）。
func notifyEmailBoundary() (string, error) {
	token, err := randomToken(24)
	if err != nil {
		return "", fmt.Errorf("生成邮件 boundary 失败: %w", err)
	}
	return "=_CyberMonitor_" + token, nil
}

// buildEmailMessage 组装邮件原文：From/To/Subject 头 + multipart/alternative
// （text/plain 与 text/html），行结尾统一 CRLF。Subject 与发件人名使用
// mime.QEncoding 编码。
func buildEmailMessage(from, fromName string, recipients []string, subject, body, boundary string) []byte {
	var buf bytes.Buffer
	writeLine := func(line string) {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
	if fromName != "" {
		writeLine(fmt.Sprintf("From: %s <%s>", mime.QEncoding.Encode("UTF-8", fromName), from))
	} else {
		writeLine("From: " + from)
	}
	writeLine("To: " + strings.Join(recipients, ", "))
	writeLine("Subject: " + mime.QEncoding.Encode("UTF-8", subject))
	writeLine("MIME-Version: 1.0")
	writeLine(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q", boundary))
	writeLine("")
	writeLine("--" + boundary)
	writeLine("Content-Type: text/plain; charset=UTF-8")
	writeLine("Content-Transfer-Encoding: 8bit")
	writeLine("")
	writeLine(strings.ReplaceAll(body, "\n", "\r\n"))
	writeLine("--" + boundary)
	writeLine("Content-Type: text/html; charset=UTF-8")
	writeLine("Content-Transfer-Encoding: 8bit")
	writeLine("")
	writeLine(notifyEmailHTML(body))
	writeLine("--" + boundary + "--")
	return buf.Bytes()
}

// notifyEmailHTML 把纯文本正文转为最简 HTML：HTML 转义 + 换行转 <br>。
func notifyEmailHTML(text string) string {
	escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)
	return `<!DOCTYPE html><html><body><div style="font-family:system-ui,-apple-system,sans-serif;white-space:pre-line;line-height:1.6">` +
		strings.ReplaceAll(escaped, "\n", "<br>") + "</div></body></html>"
}
