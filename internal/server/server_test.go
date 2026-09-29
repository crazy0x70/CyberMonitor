package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteJSONSuccess(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"status": "ok"})

	if rec.Code != http.StatusCreated {
		t.Errorf("状态码 = %d, want %d", rec.Code, http.StatusCreated)
	}
	if ct := rec.Result().Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json; charset=utf-8")
	}

	if got, want := rec.Body.String(), "{\"status\":\"ok\"}\n"; got != want {
		t.Errorf("响应体 = %q, want %q", got, want)
	}
	if !json.Valid(rec.Body.Bytes()) {
		t.Errorf("响应体不是合法 JSON: %q", rec.Body.String())
	}
}

func TestWriteJSONEncodeFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, make(chan int))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("状态码 = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if ct := rec.Result().Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json; charset=utf-8")
	}

	body := rec.Body.Bytes()
	if got, want := string(body), "{\"error\":\"encode failed\"}\n"; got != want {
		t.Errorf("失败响应体 = %q, want %q", got, want)
	}

	if !json.Valid(body) {
		t.Fatalf("响应体不是完整 JSON（半截输出）: %q", string(body))
	}
	var decoded map[string]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("响应体反序列化失败: %v (%q)", err, string(body))
	}
	if decoded["error"] == "" {
		t.Errorf("错误响应缺少 error 字段: %q", string(body))
	}
}

// 回归：WriteTimeout 是绝对写截止，若低于最慢处理器预算（公开历史查询 30s），
// 慢路径写响应时会报 i/o timeout，客户端拿到空响应（原缺陷为 10s）。
func TestHTTPServerWriteTimeoutCoversSlowestHandlerBudget(t *testing.T) {
	srv := newHTTPServer(":0", http.NotFoundHandler())
	if srv.WriteTimeout < publicHistoryQueryTimeout {
		t.Errorf("WriteTimeout = %v，必须≥最慢处理器预算（公开历史查询 %v），否则慢路径写响应会被截断", srv.WriteTimeout, publicHistoryQueryTimeout)
	}
	if srv.ReadTimeout > 15*time.Second {
		t.Errorf("ReadTimeout = %v，读侧无慢路径，不应放宽", srv.ReadTimeout)
	}
}

// 回归：读路径只做常量时间比对，不做全表重复扫描（原 O(n²) 上报周期）；
// 令牌唯一性由写路径（registerAgentAuthToken 签发前查重）保证。
func TestValidateAgentAuthTokenConstantTimeMatchOnly(t *testing.T) {
	store := &Store{profiles: map[string]*NodeProfile{
		"node-a": {AgentAuthToken: "tok"},
	}}
	if !store.validateAgentAuthToken("node-a", "tok") {
		t.Errorf("令牌匹配应通过")
	}
	if store.validateAgentAuthToken("node-a", "wrong") {
		t.Errorf("令牌不匹配必须拒绝")
	}
	if store.validateAgentAuthToken("node-a", "") {
		t.Errorf("空令牌必须拒绝")
	}
	if store.validateAgentAuthToken("node-b", "tok") {
		t.Errorf("不存在的节点必须拒绝")
	}
	empty := &Store{profiles: map[string]*NodeProfile{"node-a": {}}}
	if empty.validateAgentAuthToken("node-a", "tok") {
		t.Errorf("节点未持有令牌时必须拒绝")
	}
}

// 回归：常驻句柄 + 按大小轮转，轮转后内容从新文件开始，备份链完整。
func TestSizeLimitedWriterRotatesAndKeepsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.log")
	line := "line-0123456789abcdef\n" // 22 字节，maxSize 32：第二次写入必触发轮转
	w := &sizeLimitedWriter{path: path, maxSize: 32}

	for i := 0; i < 8; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("第 %d 次写入失败: %v", i+1, err)
		}
		if w.file == nil {
			t.Fatalf("第 %d 次写入后句柄不应为空（应常驻复用）", i+1)
		}
	}
	if w.size != int64(len(line)) {
		t.Errorf("轮转后当前大小 = %d, want %d", w.size, len(line))
	}

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读当前日志失败: %v", err)
	}
	if string(cur) != line {
		t.Errorf("当前日志 = %q, want %q（轮转后应从新文件开始）", cur, line)
	}
	for idx := 1; idx <= maxLogBackupCount; idx++ {
		backup, err := os.ReadFile(fmt.Sprintf("%s.%d", path, idx))
		if err != nil {
			t.Fatalf("读备份 %s.%d 失败: %v", path, idx, err)
		}
		if string(backup) != line {
			t.Errorf("备份 %s.%d = %q, want %q", path, idx, backup, line)
		}
	}
}
