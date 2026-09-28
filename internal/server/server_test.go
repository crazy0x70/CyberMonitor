package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
