package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResolveAIProviderSelection(t *testing.T) {
	saved := AIProviderConfig{APIKey: "saved-key", BaseURL: "https://saved.example/v1", Model: "saved-model"}
	replacement := AIProviderConfig{APIKey: "new-key", BaseURL: "https://new.example/v1", Model: "new-model"}
	settings := AISettings{CommandProvider: "openai_compatible:saved", OpenAI: saved, OpenAICompatibles: []AIProviderProfile{{ID: "saved", Name: "Saved provider", AIProviderConfig: saved}}}
	tests := []struct {
		name        string
		settings    AISettings
		selector    string
		override    *AIProviderConfig
		want        AIProviderConfig
		label       string
		errContains string
	}{
		{name: "first unsaved provider", selector: aiProviderOpenAICompatible, override: &replacement, want: replacement, label: "OpenAI 兼容提供商"},
		{name: "empty unsaved override", selector: aiProviderOpenAICompatible, override: &AIProviderConfig{}, errContains: "API Key 未配置"},
		{name: "temporary selection ignores saved label", settings: settings, selector: aiProviderOpenAICompatible, override: &replacement, want: replacement, label: "OpenAI 兼容提供商"},
		{name: "unknown ID with override", settings: settings, selector: "openai_compatible:missing", override: &replacement, errContains: "未找到指定"},
		{name: "unknown ID without override", settings: settings, selector: "openai_compatible:missing", errContains: "未找到指定"},
		{name: "saved first without override", settings: settings, selector: aiProviderOpenAICompatible, want: saved, label: "Saved provider"},
		{name: "saved ID without override", settings: settings, selector: "openai_compatible:saved", want: saved, label: "Saved provider"},
		{name: "default selector", settings: settings, want: saved, label: "Saved provider"},
		{name: "saved ID replacement", settings: settings, selector: "openai_compatible:saved", override: &replacement, want: replacement, label: "Saved provider"},
		{name: "no key backfill", settings: settings, selector: "openai_compatible:saved", override: &AIProviderConfig{BaseURL: replacement.BaseURL, Model: replacement.Model}, errContains: "API Key 未配置"},
		{name: "no URL backfill", settings: settings, selector: "openai_compatible:saved", override: &AIProviderConfig{APIKey: replacement.APIKey, Model: replacement.Model}, errContains: "Base URL"},
		{name: "no model backfill", settings: settings, selector: "openai_compatible:saved", override: &AIProviderConfig{APIKey: replacement.APIKey, BaseURL: replacement.BaseURL}, errContains: "模型"},
		{name: "missing saved config", selector: aiProviderOpenAICompatible, errContains: "未配置 OpenAI 兼容"},
		{name: "OpenAI saved", settings: settings, selector: aiProviderOpenAI, want: saved, label: "OpenAI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := json.Marshal(tt.settings)
			overrideBefore, _ := json.Marshal(tt.override)
			got, err := resolveAIProviderSelection(tt.settings, tt.selector, tt.override)
			after, _ := json.Marshal(tt.settings)
			overrideAfter, _ := json.Marshal(tt.override)
			if string(before) != string(after) || string(overrideBefore) != string(overrideAfter) {
				t.Fatal("resolution mutated input")
			}
			if tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error = %v; want %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Config != tt.want || got.Label != tt.label {
				t.Fatalf("selection = %+v; want config %+v, label %q", got, tt.want, tt.label)
			}
			provider := aiProviderOpenAICompatible
			if tt.selector == aiProviderOpenAI {
				provider = aiProviderOpenAI
			}
			if got.Provider != provider {
				t.Fatalf("provider = %q; want %q", got.Provider, provider)
			}
		})
	}
}

func TestAIProviderRejectsRedirects(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(fmt.Sprintf("%s/%d", method, status), func(t *testing.T) {
				var targetCalls atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					targetCalls.Add(1)
					t.Errorf("redirect target received %s with Authorization=%q", r.Method, r.Header.Get("Authorization"))
					_, _ = io.WriteString(w, `{"data":[{"id":"test-model"}],"choices":[{"message":{"content":"ok"}}]}`)
				}))
				defer target.Close()
				var sourceCalls atomic.Int32
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sourceCalls.Add(1)
					if r.Method != method || r.Header.Get("Authorization") != "Bearer fixture-key" {
						t.Errorf("source method/header = %s/%q", r.Method, r.Header.Get("Authorization"))
					}
					wantPath := "/v1/models"
					if method == http.MethodPost {
						wantPath = "/v1/chat/completions"
					}
					if r.URL.Path != wantPath {
						t.Errorf("path = %q; want %q", r.URL.Path, wantPath)
					}
					w.Header().Set("Location", target.URL+"/redirected")
					w.WriteHeader(status)
				}))
				defer source.Close()
				cfg := AIProviderConfig{APIKey: "fixture-key", BaseURL: source.URL + "/v1", Model: "test-model"}
				var err error
				if method == http.MethodGet {
					_, err = listAIModels(context.Background(), aiProviderOpenAICompatible, cfg)
				} else {
					_, err = callOpenAICompatible(context.Background(), cfg, "system", "user")
				}
				if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
					t.Errorf("error = %v; want status %d", err, status)
				}
				if sourceCalls.Load() != 1 || targetCalls.Load() != 0 {
					t.Errorf("source/target calls = %d/%d; want 1/0", sourceCalls.Load(), targetCalls.Load())
				}
			})
		}
	}
}

func TestAIProviderDirectRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-key" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/models":
			if r.Method != http.MethodGet {
				t.Errorf("method = %s", r.Method)
			}
			_, _ = io.WriteString(w, `{"data":[{"id":"test-model"}]}`)
		case "/v1/chat/completions":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("method/content-type = %s/%s", r.Method, r.Header.Get("Content-Type"))
			}
			var body struct {
				Model    string `json:"model"`
				Messages []struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"messages"`
				Temperature float64 `json:"temperature"`
				MaxTokens   int     `json:"max_tokens"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if body.Model != "test-model" || body.Temperature != defaultAITemperature || body.MaxTokens != defaultAIMaxOutputTokens || len(body.Messages) != 2 {
				t.Errorf("request body = %+v", body)
			} else if body.Messages[0].Role != "system" || body.Messages[0].Content != "system prompt" || body.Messages[1].Role != "user" || body.Messages[1].Content != "user prompt" {
				t.Errorf("messages = %+v", body.Messages)
			}
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"direct answer"}}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := AIProviderConfig{APIKey: "fixture-key", BaseURL: srv.URL + "/v1", Model: "test-model"}
	models, err := listAIModels(context.Background(), aiProviderOpenAICompatible, cfg)
	if err != nil || len(models) != 1 || models[0] != "test-model" {
		t.Fatalf("models = %v, error = %v", models, err)
	}
	answer, err := callOpenAICompatible(context.Background(), cfg, "system prompt", "user prompt")
	if err != nil || answer != "direct answer" {
		t.Fatalf("answer = %q, error = %v", answer, err)
	}
}
