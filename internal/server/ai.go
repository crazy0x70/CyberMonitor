package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"
)

const (
	aiProviderOpenAI            = "openai"
	aiProviderGemini            = "gemini"
	aiProviderVolcengine        = "volcengine"
	aiProviderOpenAICompatible  = "openai_compatible"
	defaultOpenAIBaseURL        = "https://api.openai.com/v1"
	defaultOpenAIModel          = "gpt-5.2"
	defaultGeminiBaseURL        = "https://generativelanguage.googleapis.com/v1beta"
	defaultGeminiModel          = "gemini-2.5-flash"
	defaultVolcengineBaseURL    = "https://ark.cn-beijing.volces.com/api/v3"
	defaultVolcengineModel      = "doubao-seed-1-6-flash"
	defaultAIMaxOutputTokens    = 512
	defaultAITemperature        = 0.2
	defaultAITestPrompt         = "请仅回复 ok"
	maxTelegramMessageRunes     = 3500
	maxAIPromptRunes            = 2000
	maxHTTPErrorBodyBytes       = 4096
	aiOfflineRecentSessionLimit = 3
)

func readResponseBodyLimited(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(body, maxHTTPErrorBodyBytes))
}

type AIProviderConfig struct {
	APIKey  string `json:"api_key,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
	Model   string `json:"model,omitempty"`
}

type AISettings struct {
	DefaultProvider   string              `json:"default_provider,omitempty"`
	CommandProvider   string              `json:"command_provider,omitempty"`
	Prompt            string              `json:"prompt,omitempty"`
	OpenAI            AIProviderConfig    `json:"openai,omitempty"`
	Gemini            AIProviderConfig    `json:"gemini,omitempty"`
	Volcengine        AIProviderConfig    `json:"volcengine,omitempty"`
	OpenAICompatible  AIProviderConfig    `json:"openai_compatible,omitempty"`
	OpenAICompatibles []AIProviderProfile `json:"openai_compatibles,omitempty"`
}

type AIProviderProfile struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	AIProviderConfig
}

type aiProviderSelection struct {
	Provider string
	Label    string
	Config   AIProviderConfig
}

type aiSnapshot struct {
	GeneratedAt string            `json:"generated_at"`
	Servers     []aiServerSummary `json:"servers"`
}

type aiServerSummary struct {
	ServerID          string                 `json:"server_id"`
	DisplayName       string                 `json:"display_name"`
	Hostname          string                 `json:"hostname,omitempty"`
	Status            string                 `json:"status"`
	Group             string                 `json:"group,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	Groups            []string               `json:"groups,omitempty"`
	Region            string                 `json:"region,omitempty"`
	OS                string                 `json:"os,omitempty"`
	Arch              string                 `json:"arch,omitempty"`
	AgentVersion      string                 `json:"agent_version,omitempty"`
	CPUUsage          float64                `json:"cpu_usage_percent"`
	MemUsage          float64                `json:"mem_usage_percent"`
	DiskUsed          float64                `json:"disk_used_percent,omitempty"`
	DiskType          string                 `json:"disk_type,omitempty"`
	NetSpeedMbps      float64                `json:"net_speed_mbps,omitempty"`
	NetRecvBytes      uint64                 `json:"net_recv_bytes"`
	NetSendBytes      uint64                 `json:"net_send_bytes"`
	RxBytesPerSec     float64                `json:"rx_bytes_per_sec"`
	TxBytesPerSec     float64                `json:"tx_bytes_per_sec"`
	ProcessCount      int                    `json:"process_count,omitempty"`
	TCPConns          int                    `json:"tcp_conns,omitempty"`
	UDPConns          int                    `json:"udp_conns,omitempty"`
	UptimeSec         uint64                 `json:"uptime_sec"`
	LastSeen          int64                  `json:"last_seen"`
	FirstSeen         int64                  `json:"first_seen"`
	ExpireAt          int64                  `json:"expire_at,omitempty"`
	RenewIntervalSec  int64                  `json:"renew_interval_sec,omitempty"`
	AlertEnabled      bool                   `json:"alert_enabled"`
	OfflineSummary    *aiOfflineSummary      `json:"offline_summary,omitempty"`
	NetworkTests      []aiNetworkTestSummary `json:"network_tests,omitempty"`
	NetworkTestTrends []aiNetworkTrend       `json:"network_test_trends,omitempty"`
}

type aiOfflineSummary struct {
	TotalCount             int                      `json:"total_count"`
	Last30dCount           int                      `json:"last_30d_count"`
	LongestDurationSec     float64                  `json:"longest_duration_sec"`
	AvgDurationSec         float64                  `json:"avg_duration_sec"`
	LastOfflineRecoveredAt int64                    `json:"last_offline_recovered_at,omitempty"`
	RecentSessions         []aiOfflineRecentSession `json:"recent_sessions,omitempty"`
}

type aiOfflineRecentSession struct {
	StartedAt   int64   `json:"started_at,omitempty"`
	RecoveredAt int64   `json:"recovered_at,omitempty"`
	DurationSec float64 `json:"duration_sec"`
}

type aiNetworkTestSummary struct {
	Name       string   `json:"name,omitempty"`
	Type       string   `json:"type"`
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	Status     string   `json:"status,omitempty"`
	Error      string   `json:"error,omitempty"`
	CheckedAt  int64    `json:"checked_at,omitempty"`
	LatencyMs  *float64 `json:"latency_ms,omitempty"`
	PacketLoss float64  `json:"packet_loss"`
}

type aiNetworkTrend struct {
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	Samples         int      `json:"samples"`
	WindowStart     int64    `json:"window_start,omitempty"`
	WindowEnd       int64    `json:"window_end,omitempty"`
	LatestCheckedAt int64    `json:"latest_checked_at,omitempty"`
	LatestLatencyMs *float64 `json:"latest_latency_ms,omitempty"`
	LatestLoss      *float64 `json:"latest_loss,omitempty"`
	AvgLatencyMs    *float64 `json:"avg_latency_ms,omitempty"`
	MaxLatencyMs    *float64 `json:"max_latency_ms,omitempty"`
	AvgLoss         *float64 `json:"avg_loss,omitempty"`
	MinIntervalSec  int64    `json:"min_interval_sec,omitempty"`
	AvgIntervalSec  float64  `json:"avg_interval_sec,omitempty"`
	StatusHint      string   `json:"status_hint,omitempty"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type openAIModelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type geminiModelsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func defaultAISettings() AISettings {
	return AISettings{
		DefaultProvider: aiProviderOpenAI,
		CommandProvider: "",
		Prompt:          "",
		OpenAI: AIProviderConfig{
			BaseURL: defaultOpenAIBaseURL,
			Model:   defaultOpenAIModel,
		},
		Gemini: AIProviderConfig{
			BaseURL: defaultGeminiBaseURL,
			Model:   defaultGeminiModel,
		},
		Volcengine: AIProviderConfig{
			BaseURL: defaultVolcengineBaseURL,
			Model:   defaultVolcengineModel,
		},
		OpenAICompatible:  AIProviderConfig{},
		OpenAICompatibles: []AIProviderProfile{},
	}
}

func mergeAISettings(existing, fallback AISettings) AISettings {
	existing = normalizeAISettings(existing)
	fallback = normalizeAISettings(fallback)
	if existing.DefaultProvider == "" {
		existing.DefaultProvider = fallback.DefaultProvider
	}
	if existing.CommandProvider == "" {
		existing.CommandProvider = fallback.CommandProvider
	}
	if existing.Prompt == "" {
		existing.Prompt = fallback.Prompt
	}
	existing.OpenAI = mergeAIProviderConfig(existing.OpenAI, fallback.OpenAI)
	existing.Gemini = mergeAIProviderConfig(existing.Gemini, fallback.Gemini)
	existing.Volcengine = mergeAIProviderConfig(existing.Volcengine, fallback.Volcengine)
	existing.OpenAICompatible = mergeAIProviderConfig(existing.OpenAICompatible, fallback.OpenAICompatible)
	if len(existing.OpenAICompatibles) == 0 {
		existing.OpenAICompatibles = fallback.OpenAICompatibles
	}
	existing.OpenAICompatibles = normalizeAICompatibles(existing.OpenAICompatibles)
	return existing
}

func mergeAIProviderConfig(existing, fallback AIProviderConfig) AIProviderConfig {
	if strings.TrimSpace(existing.APIKey) == "" {
		existing.APIKey = fallback.APIKey
	}
	if strings.TrimSpace(existing.BaseURL) == "" {
		existing.BaseURL = fallback.BaseURL
	}
	if strings.TrimSpace(existing.Model) == "" {
		existing.Model = fallback.Model
	}
	return normalizeAIProviderConfig(existing)
}

func normalizeAISettings(settings AISettings) AISettings {
	settings.DefaultProvider = normalizeAIProviderName(settings.DefaultProvider)
	if settings.DefaultProvider == "" {
		settings.DefaultProvider = aiProviderOpenAI
	}
	settings.CommandProvider = normalizeAIProviderSelector(settings.CommandProvider)
	settings.Prompt = normalizeAIPrompt(settings.Prompt)
	settings.OpenAI = normalizeAIProviderConfig(settings.OpenAI)
	settings.Gemini = normalizeAIProviderConfig(settings.Gemini)
	settings.Volcengine = normalizeAIProviderConfig(settings.Volcengine)
	settings.OpenAICompatible = normalizeAIProviderConfig(settings.OpenAICompatible)
	settings.OpenAICompatibles = normalizeAICompatibles(settings.OpenAICompatibles)
	if len(settings.OpenAICompatibles) == 0 && hasLegacyCompat(settings.OpenAICompatible) {
		settings.OpenAICompatibles = normalizeAICompatibles([]AIProviderProfile{
			{
				ID:               "compat-legacy",
				Name:             "OpenAI 兼容",
				AIProviderConfig: settings.OpenAICompatible,
			},
		})
	}
	return settings
}

func normalizeAIProviderName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case aiProviderOpenAI, "open_ai":
		return aiProviderOpenAI
	case aiProviderGemini:
		return aiProviderGemini
	case aiProviderVolcengine, "volc", "ark":
		return aiProviderVolcengine
	case aiProviderOpenAICompatible, "openai-compatible", "openai_compat":
		return aiProviderOpenAICompatible
	default:
		return ""
	}
}

func normalizeAIProviderSelector(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, aiProviderOpenAICompatible+":") {
		id := strings.TrimSpace(strings.TrimPrefix(trimmed, aiProviderOpenAICompatible+":"))
		if id == "" {
			return aiProviderOpenAICompatible
		}
		return fmt.Sprintf("%s:%s", aiProviderOpenAICompatible, id)
	}
	return normalizeAIProviderName(trimmed)
}

func normalizeAICompatibles(items []AIProviderProfile) []AIProviderProfile {
	seen := make(map[string]struct{})
	normalized := make([]AIProviderProfile, 0, len(items))
	for _, item := range items {
		item.ID = strings.TrimSpace(item.ID)
		item.Name = strings.TrimSpace(item.Name)
		item.AIProviderConfig = normalizeAIProviderConfig(item.AIProviderConfig)
		if item.Name == "" && item.APIKey == "" && item.BaseURL == "" && item.Model == "" {
			continue
		}
		if item.ID == "" {
			item.ID = randomToken(8)
		}
		if _, ok := seen[item.ID]; ok {
			item.ID = randomToken(8)
		}
		seen[item.ID] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func hasLegacyCompat(cfg AIProviderConfig) bool {
	return strings.TrimSpace(cfg.APIKey) != "" || strings.TrimSpace(cfg.BaseURL) != "" || strings.TrimSpace(cfg.Model) != ""
}

func normalizeAIProviderConfig(cfg AIProviderConfig) AIProviderConfig {
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Model = strings.TrimSpace(cfg.Model)
	return cfg
}

func validateAIBaseURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return errors.New("AI base url 无效")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("AI base url 需为 http 或 https")
	}
	return nil
}

func validateAISettings(settings AISettings) error {
	configs := []AIProviderConfig{
		settings.OpenAI,
		settings.Gemini,
		settings.Volcengine,
		settings.OpenAICompatible,
	}
	for _, cfg := range configs {
		if err := validateAIBaseURL(cfg.BaseURL); err != nil {
			return err
		}
	}
	if err := validateAICompatibles(settings.OpenAICompatibles); err != nil {
		return err
	}
	if err := validateAIPrompt(settings.Prompt); err != nil {
		return err
	}
	return nil
}

func validateAICompatibles(items []AIProviderProfile) error {
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return errors.New("OpenAI 兼容服务商名称不能为空")
		}
		if err := validateAIBaseURL(item.BaseURL); err != nil {
			return fmt.Errorf("OpenAI 兼容服务商 %s: %w", name, err)
		}
	}
	return nil
}

func normalizeAIPrompt(value string) string {
	value = strings.TrimSpace(value)
	return value
}

func validateAIPrompt(value string) error {
	if value == "" {
		return nil
	}
	if len([]rune(value)) > maxAIPromptRunes {
		return fmt.Errorf("AI Prompt 过长，最多 %d 字符", maxAIPromptRunes)
	}
	return nil
}

func applyAIProviderDefaults(provider string, cfg AIProviderConfig) AIProviderConfig {
	cfg = normalizeAIProviderConfig(cfg)
	switch provider {
	case aiProviderOpenAI:
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultOpenAIBaseURL
		}
		if cfg.Model == "" {
			cfg.Model = defaultOpenAIModel
		}
	case aiProviderGemini:
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultGeminiBaseURL
		}
		if cfg.Model == "" {
			cfg.Model = defaultGeminiModel
		}
	case aiProviderVolcengine:
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultVolcengineBaseURL
		}
		if cfg.Model == "" {
			cfg.Model = defaultVolcengineModel
		}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg
}

func selectAIProviderConfig(settings AISettings, provider string) (aiProviderSelection, error) {
	normalized := normalizeAIProviderName(provider)
	switch normalized {
	case aiProviderOpenAI:
		return aiProviderSelection{Provider: normalized, Label: "OpenAI", Config: settings.OpenAI}, nil
	case aiProviderGemini:
		return aiProviderSelection{Provider: normalized, Label: "Gemini", Config: settings.Gemini}, nil
	case aiProviderVolcengine:
		return aiProviderSelection{Provider: normalized, Label: "Volcengine", Config: settings.Volcengine}, nil
	case aiProviderOpenAICompatible:
		return aiProviderSelection{Provider: normalized, Label: "OpenAI 兼容提供商", Config: settings.OpenAICompatible}, nil
	default:
		return aiProviderSelection{}, errors.New("AI 提供商无效")
	}
}

func resolveAIProviderConfigBySelector(settings AISettings, selector string) (aiProviderSelection, error) {
	selector = normalizeAIProviderSelector(selector)
	if selector == "" {
		selector = settings.DefaultProvider
	}
	provider, providerID := parseAIProviderSelector(selector)
	if provider == aiProviderOpenAICompatible {
		if providerID != "" {
			if selection, ok := findAICompatibleProvider(settings, providerID); ok {
				return resolveAICompatibleSelection(selection)
			}
			return aiProviderSelection{}, errors.New("未找到指定的兼容服务商")
		}
		if len(settings.OpenAICompatibles) > 0 {
			return resolveAICompatibleSelection(settings.OpenAICompatibles[0])
		}
		if hasLegacyCompat(settings.OpenAICompatible) {
			return resolveAICompatibleSelection(AIProviderProfile{
				ID:               "compat-legacy",
				Name:             "OpenAI 兼容",
				AIProviderConfig: settings.OpenAICompatible,
			})
		}
		return aiProviderSelection{}, errors.New("未配置 OpenAI 兼容服务商")
	}
	return resolveAIProviderConfig(settings, provider)
}

func parseAIProviderSelector(selector string) (string, string) {
	if strings.HasPrefix(selector, aiProviderOpenAICompatible+":") {
		return aiProviderOpenAICompatible, strings.TrimSpace(strings.TrimPrefix(selector, aiProviderOpenAICompatible+":"))
	}
	return normalizeAIProviderName(selector), ""
}

func findAICompatibleProvider(settings AISettings, providerID string) (AIProviderProfile, bool) {
	for _, item := range settings.OpenAICompatibles {
		if item.ID == providerID {
			return item, true
		}
	}
	return AIProviderProfile{}, false
}

func resolveAICompatibleSelection(provider AIProviderProfile) (aiProviderSelection, error) {
	label := strings.TrimSpace(provider.Name)
	if label == "" {
		label = "OpenAI 兼容提供商"
	}
	selection := aiProviderSelection{
		Provider: aiProviderOpenAICompatible,
		Label:    label,
		Config:   provider.AIProviderConfig,
	}
	selection.Config = applyAIProviderDefaults(selection.Provider, selection.Config)
	if err := validateAIBaseURL(selection.Config.BaseURL); err != nil {
		return aiProviderSelection{}, err
	}
	if selection.Config.APIKey == "" {
		return aiProviderSelection{}, fmt.Errorf("%s API Key 未配置", selection.Label)
	}
	if selection.Config.BaseURL == "" {
		return aiProviderSelection{}, errors.New("OpenAI 兼容服务商需填写 Base URL")
	}
	if selection.Config.Model == "" {
		return aiProviderSelection{}, errors.New("OpenAI 兼容服务商需填写模型")
	}
	return selection, nil
}

func resolveAIProviderConfig(settings AISettings, provider string) (aiProviderSelection, error) {
	selection, err := selectAIProviderConfig(settings, provider)
	if err != nil {
		return aiProviderSelection{}, err
	}
	selection.Config = applyAIProviderDefaults(selection.Provider, selection.Config)
	if err := validateAIBaseURL(selection.Config.BaseURL); err != nil {
		return aiProviderSelection{}, err
	}
	if selection.Config.APIKey == "" {
		return aiProviderSelection{}, fmt.Errorf("%s API Key 未配置", selection.Label)
	}
	if selection.Provider == aiProviderOpenAICompatible {
		if selection.Config.BaseURL == "" {
			return aiProviderSelection{}, errors.New("OpenAI 兼容提供商需填写 Base URL")
		}
		if selection.Config.Model == "" {
			return aiProviderSelection{}, errors.New("OpenAI 兼容提供商需填写模型")
		}
	}
	return selection, nil
}

func resolveAIProviderConfigWithOverride(settings AISettings, provider string, override AIProviderConfig) (aiProviderSelection, error) {
	selection, err := selectAIProviderConfig(settings, provider)
	if err != nil {
		return aiProviderSelection{}, err
	}
	base := normalizeAIProviderConfig(selection.Config)
	override = normalizeAIProviderConfig(override)
	if override.APIKey != "" {
		base.APIKey = override.APIKey
	}
	if override.BaseURL != "" {
		base.BaseURL = override.BaseURL
	}
	if override.Model != "" {
		base.Model = override.Model
	}
	selection.Config = applyAIProviderDefaults(selection.Provider, base)
	if err := validateAIBaseURL(selection.Config.BaseURL); err != nil {
		return aiProviderSelection{}, err
	}
	if selection.Config.APIKey == "" {
		return aiProviderSelection{}, fmt.Errorf("%s API Key 未配置", selection.Label)
	}
	if selection.Provider == aiProviderOpenAICompatible {
		if selection.Config.BaseURL == "" {
			return aiProviderSelection{}, errors.New("OpenAI 兼容提供商需填写 Base URL")
		}
		if selection.Config.Model == "" {
			return aiProviderSelection{}, errors.New("OpenAI 兼容提供商需填写模型")
		}
	}
	return selection, nil
}

func (s *Store) AISettings() AISettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeAISettings(s.settings.AISettings)
}

func runAIQuery(ctx context.Context, store *Store, question string) (string, error) {
	settings := store.AISettings()
	provider := settings.CommandProvider
	if provider == "" {
		provider = settings.DefaultProvider
	}
	selection, err := resolveAIProviderConfigBySelector(settings, provider)
	if err != nil {
		return "", err
	}
	systemPrompt := buildAISystemPrompt(settings.Prompt)
	userPrompt, err := buildAIUserPrompt(store, question)
	if err != nil {
		return "", err
	}
	answer, err := callAIProvider(ctx, selection.Provider, selection.Config, systemPrompt, userPrompt)
	if err != nil {
		return "", err
	}
	return trimTelegramMessage(answer), nil
}

func testAIProvider(ctx context.Context, provider string, config AIProviderConfig) error {
	systemPrompt := "你是 CyberMonitor 的 API 测试助手"
	userPrompt := defaultAITestPrompt
	_, err := callAIProvider(ctx, provider, config, systemPrompt, userPrompt)
	return err
}

func listAIModels(ctx context.Context, provider string, config AIProviderConfig) ([]string, error) {
	switch provider {
	case aiProviderGemini:
		return listGeminiModels(ctx, config)
	case aiProviderOpenAI, aiProviderVolcengine, aiProviderOpenAICompatible:
		return listOpenAIModels(ctx, config)
	default:
		return nil, errors.New("AI 提供商无效")
	}
}

func listOpenAIModels(ctx context.Context, config AIProviderConfig) ([]string, error) {
	if config.APIKey == "" {
		return nil, errors.New("API Key 不能为空")
	}
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if baseURL == "" {
		return nil, errors.New("Base URL 不能为空")
	}
	endpoint := fmt.Sprintf("%s/models", baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.APIKey))
	client := &http.Client{Timeout: 18 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AI 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed openAIModelsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("AI 响应解析失败: %w", err)
	}
	if parsed.Error != nil {
		return nil, errors.New(parsed.Error.Message)
	}
	seen := make(map[string]struct{})
	models := make([]string, 0, len(parsed.Data))
	for _, item := range parsed.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, id)
	}
	return models, nil
}

func listGeminiModels(ctx context.Context, config AIProviderConfig) ([]string, error) {
	if config.APIKey == "" {
		return nil, errors.New("API Key 不能为空")
	}
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if baseURL == "" {
		return nil, errors.New("Base URL 不能为空")
	}
	endpoint := fmt.Sprintf("%s/models?key=%s", baseURL, url.QueryEscape(config.APIKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 18 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AI 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed geminiModelsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("AI 响应解析失败: %w", err)
	}
	if parsed.Error != nil {
		return nil, errors.New(parsed.Error.Message)
	}
	seen := make(map[string]struct{})
	models := make([]string, 0, len(parsed.Models))
	for _, item := range parsed.Models {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		name = strings.TrimPrefix(name, "models/")
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		models = append(models, name)
	}
	return models, nil
}

func buildAISystemPrompt(custom string) string {
	lines := []string{
		"你是 CyberMonitor 的 AI 运维助手。",
		"只能基于给定的数据回答问题，不要编造不存在的信息。",
		"如果数据不足以回答，请直接说明原因。",
		"回答简洁，必要时给出服务器名称和 ID，并指出关键指标依据。",
	}
	if strings.TrimSpace(custom) != "" {
		lines = append(lines, fmt.Sprintf("管理员提示: %s", strings.TrimSpace(custom)))
	}
	return strings.Join(lines, "\n")
}

func buildAIUserPrompt(store *Store, question string) (string, error) {
	snapshot := buildAISnapshot(store)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("问题: %s\n数据(JSON): %s", question, payload), nil
}

func buildAISnapshot(store *Store) aiSnapshot {
	snapshotTime := time.Now().UTC()
	nodes := store.Snapshot()
	history := store.snapshotTestHistory()
	offlineStore := resolveAIOfflineStore(store)
	servers := make([]aiServerSummary, 0, len(nodes))
	for _, node := range nodes {
		stats := node.Stats
		diskUsed := 0.0
		for _, disk := range stats.Disk {
			if disk.UsedPercent > diskUsed {
				diskUsed = disk.UsedPercent
			}
		}
		name := resolveNodeDisplayNameForAI(node)
		offlineSummary := buildAIOfflineSummary(offlineStore, stats.NodeID, snapshotTime)
		hostName := strings.TrimSpace(stats.Hostname)
		if hostName == "" {
			hostName = strings.TrimSpace(stats.NodeName)
		}
		if hostName == "" {
			hostName = strings.TrimSpace(stats.NodeID)
		}
		group := strings.TrimSpace(node.Group)
		tags := append([]string{}, node.Tags...)
		groups := append([]string{}, node.Groups...)
		diskType := strings.TrimSpace(node.DiskType)
		if diskType == "" {
			diskType = strings.TrimSpace(stats.DiskType)
		}
		netSpeedMbps := float64(node.NetSpeedMbps)
		if netSpeedMbps <= 0 {
			netSpeedMbps = stats.NetSpeedMbps
		}
		testSummaries, testsByKey := buildAINetworkTestSummaries(stats.NetworkTests)
		testTrends := buildAINetworkTrendSummaries(stats.NodeID, testsByKey, history)
		servers = append(servers, aiServerSummary{
			ServerID:          node.ServerID,
			DisplayName:       name,
			Hostname:          hostName,
			Status:            node.Status,
			Group:             group,
			Tags:              tags,
			Groups:            groups,
			Region:            strings.TrimSpace(node.Region),
			OS:                stats.OS,
			Arch:              stats.Arch,
			AgentVersion:      strings.TrimSpace(stats.AgentVersion),
			CPUUsage:          stats.CPU.UsagePercent,
			MemUsage:          stats.Memory.UsedPercent,
			DiskUsed:          diskUsed,
			DiskType:          diskType,
			NetSpeedMbps:      netSpeedMbps,
			NetRecvBytes:      stats.Network.BytesRecv,
			NetSendBytes:      stats.Network.BytesSent,
			RxBytesPerSec:     stats.Network.RxBytesPerSec,
			TxBytesPerSec:     stats.Network.TxBytesPerSec,
			ProcessCount:      stats.ProcessCount,
			TCPConns:          stats.TCPConns,
			UDPConns:          stats.UDPConns,
			UptimeSec:         stats.UptimeSec,
			LastSeen:          node.LastSeen,
			FirstSeen:         node.FirstSeen,
			ExpireAt:          node.ExpireAt,
			RenewIntervalSec:  node.RenewIntervalSec,
			AlertEnabled:      node.AlertEnabled,
			OfflineSummary:    offlineSummary,
			NetworkTests:      testSummaries,
			NetworkTestTrends: testTrends,
		})
	}
	return aiSnapshot{
		GeneratedAt: snapshotTime.Format("2006-01-02 15:04:05"),
		Servers:     servers,
	}
}

func resolveAIOfflineStore(store *Store) *history.OfflineStore {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	historyManager := store.historyManager
	store.mu.RUnlock()
	if historyManager == nil {
		return nil
	}
	return historyManager.OfflineStore()
}

func buildAIOfflineSummary(offlineStore *history.OfflineStore, nodeID string, now time.Time) *aiOfflineSummary {
	if offlineStore == nil {
		return nil
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	insights, err := offlineStore.QueryInsights(nodeID, now, aiOfflineRecentSessionLimit)
	if err != nil {
		return nil
	}

	summary := &aiOfflineSummary{
		TotalCount:         insights.TotalCount,
		Last30dCount:       insights.Last30dCount,
		LongestDurationSec: insights.LongestDurationSec,
		AvgDurationSec:     insights.AvgDurationSec,
	}
	if !insights.LastOfflineRecoveredAt.IsZero() {
		summary.LastOfflineRecoveredAt = insights.LastOfflineRecoveredAt.Unix()
	}
	if len(insights.RecentSessions) > 0 {
		summary.RecentSessions = make([]aiOfflineRecentSession, len(insights.RecentSessions))
		for i, session := range insights.RecentSessions {
			summary.RecentSessions[i] = aiOfflineRecentSession{
				StartedAt:   session.StartedAt.Unix(),
				RecoveredAt: session.RecoveredAt.Unix(),
				DurationSec: session.DurationSec,
			}
		}
	}
	return summary
}

func buildAINetworkTestSummaries(tests []metrics.NetworkTestResult) ([]aiNetworkTestSummary, map[string]metrics.NetworkTestResult) {
	if len(tests) == 0 {
		return nil, nil
	}
	testsByKey := make(map[string]metrics.NetworkTestResult)
	keys := make([]string, 0, len(tests))
	for _, test := range tests {
		key := buildTestHistoryKey(test)
		if key == "" {
			key = fmt.Sprintf("%s|%s|%d|%s", strings.ToLower(strings.TrimSpace(test.Type)), strings.ToLower(strings.TrimSpace(test.Host)), test.Port, strings.ToLower(strings.TrimSpace(test.Name)))
		}
		existing, ok := testsByKey[key]
		if !ok || test.CheckedAt >= existing.CheckedAt {
			if !ok {
				keys = append(keys, key)
			}
			testsByKey[key] = test
		}
	}
	sort.Strings(keys)

	summaries := make([]aiNetworkTestSummary, 0, len(keys))
	for _, key := range keys {
		test := testsByKey[key]
		summaries = append(summaries, aiNetworkTestSummary{
			Name:       strings.TrimSpace(test.Name),
			Type:       strings.ToLower(strings.TrimSpace(test.Type)),
			Host:       strings.TrimSpace(test.Host),
			Port:       test.Port,
			Status:     strings.TrimSpace(test.Status),
			Error:      strings.TrimSpace(test.Error),
			CheckedAt:  test.CheckedAt,
			LatencyMs:  normalizeFloatPointer(test.LatencyMs),
			PacketLoss: test.PacketLoss,
		})
	}
	return summaries, testsByKey
}

func buildAINetworkTrendSummaries(
	nodeID string,
	currentByKey map[string]metrics.NetworkTestResult,
	history map[string]map[string]*TestHistoryEntry,
) []aiNetworkTrend {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || history == nil {
		return nil
	}
	nodeHistory := history[nodeID]
	if len(nodeHistory) == 0 {
		return nil
	}

	keys := make([]string, 0, len(nodeHistory))
	for key, entry := range nodeHistory {
		if key == "" || entry == nil || len(entry.Times) == 0 {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)

	trends := make([]aiNetworkTrend, 0, len(keys))
	for _, key := range keys {
		entry := nodeHistory[key]
		kind, host, port, name := parseTestHistoryKey(key)
		var current *metrics.NetworkTestResult
		if currentByKey != nil {
			if test, ok := currentByKey[key]; ok {
				current = &test
				if strings.TrimSpace(test.Type) != "" {
					kind = strings.ToLower(strings.TrimSpace(test.Type))
				}
				if strings.TrimSpace(test.Host) != "" {
					host = strings.TrimSpace(test.Host)
				}
				if test.Port > 0 {
					port = test.Port
				}
				if strings.TrimSpace(test.Name) != "" {
					name = strings.TrimSpace(test.Name)
				}
			}
		}
		trends = append(trends, summarizeAINetworkTrend(kind, host, port, name, entry, current))
	}
	return trends
}

func summarizeAINetworkTrend(
	kind string,
	host string,
	port int,
	name string,
	entry *TestHistoryEntry,
	current *metrics.NetworkTestResult,
) aiNetworkTrend {
	normalizeHistoryEntry(entry)
	windowStart := int64(0)
	windowEnd := int64(0)
	if len(entry.Times) > 0 {
		windowStart = entry.Times[0]
		windowEnd = entry.Times[len(entry.Times)-1]
	}
	latestCheckedAt := entry.LastAt
	if latestCheckedAt <= 0 {
		latestCheckedAt = windowEnd
	}
	latestLatency := latestNonNilFloat(entry.Latency)
	latestLoss := latestNonNilFloat(entry.Loss)
	if current != nil {
		currentCheckedAt := current.CheckedAt
		if currentCheckedAt <= 0 {
			currentCheckedAt = latestCheckedAt
		}
		if currentCheckedAt >= latestCheckedAt {
			latestCheckedAt = currentCheckedAt
			latestLatency = normalizeFloatPointer(current.LatencyMs)
			latestLoss = normalizeFloatValue(current.PacketLoss)
		}
	}
	avgLatency := averageNonNilFloat(entry.Latency)
	maxLatency := maxNonNilFloat(entry.Latency)
	avgLoss := averageNonNilFloat(entry.Loss)

	return aiNetworkTrend{
		Name:            strings.TrimSpace(name),
		Type:            strings.ToLower(strings.TrimSpace(kind)),
		Host:            strings.TrimSpace(host),
		Port:            port,
		Samples:         len(entry.Times),
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		LatestCheckedAt: latestCheckedAt,
		LatestLatencyMs: latestLatency,
		LatestLoss:      latestLoss,
		AvgLatencyMs:    avgLatency,
		MaxLatencyMs:    maxLatency,
		AvgLoss:         avgLoss,
		MinIntervalSec:  entry.MinIntervalSec,
		AvgIntervalSec:  entry.AvgIntervalSec,
		StatusHint:      deriveAINetworkStatusHint(current, latestLatency, latestLoss, avgLatency),
	}
}

func parseTestHistoryKey(key string) (kind string, host string, port int, name string) {
	parts := strings.SplitN(key, "|", 4)
	if len(parts) == 4 {
		kind = strings.TrimSpace(parts[0])
		host = strings.TrimSpace(parts[1])
		if parsed, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && parsed > 0 {
			port = parsed
		}
		name = strings.TrimSpace(parts[3])
	}
	if kind == "" {
		kind = "icmp"
	}
	return kind, host, port, name
}

func latestNonNilFloat(values []*float64) *float64 {
	for idx := len(values) - 1; idx >= 0; idx-- {
		if value := normalizeFloatPointer(values[idx]); value != nil {
			return value
		}
	}
	return nil
}

func averageNonNilFloat(values []*float64) *float64 {
	total := 0.0
	count := 0
	for _, raw := range values {
		value := normalizeFloatPointer(raw)
		if value == nil {
			continue
		}
		total += *value
		count++
	}
	if count == 0 {
		return nil
	}
	avg := total / float64(count)
	return &avg
}

func maxNonNilFloat(values []*float64) *float64 {
	var maxValue *float64
	for _, raw := range values {
		value := normalizeFloatPointer(raw)
		if value == nil {
			continue
		}
		if maxValue == nil || *value > *maxValue {
			cloned := *value
			maxValue = &cloned
		}
	}
	return maxValue
}

func deriveAINetworkStatusHint(
	current *metrics.NetworkTestResult,
	latestLatency *float64,
	latestLoss *float64,
	avgLatency *float64,
) string {
	if current != nil {
		if status := strings.ToLower(strings.TrimSpace(current.Status)); status != "" {
			return status
		}
		if errText := strings.TrimSpace(current.Error); errText != "" {
			return "error"
		}
	}
	if latestLoss != nil {
		if *latestLoss >= 99.9 {
			return "unreachable"
		}
		if *latestLoss > 0 {
			return "packet_loss"
		}
	}
	if latestLatency == nil {
		return "unknown"
	}
	if avgLatency != nil && *avgLatency > 0 && *latestLatency > *avgLatency*1.5 {
		return "latency_spike"
	}
	return "healthy"
}

func resolveNodeDisplayNameForAI(node NodeView) string {
	if value := strings.TrimSpace(node.Alias); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.NodeName); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.Hostname); value != "" {
		return value
	}
	if value := strings.TrimSpace(node.Stats.NodeID); value != "" {
		return value
	}
	return "未命名节点"
}

func callAIProvider(ctx context.Context, provider string, config AIProviderConfig, systemPrompt, userPrompt string) (string, error) {
	switch provider {
	case aiProviderGemini:
		return callGemini(ctx, config, systemPrompt, userPrompt)
	case aiProviderOpenAI, aiProviderVolcengine, aiProviderOpenAICompatible:
		return callOpenAICompatible(ctx, config, systemPrompt, userPrompt)
	default:
		return "", errors.New("AI 提供商无效")
	}
}

func callOpenAICompatible(ctx context.Context, config AIProviderConfig, systemPrompt, userPrompt string) (string, error) {
	if config.APIKey == "" {
		return "", errors.New("API Key 不能为空")
	}
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if baseURL == "" {
		return "", errors.New("Base URL 不能为空")
	}
	if config.Model == "" {
		return "", errors.New("模型不能为空")
	}
	payload := map[string]any{
		"model": config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": defaultAITemperature,
		"max_tokens":  defaultAIMaxOutputTokens,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/chat/completions", baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.APIKey))
	client := &http.Client{Timeout: 18 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("AI 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("AI 响应解析失败: %w", err)
	}
	if parsed.Error != nil {
		return "", errors.New(parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("AI 未返回结果")
	}
	answer := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if answer == "" {
		return "", errors.New("AI 未返回有效内容")
	}
	return answer, nil
}

func callGemini(ctx context.Context, config AIProviderConfig, systemPrompt, userPrompt string) (string, error) {
	if config.APIKey == "" {
		return "", errors.New("API Key 不能为空")
	}
	if config.Model == "" {
		return "", errors.New("模型不能为空")
	}
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if baseURL == "" {
		return "", errors.New("Base URL 不能为空")
	}
	model := normalizeGeminiModel(config.Model)
	prompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)
	payload := map[string]any{
		"contents": []map[string]any{
			{
				"role": "user",
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]any{
			"temperature":     defaultAITemperature,
			"maxOutputTokens": defaultAIMaxOutputTokens,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/%s:generateContent?key=%s", baseURL, model, url.QueryEscape(config.APIKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 18 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readResponseBodyLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("AI 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed geminiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("AI 响应解析失败: %w", err)
	}
	if parsed.Error != nil {
		return "", errors.New(parsed.Error.Message)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("AI 未返回结果")
	}
	answer := strings.TrimSpace(parsed.Candidates[0].Content.Parts[0].Text)
	if answer == "" {
		return "", errors.New("AI 未返回有效内容")
	}
	return answer, nil
}

func normalizeGeminiModel(model string) string {
	value := strings.TrimSpace(model)
	if value == "" {
		return defaultGeminiModel
	}
	if strings.Contains(value, "/") {
		return value
	}
	return "models/" + value
}

func trimTelegramMessage(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}
	runes := []rune(trimmed)
	if len(runes) <= maxTelegramMessageRunes {
		return trimmed
	}
	return string(runes[:maxTelegramMessageRunes]) + "..."
}
