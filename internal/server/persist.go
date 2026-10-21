package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/server/history"
)

const (
	adminTokenLength       = 12
	tokenAlphabet          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	defaultSiteTitle       = "CyberMonitor"
	defaultHomeTitle       = "CyberMonitor"
	defaultHomeSub         = "主机监控"
	defaultLocale          = "zh-CN"
	defaultAlertOfflineSec = 300
	defaultLoginFailLimit  = 5
	defaultLoginFailWindow = 15 * 60
	defaultLoginLockSec    = 15 * 60
	maxDurationSettingSec  = 30 * 24 * 3600
	testHistoryFileName    = "test_history.json"
	configExportVersion    = 1
	maxTestCatalogItems    = 512
)

// defaultResourceHistoryDays 是资源历史保留天数的默认值。
const defaultResourceHistoryDays = 7

// normalizeResourceHistoryDays 把非法值收敛到默认值（加载旧配置 / 读取公开设置用）。
func normalizeResourceHistoryDays(days int) int {
	if history.ValidResourceRetentionDays(days) {
		return days
	}
	return defaultResourceHistoryDays
}

var secureRandomReader io.Reader = rand.Reader

type Settings struct {
	AdminPath            string  `json:"admin_path"`
	AdminUser            string  `json:"admin_user"`
	AdminPass            string  `json:"admin_pass"`
	AdminPassPlain       string  `json:"-"`
	TurnstileSiteKey     string  `json:"turnstile_site_key,omitempty"`
	TurnstileSecretKey   string  `json:"turnstile_secret_key,omitempty"`
	TokenSalt            string  `json:"token_salt,omitempty"`
	AuthToken            string  `json:"auth_token,omitempty"`
	AgentToken           string  `json:"agent_token,omitempty"`
	AgentEndpoint        string  `json:"agent_endpoint,omitempty"`
	SiteTitle            string  `json:"site_title,omitempty"`
	SiteIcon             string  `json:"site_icon,omitempty"`
	SiteBackgroundImage  string  `json:"site_background_image,omitempty"`
	HomeTitle            string  `json:"home_title,omitempty"`
	HomeSubtitle         string  `json:"home_subtitle,omitempty"`
	Locale               string  `json:"locale,omitempty"`
	RegionGroupDisabled  bool    `json:"region_group_disabled,omitempty"`
	AlertWebhook         string  `json:"alert_webhook,omitempty"`
	AlertOfflineSec      int64   `json:"alert_offline_sec,omitempty"`
	AlertTelegramToken   string  `json:"alert_telegram_token,omitempty"`
	AlertTelegramUserIDs []int64 `json:"alert_telegram_user_ids,omitempty"`
	AlertTelegramUserID  int64   `json:"alert_telegram_user_id,omitempty"`
	// NotifyChannels 是 F5 引入的多渠道通知模型；为空时由上面的旧字段在加载时
	// 合成（feishu / telegram 两条迁移渠道）。旧字段在本版本内与渠道双向同步保留。
	NotifyChannels     []NotifyChannel   `json:"notify_channels,omitempty"`
	LoginFailLimit     int               `json:"login_fail_limit,omitempty"`
	LoginFailWindowSec int64             `json:"login_fail_window_sec,omitempty"`
	LoginLockSec       int64             `json:"login_lock_sec,omitempty"`
	AdminAuth          AdminAuthSettings `json:"admin_auth,omitempty"`
	AISettings         AISettings        `json:"ai_settings,omitempty"`
	Groups             []string          `json:"groups,omitempty"`
	GroupTree          []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog        []TestCatalogItem `json:"test_catalog,omitempty"`
	// ResourceHistoryDays 是资源历史（CPU / 内存 / 网络）的保留天数，允许 1/7/30。
	ResourceHistoryDays int `json:"resource_history_days,omitempty"`
	// AlertRules 是 F4 引入的告警规则模型；加载时保证含且仅含一条 metric=offline
	// 的内置规则（不可删除，duration_sec 始终镜像 AlertOfflineSec）。
	AlertRules []AlertRule `json:"alert_rules,omitempty"`
}

type SettingsView struct {
	AdminPath          string `json:"admin_path"`
	AdminUser          string `json:"admin_user"`
	TurnstileSiteKey   string `json:"turnstile_site_key,omitempty"`
	TurnstileSecretKey string `json:"turnstile_secret_key,omitempty"`
	AgentEndpoint      string `json:"agent_endpoint,omitempty"`
	// AgentEndpointSuggestion 是按当前请求推断的 Agent 对接地址：只用于展示与
	// 生成安装命令，不写回 agent_endpoint、不导出。
	AgentEndpointSuggestion string  `json:"agent_endpoint_suggestion,omitempty"`
	AgentToken              string  `json:"agent_token,omitempty"`
	AgentTokenSet           bool    `json:"agent_token_set,omitempty"`
	SiteTitle               string  `json:"site_title,omitempty"`
	SiteIcon                string  `json:"site_icon,omitempty"`
	SiteBackgroundImage     string  `json:"site_background_image,omitempty"`
	HomeTitle               string  `json:"home_title,omitempty"`
	HomeSubtitle            string  `json:"home_subtitle,omitempty"`
	Locale                  string  `json:"locale,omitempty"`
	RegionGroupEnabled      *bool   `json:"region_group_enabled,omitempty"`
	AlertWebhook            string  `json:"alert_webhook,omitempty"`
	AlertWebhookSet         bool    `json:"alert_webhook_set,omitempty"`
	AlertOfflineSec         int64   `json:"alert_offline_sec,omitempty"`
	AlertTelegramToken      string  `json:"alert_telegram_token,omitempty"`
	AlertTelegramTokenSet   bool    `json:"alert_telegram_token_set,omitempty"`
	AlertTelegramUserIDs    []int64 `json:"alert_telegram_user_ids,omitempty"`
	// NotifyChannels 为视图形态：Secrets 置空，改以 SecretsSet 标记已配置的敏感字段。
	NotifyChannels      []NotifyChannel   `json:"notify_channels,omitempty"`
	LoginFailLimit      int               `json:"login_fail_limit,omitempty"`
	LoginFailWindowSec  int64             `json:"login_fail_window_sec,omitempty"`
	LoginLockSec        int64             `json:"login_lock_sec,omitempty"`
	AdminAuth           AdminAuthSettings `json:"admin_auth,omitempty"`
	AISettings          AISettings        `json:"ai_settings,omitempty"`
	Version             string            `json:"version,omitempty"`
	Commit              string            `json:"commit,omitempty"`
	Groups              []string          `json:"groups,omitempty"`
	GroupTree           []GroupNode       `json:"group_tree,omitempty"`
	TestCatalog         []TestCatalogItem `json:"test_catalog,omitempty"`
	ResourceHistoryDays int               `json:"resource_history_days,omitempty"`
	// AlertRules（F4）：规则为非敏感配置，View 原样返回；alert_rule_status 为运行时
	// 聚合（每条规则当前处于 FIRING 的节点数），导入时被忽略。
	AlertRules      []AlertRule                    `json:"alert_rules,omitempty"`
	AlertRuleStatus map[string]AlertRuleStatusView `json:"alert_rule_status,omitempty"`
}

type SettingsUpdate struct {
	AdminPath            *string            `json:"admin_path"`
	AdminUser            *string            `json:"admin_user"`
	AdminPass            *string            `json:"admin_pass"`
	TurnstileSiteKey     *string            `json:"turnstile_site_key"`
	TurnstileSecretKey   *string            `json:"turnstile_secret_key"`
	AgentToken           *string            `json:"agent_token"`
	AgentEndpoint        *string            `json:"agent_endpoint"`
	SiteTitle            *string            `json:"site_title"`
	SiteIcon             *string            `json:"site_icon"`
	SiteBackgroundImage  *string            `json:"site_background_image"`
	HomeTitle            *string            `json:"home_title"`
	HomeSubtitle         *string            `json:"home_subtitle"`
	Locale               *string            `json:"locale"`
	RegionGroupEnabled   *bool              `json:"region_group_enabled"`
	AlertWebhook         *string            `json:"alert_webhook"`
	AlertOfflineSec      *int64             `json:"alert_offline_sec"`
	AlertTelegramToken   *string            `json:"alert_telegram_token"`
	AlertTelegramUserIDs *[]int64           `json:"alert_telegram_user_ids"`
	NotifyChannels       *[]NotifyChannel   `json:"notify_channels,omitempty"`
	LoginFailLimit       *int               `json:"login_fail_limit"`
	LoginFailWindowSec   *int64             `json:"login_fail_window_sec"`
	LoginLockSec         *int64             `json:"login_lock_sec"`
	AdminAuth            *AdminAuthSettings `json:"admin_auth"`
	AISettings           *AISettings        `json:"ai_settings"`
	Groups               *[]string          `json:"groups"`
	GroupTree            *[]GroupNode       `json:"group_tree"`
	GroupMoves           *[]GroupMove       `json:"group_moves,omitempty"`
	TestCatalog          *[]TestCatalogItem `json:"test_catalog"`
	ResourceHistoryDays  *int               `json:"resource_history_days"`
	// AlertRules（F4）：nil 表示本次请求不改规则；非 nil 时为完整规则列表（含内置
	// offline 规则的处理见 normalizeAlertRules）。
	AlertRules *[]AlertRule `json:"alert_rules,omitempty"`
}

type AdminAuthSettings struct {
	PasswordLoginEnabled bool                   `json:"password_login_enabled"`
	GitHub               OAuth2ProviderSettings `json:"github,omitempty"`
	OIDC                 OIDCProviderSettings   `json:"oidc,omitempty"`
}

type OAuth2ProviderSettings struct {
	Enabled              bool     `json:"enabled"`
	DisplayName          string   `json:"display_name,omitempty"`
	ClientID             string   `json:"client_id,omitempty"`
	ClientSecret         string   `json:"client_secret,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	AllowedLogins        []string `json:"allowed_logins,omitempty"`
	AllowedEmails        []string `json:"allowed_emails,omitempty"`
	AllowedEmailDomains  []string `json:"allowed_email_domains,omitempty"`
	RequireVerifiedEmail bool     `json:"require_verified_email"`
}

type OIDCProviderSettings struct {
	Enabled              bool     `json:"enabled"`
	DisplayName          string   `json:"display_name,omitempty"`
	IssuerURL            string   `json:"issuer_url,omitempty"`
	ClientID             string   `json:"client_id,omitempty"`
	ClientSecret         string   `json:"client_secret,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	AllowedSubjects      []string `json:"allowed_subjects,omitempty"`
	AllowedEmails        []string `json:"allowed_emails,omitempty"`
	AllowedEmailDomains  []string `json:"allowed_email_domains,omitempty"`
	RequireVerifiedEmail bool     `json:"require_email_verified"`
}

type PersistedData struct {
	Settings        Settings                       `json:"settings"`
	Profiles        map[string]*NodeProfile        `json:"profiles"`
	Nodes           map[string]NodeState           `json:"nodes,omitempty"`
	OfflineSessions map[string]OfflineSessionState `json:"offline_sessions,omitempty"`
	Alerted         map[string]AlertedState        `json:"alerted,omitempty"`
	// AlertStates（F4）按 `nodeID|ruleID` 记录告警规则的评估状态机；offline 规则
	// 不在此表中（继续使用上方 Alerted，保证旧离线测试与数据兼容）。
	AlertStates           map[string]RuleAlertState `json:"alert_states,omitempty"`
	PendingHistoryClear   bool                      `json:"pending_history_clear,omitempty"`
	PendingHistoryDeletes []string                  `json:"pending_history_deletes,omitempty"`
}

type legacyPersistedProfile struct {
	Tests []metrics.NetworkTestConfig `json:"tests,omitempty"`
}

type OfflineSessionState struct {
	StartedAt int64 `json:"started_at"`
}

// AlertedState 记录单节点的离线告警投递进度。Delivered 按渠道 ID 记录投递成功
// 的渠道，只补发失败渠道；旧版 state.json 中的 delivered_feishu / delivered_telegram
// 两个 bool 在加载时映射到渠道 id "feishu" / "telegram"（见 UnmarshalJSON）。
type AlertedState struct {
	OfflineSince    time.Time       `json:"offline_since"`
	NextRetryAt     time.Time       `json:"next_retry_at,omitempty"`
	RetryCount      int             `json:"retry_count,omitempty"`
	Delivered       map[string]bool `json:"delivered,omitempty"`
	RecoveryPending bool            `json:"recovery_pending,omitempty"`
}

// UnmarshalJSON 兼容旧格式：delivered_feishu / delivered_telegram 映射到
// Delivered["feishu"] / Delivered["telegram"]，与加载迁移合成的渠道 ID 一致。
func (s *AlertedState) UnmarshalJSON(data []byte) error {
	type alertedStateAlias AlertedState
	var alias alertedStateAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	var legacy struct {
		DeliveredFeishu   bool `json:"delivered_feishu,omitempty"`
		DeliveredTelegram bool `json:"delivered_telegram,omitempty"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*s = AlertedState(alias)
	if legacy.DeliveredFeishu || legacy.DeliveredTelegram {
		if s.Delivered == nil {
			s.Delivered = make(map[string]bool)
		}
		if legacy.DeliveredFeishu {
			s.Delivered[legacyFeishuChannelID] = true
		}
		if legacy.DeliveredTelegram {
			s.Delivered[legacyTelegramChannelID] = true
		}
	}
	return nil
}

// AlertRule 是 F4 定稿的单条件告警规则模型（事件类规则 expiry / traffic_quota
// 单独处理，Op/Threshold 等字段的适用性见指标表）。
type AlertRule struct {
	ID          string     `json:"id"`           // "r_" + 随机 10 位；内置离线规则固定为 "offline"
	Name        string     `json:"name"`         //
	Enabled     bool       `json:"enabled"`      //
	Metric      string     `json:"metric"`       // 见 alertRuleMetricTable
	Op          string     `json:"op"`           // "gt" | "lt"（offline/expiry/traffic_quota 忽略）
	Threshold   float64    `json:"threshold"`    // 单位随指标（net_in/net_out 为 B/s）
	DurationSec int64      `json:"duration_sec"` // 持续窗口；0 = 单次采样即判定
	Ratio       float64    `json:"ratio"`        // 窗口内越限占比，默认 0.7（Nezha 语义）
	Scope       AlertScope `json:"scope"`        //
	// ChannelIDs 为空 = 全部已启用渠道。
	ChannelIDs []string `json:"channel_ids,omitempty"` //
	// NotifyRecover 默认 true：省略该字段的请求按 true 解码（见 UnmarshalJSON）。
	NotifyRecover bool   `json:"notify_recover"`       //
	Repeat        string `json:"repeat"`               // "once" | "backoff"（15min 起 ×2，上限 24h）
	ProbeName     string `json:"probe_name,omitempty"` // probe_* 指标用，对应 network_tests[].name
	LeadDays      []int  `json:"lead_days,omitempty"`  // expiry 用，默认 [7,3,1]
}

// UnmarshalJSON 落实文档「notify_recover 默认 true」：请求 / 草稿省略该字段时按
// true 解码，显式 false 保持 false（bool 无三态，只能在解码层区分省略与否）。
// 落盘与 View 的编码始终携带 notify_recover，F4 之前不存在 alert_rules 数据，
// 因此旧 state.json 与导出文件无兼容负担。解码内部沿用 DisallowUnknownFields，
// 保持 decodeJSON 对规则体内未知字段的拒绝语义（preview 路由测试依赖该行为）。
func (r *AlertRule) UnmarshalJSON(data []byte) error {
	type alertRuleAlias AlertRule
	payload := struct {
		*alertRuleAlias
		NotifyRecover *bool `json:"notify_recover"` // 遮蔽 alias 的同名 bool，捕获「是否显式携带」
	}{alertRuleAlias: (*alertRuleAlias)(r)}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return err
	}
	if payload.NotifyRecover == nil {
		r.NotifyRecover = true
		return nil
	}
	r.NotifyRecover = *payload.NotifyRecover
	return nil
}

// AlertScope 描述规则适用的节点集合：mode=all 时 Exclude 生效；mode=include 时
// Nodes / Groups 任一命中即适用（Groups 值为 "A" 或 "A:t" 这类 selection 字符串）。
type AlertScope struct {
	Mode    string   `json:"mode"`              // "all" | "include"
	Nodes   []string `json:"nodes,omitempty"`   // node id
	Groups  []string `json:"groups,omitempty"`  // "A" 或 "A:t"
	Exclude []string `json:"exclude,omitempty"` // node id（mode=all 时生效）
}

// RuleAlertState 是单 (node, rule) 的评估状态机（F4）。State 为 "OK" | "FIRING"；
// offline 规则不使用本结构（沿用 AlertedState）。
type RuleAlertState struct {
	State          string          `json:"state"`
	FiringSince    time.Time       `json:"firing_since,omitempty"`
	LastNotifiedAt time.Time       `json:"last_notified_at,omitempty"`
	NextRepeatAt   time.Time       `json:"next_repeat_at,omitempty"`
	Delivered      map[string]bool `json:"delivered,omitempty"`
	RetryCount     int             `json:"retry_count,omitempty"`
	NextRetryAt    time.Time       `json:"next_retry_at,omitempty"`
	// LastStepPct 为 traffic_quota 台阶去重（本周期已提醒到的台阶）。
	LastStepPct float64 `json:"last_step_pct,omitempty"`
	// SentLeadDays 为 expiry 提醒去重（已发送的 lead day）。到期时间后移导致
	// daysLeft 回升超过已记录值时整体清零（见 collectExpiryEventsLocked）。
	SentLeadDays []int `json:"sent_lead_days,omitempty"`
	// RecoveryValue / RecoveryDurationSec 是 FIRING→OK 瞬间的恢复快照：恢复通知
	// 补发与重试只读快照，不用补发时刻的当前值，也不重新推算时长。旧 state.json
	// 没有这两个字段，加载后为 nil（补发文案显示未知，不伪造）。
	RecoveryValue       *float64 `json:"recovery_value,omitempty"`
	RecoveryDurationSec *int64   `json:"recovery_duration_sec,omitempty"`
	// ViolatedRatio 是当前状态对应事件（阈值告警或恢复）的窗口内越限时间占比
	// （0..1）：告警文案说“近 N 内 X% 时间越限”就用它，失败补发沿用触发那一刻的
	// 值而不是重新计算。单次采样判定（duration_sec<=0）没有窗口，为空。旧
	// state.json 没有该字段，加载后为 nil（文案退化为条件描述，不编造百分比）。
	ViolatedRatio *float64 `json:"violated_ratio,omitempty"`
	// EventID 标识本状态当前对应的那一条通知事件（告警/恢复/台阶/lead day）。
	// 投递是异步的，回执返回时同一 (node, rule) 可能已产生新事件；回执只在
	// state.EventID 与事件 ID 相等时生效，避免迟到回执污染新事件。旧 state.json
	// 没有该字段，加载后为空字符串，与同样为空的事件 ID 匹配（向后兼容）。
	EventID string `json:"event_id,omitempty"`
}

// AlertRuleStatusView 是 SettingsView.alert_rule_status 的条目：某规则当前处于
// FIRING 状态的节点数。
type AlertRuleStatusView struct {
	Firing int `json:"firing"`
}

// TrafficCounter 是节点月度流量累计（F4 traffic_quota 的前置数据）。AccSent/AccRecv
// 由 updateNodeStats 按 Increment 累加，agent 重启回绕时把新值当增量；到重置日清零。
type TrafficCounter struct {
	CycleStart int64  `json:"cycle_start,omitempty"` // 当前周期起点（unix 秒，本地时区口径）
	LastSent   uint64 `json:"last_sent,omitempty"`   // 上次上报的 agent 累计发送字节数
	LastRecv   uint64 `json:"last_recv,omitempty"`   // 上次上报的 agent 累计接收字节数
	AccSent    uint64 `json:"acc_sent,omitempty"`    // 本周期累计发送
	AccRecv    uint64 `json:"acc_recv,omitempty"`    // 本周期累计接收
}

// NotifyChannel 是 F5 定稿的多渠道通知模型。Config 存非敏感字段，Secrets 存敏感
// 字段（View 置空并改给 SecretsSet）；SecretsSet 仅出现在视图/请求载体中，落盘前
// 会被 normalizeNotifyChannels 丢弃。LastTest 由测试推送接口写入。
type NotifyChannel struct {
	ID         string             `json:"id,omitempty"`
	Type       string             `json:"type,omitempty"`
	Name       string             `json:"name,omitempty"`
	Enabled    bool               `json:"enabled,omitempty"`
	Config     map[string]string  `json:"config,omitempty"`
	Secrets    map[string]string  `json:"secrets,omitempty"`
	SecretsSet map[string]bool    `json:"secrets_set,omitempty"`
	LastTest   *ChannelTestResult `json:"last_test,omitempty"`
	// SecretsClear（B-08 / D-04）仅请求载体：列出本次保存要清除的 secret key。
	// 合并阶段生效后，落盘（normalizeNotifyChannels）与视图（SettingsView）
	// 返回前都会被丢弃，不会出现在 state.json 与导出文件中。
	SecretsClear []string `json:"secrets_clear,omitempty"`
}

// ChannelTestResult 记录一次测试推送的结果（ok=false 时 Error 为错误原文）。
type ChannelTestResult struct {
	At        int64  `json:"at"`
	Ok        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

const (
	legacyFeishuChannelID   = "feishu"
	legacyTelegramChannelID = "telegram"

	notifyChannelTypeTelegram = "telegram"
	notifyChannelTypeFeishu   = "feishu"
	notifyChannelTypeBark     = "bark"
	notifyChannelTypeSlack    = "slack"
	notifyChannelTypeDingtalk = "dingtalk"
	notifyChannelTypeWecom    = "wecom"
	notifyChannelTypeEmail    = "email"

	defaultTelegramAPIEndpoint = "https://api.telegram.org"
)

// notifyChannelTypes 是渠道类型白名单（F5 定稿的 7 种）。各类型的发送器均已实现
// （notify_telegram / notify_feishu / notify_bark / notify_slack / notify_dingtalk /
// notify_wecom / notify_email，由 newNotifier 构造）。
var notifyChannelTypes = map[string]struct{}{
	notifyChannelTypeTelegram: {},
	notifyChannelTypeFeishu:   {},
	notifyChannelTypeBark:     {},
	notifyChannelTypeSlack:    {},
	notifyChannelTypeDingtalk: {},
	notifyChannelTypeWecom:    {},
	notifyChannelTypeEmail:    {},
}

type TestHistoryEntry struct {
	Latency        []*float64 `json:"latency"`
	Loss           []*float64 `json:"loss"`
	Times          []int64    `json:"times"`
	LastAt         int64      `json:"last_at"`
	MinIntervalSec int64      `json:"min_interval_sec,omitempty"`
	AvgIntervalSec float64    `json:"avg_interval_sec,omitempty"`
}

type ConfigTransferData struct {
	Version    int                               `json:"version"`
	ExportedAt int64                             `json:"exported_at"`
	Settings   SettingsView                      `json:"settings"`
	Profiles   map[string]*ConfigTransferProfile `json:"profiles,omitempty"`
}

type ConfigTransferProfile struct {
	AlertEnabled     *bool    `json:"alert_enabled,omitempty"`
	Alias            string   `json:"alias,omitempty"`
	Group            string   `json:"group,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	Region           string   `json:"region,omitempty"`
	DiskType         string   `json:"disk_type,omitempty"`
	NetSpeedMbps     int      `json:"net_speed_mbps,omitempty"`
	ExpireAt         int64    `json:"expire_at,omitempty"`
	AutoRenew        bool     `json:"auto_renew,omitempty"`
	RenewIntervalSec int64    `json:"renew_interval_sec,omitempty"`
	// 流量配额配置（F4）。TrafficCounter 为运行数据，不参与导出（导入后重新累计）。
	TrafficLimitBytes uint64          `json:"traffic_limit_bytes,omitempty"`
	TrafficLimitType  string          `json:"traffic_limit_type,omitempty"`
	TrafficResetDay   int             `json:"traffic_reset_day,omitempty"`
	TestIntervalSec   int             `json:"test_interval_sec"`
	TestSelections    []TestSelection `json:"test_selections,omitempty"`
}

type ResetResult struct {
	AdminUser string
	AdminPass string
	AdminPath string
}

var ErrDataDirLocked = errors.New("数据目录正被其他进程使用（服务可能正在运行）")

func ResetAdminPassword(dataDir string) (ResetResult, error) {
	if strings.TrimSpace(dataDir) == "" {
		return ResetResult{}, errors.New("data dir required")
	}
	dataPath := filepath.Join(dataDir, "state.json")
	lockFile, err := tryLockFile(filepath.Join(dataDir, "server.lock"))
	if err != nil {
		return ResetResult{}, err
	}
	defer lockFile.Close()
	payload, loaded, err := loadPersistedData(dataPath)
	if err != nil {
		return ResetResult{}, err
	}
	if !loaded {
		settings, err := initSettings(Config{JWTSecret: ""})
		if err != nil {
			return ResetResult{}, err
		}
		payload.Settings = settings
		payload = applyPersistedDataDefaults(payload)
	}
	newPass, err := randomToken(adminTokenLength)
	if err != nil {
		return ResetResult{}, err
	}
	newHash, err := hashPassword(newPass)
	if err != nil {
		return ResetResult{}, err
	}
	payload.Settings.AdminPass = newHash
	tokenSalt, err := randomToken(adminTokenLength)
	if err != nil {
		return ResetResult{}, err
	}
	payload.Settings.TokenSalt = tokenSalt
	if err := savePersistedData(dataPath, payload); err != nil {
		return ResetResult{}, err
	}
	return ResetResult{
		AdminUser: payload.Settings.AdminUser,
		AdminPass: newPass,
		AdminPath: payload.Settings.AdminPath,
	}, nil
}

type TestCatalogItem struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	IntervalSec int    `json:"interval_sec,omitempty"`
	// O-01：下发范围。nil 表示「不下发」（旧数据行为不变，仅节点手动选择生效）；
	// 非 nil 时经 normalizeAlertScope 规范化（mode=all|include，exclude 两种模式
	// 都生效，复用 D-05 语义），范围命中的节点自动获得该探测。指针字段：加载后
	// 不就地修改（normalizeTestCatalog 总是构造新值），浅拷贝（cloneSettings /
	// settingsViewLocked 的 slices.Clone）共享指针是只读安全的。
	Scope *AlertScope `json:"scope,omitempty"`
}

type GroupNode struct {
	Name     string      `json:"name"`
	Children []GroupNode `json:"children,omitempty"`
}

// GroupMove 描述一次分组归属迁移（F1）：From / To 为 selection 字符串，
// 形如 "A"（分组级，整体替换前缀）或 "A:t"（标签级，精确匹配）。
type GroupMove struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func strictUnmarshalJSON(data []byte, target any) error {
	trailing, err := history.DecodeFirstJSONValue(data, target)
	if err != nil {
		return err
	}
	if trailing {
		return errors.New("extra content after JSON value")
	}
	return nil
}

func loadPersistedData(path string) (PersistedData, bool, error) {
	payload, loaded, err := readPersistedDataFile(path)
	if loaded {
		return payload, loaded, nil
	}
	backupPath := path + ".bak"
	backupPayload, backupLoaded, backupErr := readPersistedDataFile(backupPath)
	if !backupLoaded {
		var loadErrors []error
		if err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("读取 %s 失败: %w", path, err))
		}
		if backupErr != nil {
			loadErrors = append(loadErrors, fmt.Errorf("读取备份 %s 失败: %w", backupPath, backupErr))
		}
		return payload, false, errors.Join(loadErrors...)
	}
	if err != nil {
		log.Printf("读取 %s 失败（%v），从备份 %s 恢复", path, err, backupPath)
	} else {
		log.Printf("主文件 %s 缺失，已从备份 %s 恢复数据，下次持久化将写回主文件", path, backupPath)
	}
	if err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			log.Printf("移除损坏的主文件 %s 失败（%v）", path, removeErr)
		}
	}
	return backupPayload, backupLoaded, nil
}

func readPersistedDataFile(path string) (PersistedData, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PersistedData{}, false, nil
		}
		return PersistedData{}, false, err
	}
	var payload PersistedData
	if err := strictUnmarshalJSON(data, &payload); err != nil {
		return PersistedData{}, false, err
	}
	var probe struct {
		Profiles map[string]json.RawMessage `json:"profiles"`
		Settings struct {
			AISettings json.RawMessage `json:"ai_settings"`
		} `json:"settings"`
	}
	if err := strictUnmarshalJSON(data, &probe); err != nil {
		return PersistedData{}, false, err
	}
	if err := migrateLegacyProfileTests(probe.Profiles, &payload); err != nil {
		return PersistedData{}, false, err
	}
	if err := migrateLegacyAISettings(probe.Settings.AISettings, &payload); err != nil {
		return PersistedData{}, false, err
	}
	nodes := normalizePersistedNodeStates(payload.Nodes)
	payload.Nodes = nodes
	payload.OfflineSessions = normalizeNodeIDMap("offline_sessions", payload.OfflineSessions)
	payload.Alerted = normalizeNodeIDMap("alerted", payload.Alerted)
	payload.AlertStates = normalizeAlertStates(payload.AlertStates)
	profiles, err := normalizePersistedProfiles(payload.Settings, payload.Nodes, dropInvalidProfileKeys(payload.Profiles))
	if err != nil {
		return PersistedData{}, false, err
	}
	payload.Profiles = profiles
	pendingClear, pendingDeletes := normalizePersistedHistoryCleanup(payload.PendingHistoryClear, payload.PendingHistoryDeletes)
	payload.PendingHistoryClear = pendingClear
	payload.PendingHistoryDeletes = pendingDeletes
	return payload, true, nil
}

func savePersistedData(path string, payload PersistedData) error {
	// 先完整写 .new，再两步 rename：任意时刻 state.json 或 .bak 至少存在一份完整态，
	// 避免“先 rename 主文件→.bak 再写新文件”窗口期内主文件缺席。
	newPath := path + ".new"
	if err := writeJSONFileAtomic(newPath, payload); err != nil {
		return err
	}
	if err := os.Rename(path, path+".bak"); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("轮转备份 %s 失败（%v），继续写入主文件", path+".bak", err)
	}
	if err := os.Rename(newPath, path); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	// 最终 rename 已成功即视为提交完成：父目录 fsync 失败只记日志、不回滚——
	// 主文件内容本身已落盘，目录未同步仅意味着极端掉电后可能回退到旧状态，不会损坏数据。
	fsyncParentDir(path)
	return nil
}

// fsyncParentDir 尽力把两次 rename 的目录项变更刷入磁盘，掉电后 rename 结果仍然可见。
// Windows 无法对目录句柄 Sync，打开/同步失败时静默降级（与 history 包 syncParentDir 一致）。
func fsyncParentDir(path string) {
	dir := filepath.Dir(path)
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil && runtime.GOOS != "windows" {
		log.Printf("同步目录 %s 失败（%v），掉电后最近的持久化可能回退", dir, err)
	}
}

func applyPersistedDataDefaults(payload PersistedData) PersistedData {
	if payload.Profiles == nil {
		payload.Profiles = make(map[string]*NodeProfile)
	}
	if payload.Nodes == nil {
		payload.Nodes = make(map[string]NodeState)
	}
	if payload.OfflineSessions == nil {
		payload.OfflineSessions = make(map[string]OfflineSessionState)
	}
	if payload.Alerted == nil {
		payload.Alerted = make(map[string]AlertedState)
	}
	if payload.AlertStates == nil {
		payload.AlertStates = make(map[string]RuleAlertState)
	}
	return payload
}

// normalizeNodeIDMap 丢弃非法节点 ID 的条目并记录警告：单个坏 ID 不应阻止服务启动。
// trim 冲突用确定性两遍法消解，保证结果与 map 遍历顺序无关且跨表（nodes/profiles 等）一致：
// 第一遍收录 key 本身已等于 TrimSpace 后的条目；第二遍按原始 key 排序处理需要 trim 的条目，
// 目标 key 已被占据则丢弃并告警。
func normalizeNodeIDMap[V any](prefix string, items map[string]V) map[string]V {
	normalized := make(map[string]V, len(items))
	pending := make([]string, 0, len(items))
	for rawNodeID, item := range items {
		nodeID, err := history.NormalizeNodeID(rawNodeID)
		if err != nil || nodeID == "" {
			log.Printf("忽略 %s 中非法的节点 ID: %q", prefix, rawNodeID)
			continue
		}
		if rawNodeID == nodeID {
			normalized[nodeID] = item
			continue
		}
		pending = append(pending, rawNodeID)
	}
	sort.Strings(pending)
	for _, rawNodeID := range pending {
		nodeID, _ := history.NormalizeNodeID(rawNodeID)
		if _, exists := normalized[nodeID]; exists {
			log.Printf("忽略 %s 中的节点 ID %q：规范化为 %q 后与既有条目冲突", prefix, rawNodeID, nodeID)
			continue
		}
		normalized[nodeID] = items[rawNodeID]
	}
	return normalized
}

func normalizePersistedNodeStates(nodes map[string]NodeState) map[string]NodeState {
	normalized := normalizeNodeIDMap("nodes", nodes)
	for nodeID, node := range normalized {
		node.Stats.NodeID = nodeID
		normalized[nodeID] = node
	}
	return normalized
}

// dropInvalidProfileKeys 预先丢弃非法/重复节点 ID 的 profile 条目，
// 避免 normalizePersistedProfiles 因单个坏 ID 拒绝启动。
func dropInvalidProfileKeys(profiles map[string]*NodeProfile) map[string]*NodeProfile {
	return normalizeNodeIDMap("profiles", profiles)
}

func normalizePersistedHistoryCleanup(clear bool, deletes []string) (bool, []string) {
	if clear {
		return true, nil
	}
	if len(deletes) == 0 {
		return false, nil
	}
	seen := make(map[string]struct{}, len(deletes))
	normalized := make([]string, 0, len(deletes))
	for _, rawNodeID := range deletes {
		nodeID, err := history.NormalizeNodeID(rawNodeID)
		if err != nil || nodeID == "" {
			log.Printf("忽略 pending_history_deletes 中非法的节点 ID: %q", rawNodeID)
			continue
		}
		if _, ok := seen[nodeID]; ok {
			continue
		}
		seen[nodeID] = struct{}{}
		normalized = append(normalized, nodeID)
	}
	sort.Strings(normalized)
	return false, normalized
}

func migrateLegacyProfileTests(rawProfiles map[string]json.RawMessage, payload *PersistedData) error {
	if payload == nil || len(payload.Profiles) == 0 {
		return nil
	}

	if payload.Settings.TestCatalog == nil {
		payload.Settings.TestCatalog = []TestCatalogItem{}
	}
	if len(payload.Settings.TestCatalog) > maxTestCatalogItems {
		payload.Settings.TestCatalog = payload.Settings.TestCatalog[:maxTestCatalogItems]
	}

	legacyTests, err := readLegacyProfileTests(rawProfiles)
	if err != nil {
		return err
	}
	if len(legacyTests) == 0 {
		return nil
	}

	catalogIndex := legacyTestCatalogIndex(payload.Settings.TestCatalog)

	for nodeID, tests := range legacyTests {
		if len(tests) == 0 {
			continue
		}
		profile := payload.Profiles[nodeID]
		if profile == nil {
			continue
		}
		if len(profile.TestSelections) > 0 {
			profile.TestSelections = normalizeTestSelections(payload.Settings.TestCatalog, profile.TestSelections)
			if len(profile.TestSelections) > 0 {
				continue
			}
		}
		selections := make([]TestSelection, 0, len(tests))
		seenSelections := make(map[string]struct{}, len(tests))
		for _, test := range tests {
			item, ok := legacyTestCatalogItem(test, catalogIndex)
			if !ok {
				continue
			}
			if item.ID == "" {
				if len(payload.Settings.TestCatalog) >= maxTestCatalogItems {
					continue
				}
				id, err := randomToken(10)
				if err != nil {
					return err
				}
				item.ID = id
				payload.Settings.TestCatalog = append(payload.Settings.TestCatalog, item)
				catalogIndex[legacyTestCatalogKey(item.Name, item.Type, item.Host, item.Port)] = item
			}
			if _, exists := seenSelections[item.ID]; exists {
				continue
			}
			seenSelections[item.ID] = struct{}{}
			selections = append(selections, TestSelection{
				TestID:      item.ID,
				IntervalSec: test.IntervalSec,
			})
		}
		if len(selections) > 0 {
			profile.TestSelections = normalizeTestSelections(payload.Settings.TestCatalog, selections)
		}
	}
	return nil
}

func migrateLegacyAISettings(rawAISettings json.RawMessage, payload *PersistedData) error {
	if payload == nil || len(rawAISettings) == 0 {
		return nil
	}

	var legacy struct {
		DefaultProvider  string           `json:"default_provider"`
		OpenAICompatible AIProviderConfig `json:"openai_compatible"`
	}
	if err := strictUnmarshalJSON(rawAISettings, &legacy); err != nil {
		return err
	}

	compatID := "legacy-openai-compatible"
	if legacyAIProviderConfigPresent(legacy.OpenAICompatible) && !aiCompatibleIDExists(payload.Settings.AISettings.OpenAICompatibles, compatID) {
		payload.Settings.AISettings.OpenAICompatibles = append(payload.Settings.AISettings.OpenAICompatibles, AIProviderProfile{
			ID:               compatID,
			Name:             "OpenAI 兼容",
			AIProviderConfig: legacy.OpenAICompatible,
		})
	}

	if strings.TrimSpace(payload.Settings.AISettings.CommandProvider) != "" {
		return nil
	}
	provider := normalizeAIProviderName(legacy.DefaultProvider)
	if provider == "" {
		return nil
	}
	if provider == aiProviderOpenAICompatible && legacyAIProviderConfigPresent(legacy.OpenAICompatible) {
		payload.Settings.AISettings.CommandProvider = aiProviderOpenAICompatible + ":" + compatID
		return nil
	}
	payload.Settings.AISettings.CommandProvider = provider
	return nil
}

func legacyAIProviderConfigPresent(cfg AIProviderConfig) bool {
	return strings.TrimSpace(cfg.APIKey) != "" ||
		strings.TrimSpace(cfg.BaseURL) != "" ||
		strings.TrimSpace(cfg.Model) != ""
}

func aiCompatibleIDExists(items []AIProviderProfile, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item.ID) == id {
			return true
		}
	}
	return false
}

func readLegacyProfileTests(rawProfiles map[string]json.RawMessage) (map[string][]metrics.NetworkTestConfig, error) {
	if len(rawProfiles) == 0 {
		return nil, nil
	}

	result := make(map[string][]metrics.NetworkTestConfig)
	for nodeID, rawProfile := range rawProfiles {
		var profile legacyPersistedProfile
		if err := strictUnmarshalJSON(rawProfile, &profile); err != nil {
			return nil, err
		}
		if len(profile.Tests) > 0 {
			result[nodeID] = profile.Tests
		}
	}
	return result, nil
}

func legacyTestCatalogIndex(items []TestCatalogItem) map[string]TestCatalogItem {
	index := make(map[string]TestCatalogItem, len(items))
	for _, item := range items {
		key := legacyTestCatalogKey(item.Name, item.Type, item.Host, item.Port)
		if key == "" {
			continue
		}
		if _, exists := index[key]; !exists {
			index[key] = item
		}
	}
	return index
}

func legacyTestCatalogItem(test metrics.NetworkTestConfig, index map[string]TestCatalogItem) (TestCatalogItem, bool) {
	candidate := TestCatalogItem{
		Name:        strings.TrimSpace(test.Name),
		Type:        strings.ToLower(strings.TrimSpace(test.Type)),
		Host:        strings.TrimSpace(test.Host),
		Port:        test.Port,
		IntervalSec: test.IntervalSec,
	}
	if candidate.Host == "" {
		return TestCatalogItem{}, false
	}
	if candidate.Type != "icmp" && candidate.Type != "tcp" {
		if candidate.Port > 0 {
			candidate.Type = "tcp"
		} else {
			candidate.Type = "icmp"
		}
	}
	if candidate.Type == "icmp" {
		candidate.Port = 0
	}
	if candidate.Name == "" {
		candidate.Name = candidate.Host
	}
	key := legacyTestCatalogKey(candidate.Name, candidate.Type, candidate.Host, candidate.Port)
	if item, ok := index[key]; ok {
		return item, true
	}
	normalized, err := normalizeTestCatalog([]TestCatalogItem{candidate})
	if err != nil || len(normalized) == 0 {
		return TestCatalogItem{}, false
	}
	normalized[0].ID = ""
	return normalized[0], true
}

func legacyTestCatalogKey(name, testType, host string, port int) string {
	kind := strings.ToLower(strings.TrimSpace(testType))
	trimmedHost := strings.TrimSpace(host)
	trimmedName := strings.TrimSpace(name)
	if trimmedHost == "" {
		return ""
	}
	if kind == "icmp" {
		port = 0
	}
	return strings.ToLower(fmt.Sprintf("%s|%s|%s|%d", trimmedName, kind, trimmedHost, port))
}

func writeJSONFileAtomic(path string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return history.WriteFileAtomic(path, data)
}

func cloneProfiles(profiles map[string]*NodeProfile) map[string]*NodeProfile {
	if len(profiles) == 0 {
		return map[string]*NodeProfile{}
	}
	cloned := make(map[string]*NodeProfile, len(profiles))
	for id, profile := range profiles {
		if profile == nil {
			continue
		}
		copyProfile := cloneNodeProfileValue(profile)
		cloned[id] = &copyProfile
	}
	return cloned
}

func cloneNodeProfileValue(profile *NodeProfile) NodeProfile {
	if profile == nil {
		return NodeProfile{}
	}
	copyProfile := *profile
	copyProfile.Tags = slices.Clone(profile.Tags)
	copyProfile.Groups = slices.Clone(profile.Groups)
	copyProfile.TestSelections = slices.Clone(profile.TestSelections)
	copyProfile.AgentUpdate = cloneAgentUpdateInstruction(profile.AgentUpdate)
	if profile.TrafficCounter != nil {
		counter := *profile.TrafficCounter
		copyProfile.TrafficCounter = &counter
	}
	if profile.AlertEnabled != nil {
		value := *profile.AlertEnabled
		copyProfile.AlertEnabled = &value
	}
	return copyProfile
}

func redactProfileRuntimeForTransfer(profile *NodeProfile) {
	if profile == nil {
		return
	}
	profile.AgentAuthToken = ""
	profile.AgentUpdate = nil
	profile.AgentUpdateState = ""
	profile.AgentUpdateTargetVersion = ""
	profile.AgentUpdateMessage = ""
	profile.AgentUpdateLeaseUntil = 0
	profile.AgentUpdateReportedAt = 0
}

func configTransferProfilesFromNodeProfiles(profiles map[string]*NodeProfile) map[string]*ConfigTransferProfile {
	if len(profiles) == 0 {
		return map[string]*ConfigTransferProfile{}
	}
	transfers := make(map[string]*ConfigTransferProfile, len(profiles))
	for nodeID, profile := range profiles {
		if profile == nil {
			transfers[nodeID] = &ConfigTransferProfile{}
			continue
		}
		transfer := ConfigTransferProfile{
			Alias:             profile.Alias,
			Group:             profile.Group,
			Tags:              slices.Clone(profile.Tags),
			Groups:            slices.Clone(profile.Groups),
			Region:            profile.Region,
			DiskType:          profile.DiskType,
			NetSpeedMbps:      profile.NetSpeedMbps,
			ExpireAt:          profile.ExpireAt,
			AutoRenew:         profile.AutoRenew,
			RenewIntervalSec:  profile.RenewIntervalSec,
			TrafficLimitBytes: profile.TrafficLimitBytes,
			TrafficLimitType:  profile.TrafficLimitType,
			TrafficResetDay:   profile.TrafficResetDay,
			TestIntervalSec:   profile.TestIntervalSec,
			TestSelections:    slices.Clone(profile.TestSelections),
		}
		if profile.AlertEnabled != nil {
			value := *profile.AlertEnabled
			transfer.AlertEnabled = &value
		}
		transfers[nodeID] = &transfer
	}
	return transfers
}

func configTransferProfilesToNodeProfiles(profiles map[string]*ConfigTransferProfile) map[string]*NodeProfile {
	if len(profiles) == 0 {
		return map[string]*NodeProfile{}
	}
	nodes := make(map[string]*NodeProfile, len(profiles))
	for nodeID, transfer := range profiles {
		if transfer == nil {
			nodes[nodeID] = &NodeProfile{}
			continue
		}
		profile := NodeProfile{
			Alias:             transfer.Alias,
			Group:             transfer.Group,
			Tags:              slices.Clone(transfer.Tags),
			Groups:            slices.Clone(transfer.Groups),
			Region:            transfer.Region,
			DiskType:          transfer.DiskType,
			NetSpeedMbps:      transfer.NetSpeedMbps,
			ExpireAt:          transfer.ExpireAt,
			AutoRenew:         transfer.AutoRenew,
			RenewIntervalSec:  transfer.RenewIntervalSec,
			TrafficLimitBytes: transfer.TrafficLimitBytes,
			TrafficLimitType:  transfer.TrafficLimitType,
			TrafficResetDay:   transfer.TrafficResetDay,
			TestIntervalSec:   transfer.TestIntervalSec,
			TestSelections:    slices.Clone(transfer.TestSelections),
		}
		if transfer.AlertEnabled != nil {
			value := *transfer.AlertEnabled
			profile.AlertEnabled = &value
		}
		nodes[nodeID] = &profile
	}
	return nodes
}

func cloneOfflineSessions(sessions map[string]OfflineSessionState) map[string]OfflineSessionState {
	if len(sessions) == 0 {
		return map[string]OfflineSessionState{}
	}
	cloned := make(map[string]OfflineSessionState, len(sessions))
	for nodeID, session := range sessions {
		cloned[nodeID] = session
	}
	return cloned
}

func cloneAlertedStates(alerted map[string]AlertedState) map[string]AlertedState {
	if len(alerted) == 0 {
		return map[string]AlertedState{}
	}
	cloned := make(map[string]AlertedState, len(alerted))
	for nodeID, state := range alerted {
		cloned[nodeID] = cloneAlertedState(state)
	}
	return cloned
}

func cloneAlertedState(state AlertedState) AlertedState {
	state.Delivered = cloneNotifyBoolMap(state.Delivered)
	return state
}

// cloneAlertStates 深拷贝 F4 规则评估状态表（key 为 nodeID|ruleID）。
func cloneAlertStates(states map[string]RuleAlertState) map[string]RuleAlertState {
	if len(states) == 0 {
		return map[string]RuleAlertState{}
	}
	cloned := make(map[string]RuleAlertState, len(states))
	for key, state := range states {
		cloned[key] = cloneRuleAlertState(state)
	}
	return cloned
}

func cloneRuleAlertState(state RuleAlertState) RuleAlertState {
	state.Delivered = cloneNotifyBoolMap(state.Delivered)
	state.SentLeadDays = slices.Clone(state.SentLeadDays)
	state.ViolatedRatio = cloneFloat64Ptr(state.ViolatedRatio)
	if state.RecoveryValue != nil {
		value := *state.RecoveryValue
		state.RecoveryValue = &value
	}
	if state.RecoveryDurationSec != nil {
		duration := *state.RecoveryDurationSec
		state.RecoveryDurationSec = &duration
	}
	return state
}

func initSettings(cfg Config) (Settings, error) {
	path := strings.TrimSpace(cfg.AdminPath)
	if path == "" {
		token, err := randomToken(adminTokenLength)
		if err != nil {
			return Settings{}, err
		}
		path = "/" + token
	} else {
		if normalized, err := normalizeAdminPath(path); err == nil {
			path = normalized
		} else {
			token, err := randomToken(adminTokenLength)
			if err != nil {
				return Settings{}, err
			}
			path = "/" + token
		}
	}

	user := strings.TrimSpace(cfg.AdminUser)
	if user == "" {
		token, err := randomToken(adminTokenLength)
		if err != nil {
			return Settings{}, err
		}
		user = token
	}
	passHash, passPlain, err := buildAdminPassword(cfg.AdminPass)
	if err != nil {
		return Settings{}, err
	}
	tokenSalt, err := randomToken(adminTokenLength)
	if err != nil {
		return Settings{}, err
	}

	settings := Settings{
		AdminPath:            path,
		AdminUser:            user,
		AdminPass:            passHash,
		AdminPassPlain:       passPlain,
		TokenSalt:            tokenSalt,
		AuthToken:            cfg.JWTSecret,
		AgentToken:           cfg.AgentToken,
		AgentEndpoint:        "",
		SiteTitle:            defaultSiteTitle,
		SiteIcon:             "",
		SiteBackgroundImage:  "",
		HomeTitle:            defaultHomeTitle,
		HomeSubtitle:         defaultHomeSub,
		Locale:               defaultLocale,
		AlertWebhook:         "",
		AlertOfflineSec:      defaultAlertOfflineSec,
		AlertTelegramToken:   "",
		AlertTelegramUserIDs: []int64{},
		LoginFailLimit:       defaultLoginFailLimit,
		LoginFailWindowSec:   defaultLoginFailWindow,
		LoginLockSec:         defaultLoginLockSec,
		AdminAuth:            defaultAdminAuthSettings(),
		AISettings:           defaultAISettings(),
		Groups:               []string{},
		GroupTree:            []GroupNode{},
		TestCatalog:          []TestCatalogItem{},
		ResourceHistoryDays:  defaultResourceHistoryDays,
	}
	ensureOfflineAlertRule(&settings)
	return settings, nil
}

func buildAdminPassword(input string) (string, string, error) {
	pass := strings.TrimSpace(input)
	generated := pass == ""
	if generated {
		token, err := randomToken(adminTokenLength)
		if err != nil {
			return "", "", err
		}
		pass = token
	}
	hash, err := hashPassword(pass)
	if err != nil {
		return "", "", fmt.Errorf("hash admin password: %w", err)
	}
	if generated {
		return hash, pass, nil
	}
	return hash, "", nil
}

func mergeSettings(existing, fallback Settings) (Settings, error) {
	mergeString := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	mergeInt64 := func(dst *int64, src int64) {
		if *dst <= 0 {
			*dst = src
		}
		if *dst > maxDurationSettingSec {
			*dst = maxDurationSettingSec
		}
	}
	mergeInt := func(dst *int, src int) {
		if *dst == 0 {
			*dst = src
		}
	}

	mergeString(&existing.AdminPath, fallback.AdminPath)
	mergeString(&existing.AdminUser, fallback.AdminUser)
	mergeString(&existing.AdminPass, fallback.AdminPass)
	mergeString(&existing.TokenSalt, fallback.TokenSalt)

	if existing.AgentToken == "" && existing.AuthToken != "" {
		existing.AgentToken = existing.AuthToken
		if fallback.AuthToken != "" && fallback.AuthToken != existing.AuthToken {
			existing.AuthToken = fallback.AuthToken
		}
	}
	mergeString(&existing.AuthToken, fallback.AuthToken)
	mergeString(&existing.AgentToken, fallback.AgentToken)
	mergeString(&existing.AgentEndpoint, fallback.AgentEndpoint)
	mergeString(&existing.SiteTitle, fallback.SiteTitle)
	mergeString(&existing.HomeTitle, fallback.HomeTitle)
	mergeString(&existing.HomeSubtitle, fallback.HomeSubtitle)
	mergeString(&existing.SiteIcon, fallback.SiteIcon)
	mergeString(&existing.Locale, fallback.Locale)
	existing.Locale = normalizeLocale(existing.Locale)
	mergeString(&existing.AlertTelegramToken, fallback.AlertTelegramToken)

	mergeInt64(&existing.AlertOfflineSec, fallback.AlertOfflineSec)
	mergeInt64(&existing.LoginFailWindowSec, fallback.LoginFailWindowSec)
	mergeInt64(&existing.LoginLockSec, fallback.LoginLockSec)
	mergeInt(&existing.LoginFailLimit, fallback.LoginFailLimit)
	existing.AdminAuth = mergeAdminAuthSettings(existing.AdminAuth, fallback.AdminAuth)

	if len(existing.AlertTelegramUserIDs) == 0 && existing.AlertTelegramUserID > 0 {
		existing.AlertTelegramUserIDs = []int64{existing.AlertTelegramUserID}
	}
	existing.AlertTelegramUserID = 0
	if len(existing.AlertTelegramUserIDs) > 0 {
		existing.AlertTelegramUserIDs = normalizeTelegramUserIDs(existing.AlertTelegramUserIDs)
	}
	if strings.TrimSpace(existing.AlertTelegramToken) == "" || len(existing.AlertTelegramUserIDs) == 0 {
		existing.AlertTelegramToken = ""
		existing.AlertTelegramUserIDs = []int64{}
	}

	aiSettings, err := mergeAISettings(existing.AISettings, fallback.AISettings)
	if err != nil {
		return Settings{}, err
	}
	existing.AISettings = aiSettings

	if existing.Groups == nil {
		existing.Groups = fallback.Groups
	}
	if len(existing.GroupTree) == 0 {
		existing.GroupTree = buildGroupTree(existing.Groups)
	}
	existing.Groups = flattenGroupTree(existing.GroupTree)

	if existing.TestCatalog == nil {
		existing.TestCatalog = fallback.TestCatalog
	}
	existing.ResourceHistoryDays = normalizeResourceHistoryDays(existing.ResourceHistoryDays)

	// F5：加载迁移——NotifyChannels 为空时由旧告警字段合成迁移渠道；随后旧字段
	// 始终从启用渠道回填，保证两套表示一致（Telegram Bot 轮询读 TelegramSettings()）。
	migrateLegacyNotifyChannels(&existing)
	syncLegacyAlertFieldsFromChannels(&existing)

	// F4：加载迁移——保证含且仅含一条 metric=offline 的内置规则，且其 duration_sec
	// 镜像 AlertOfflineSec（旧 state.json 没有任何规则时合成一条）。
	ensureOfflineAlertRule(&existing)

	return existing, nil
}

// migrateLegacyNotifyChannels 在 NotifyChannels 为空时由旧告警字段合成迁移渠道：
// AlertWebhook → {ID:"feishu"}；AlertTelegramToken+AlertTelegramUserIDs → {ID:"telegram"}。
func migrateLegacyNotifyChannels(settings *Settings) {
	if len(settings.NotifyChannels) > 0 {
		return
	}
	var channels []NotifyChannel
	if webhook := strings.TrimSpace(settings.AlertWebhook); webhook != "" {
		channels = append(channels, NotifyChannel{
			ID:      legacyFeishuChannelID,
			Type:    notifyChannelTypeFeishu,
			Name:    "飞书",
			Enabled: true,
			Secrets: map[string]string{"webhook": webhook},
		})
	}
	if token := strings.TrimSpace(settings.AlertTelegramToken); token != "" && len(settings.AlertTelegramUserIDs) > 0 {
		channels = append(channels, NotifyChannel{
			ID:      legacyTelegramChannelID,
			Type:    notifyChannelTypeTelegram,
			Name:    "Telegram",
			Enabled: true,
			Config:  map[string]string{"chat_ids": joinTelegramChatIDs(settings.AlertTelegramUserIDs)},
			Secrets: map[string]string{"bot_token": token},
		})
	}
	if len(channels) > 0 {
		settings.NotifyChannels = channels
	}
}

// syncLegacyAlertFieldsFromChannels 是渠道 → 旧字段方向的同步：旧字段始终反映
// 第一个启用渠道的取值（feishu 取 webhook；telegram 取 bot_token + chat_ids），
// Telegram Bot 轮询因此仍能通过 TelegramSettings() 读到第一个启用 telegram 渠道。
// 没有满足条件的启用渠道时旧字段清空。
func syncLegacyAlertFieldsFromChannels(settings *Settings) {
	settings.AlertWebhook = ""
	for _, channel := range settings.NotifyChannels {
		if !channel.Enabled || channel.Type != notifyChannelTypeFeishu {
			continue
		}
		if webhook := strings.TrimSpace(channel.Secrets["webhook"]); webhook != "" {
			settings.AlertWebhook = webhook
			break
		}
	}
	settings.AlertTelegramToken = ""
	settings.AlertTelegramUserIDs = nil
	for _, channel := range settings.NotifyChannels {
		if !channel.Enabled || channel.Type != notifyChannelTypeTelegram {
			continue
		}
		token := strings.TrimSpace(channel.Secrets["bot_token"])
		// 旧字段 AlertTelegramUserIDs 是 Bot 命令授权名单，只保留正的用户 ID：
		// 负数群/频道 chat_id 不得进入授权范围。
		userIDs := normalizeTelegramUserIDs(parseNotifyChatIDs(channel.Config["chat_ids"]))
		if token == "" || len(userIDs) == 0 {
			continue
		}
		settings.AlertTelegramToken = token
		settings.AlertTelegramUserIDs = userIDs
		break
	}
}

// upsertLegacyFeishuChannel 是旧字段 → 渠道方向的同步（更新设置时使用）：
// webhook 非空时写入/更新 ID 为 "feishu" 的启用渠道；为空时移除该迁移渠道。
func upsertLegacyFeishuChannel(settings *Settings, webhook string) {
	webhook = strings.TrimSpace(webhook)
	for i := range settings.NotifyChannels {
		if settings.NotifyChannels[i].ID != legacyFeishuChannelID {
			continue
		}
		if webhook == "" {
			settings.NotifyChannels = append(settings.NotifyChannels[:i], settings.NotifyChannels[i+1:]...)
			return
		}
		settings.NotifyChannels[i].Type = notifyChannelTypeFeishu
		settings.NotifyChannels[i].Enabled = true
		setNotifyChannelSecret(&settings.NotifyChannels[i], "webhook", webhook)
		return
	}
	if webhook == "" {
		return
	}
	settings.NotifyChannels = append(settings.NotifyChannels, NotifyChannel{
		ID:      legacyFeishuChannelID,
		Type:    notifyChannelTypeFeishu,
		Name:    "飞书",
		Enabled: true,
		Secrets: map[string]string{"webhook": webhook},
	})
}

// upsertLegacyTelegramChannel 同上：token 与用户 ID 齐备时写入/更新 ID 为
// "telegram" 的启用渠道，两者皆空时移除该迁移渠道。
func upsertLegacyTelegramChannel(settings *Settings, token string, userIDs []int64) {
	token = strings.TrimSpace(token)
	ids := normalizeTelegramUserIDs(userIDs)
	bothSet := token != "" && len(ids) > 0
	for i := range settings.NotifyChannels {
		if settings.NotifyChannels[i].ID != legacyTelegramChannelID {
			continue
		}
		if !bothSet {
			settings.NotifyChannels = append(settings.NotifyChannels[:i], settings.NotifyChannels[i+1:]...)
			return
		}
		settings.NotifyChannels[i].Type = notifyChannelTypeTelegram
		settings.NotifyChannels[i].Enabled = true
		setNotifyChannelSecret(&settings.NotifyChannels[i], "bot_token", token)
		setNotifyChannelConfig(&settings.NotifyChannels[i], "chat_ids", joinTelegramChatIDs(ids))
		return
	}
	if !bothSet {
		return
	}
	settings.NotifyChannels = append(settings.NotifyChannels, NotifyChannel{
		ID:      legacyTelegramChannelID,
		Type:    notifyChannelTypeTelegram,
		Name:    "Telegram",
		Enabled: true,
		Config:  map[string]string{"chat_ids": joinTelegramChatIDs(ids)},
		Secrets: map[string]string{"bot_token": token},
	})
}

func setNotifyChannelSecret(channel *NotifyChannel, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		delete(channel.Secrets, key)
		return
	}
	if channel.Secrets == nil {
		channel.Secrets = make(map[string]string)
	}
	channel.Secrets[key] = value
}

func setNotifyChannelConfig(channel *NotifyChannel, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		delete(channel.Config, key)
		return
	}
	if channel.Config == nil {
		channel.Config = make(map[string]string)
	}
	channel.Config[key] = value
}

func normalizeNotifyChannelType(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := notifyChannelTypes[value]; !ok {
		return ""
	}
	return value
}

// normalizeNotifyChannels 规范化渠道列表：类型白名单、ID 去重（空/冲突时生成
// "c_"+随机串）、字符串修剪、空值丢弃。SecretsSet 与 SecretsClear 均为请求载体
// 专属字段（后者 B-08 已在合并阶段生效），落盘前在此丢弃。
func normalizeNotifyChannels(channels []NotifyChannel) ([]NotifyChannel, error) {
	if len(channels) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(channels))
	normalized := make([]NotifyChannel, 0, len(channels))
	for _, channel := range channels {
		channelType := normalizeNotifyChannelType(channel.Type)
		if channelType == "" {
			return nil, fmt.Errorf("不支持的通知渠道类型: %q", strings.TrimSpace(channel.Type))
		}
		id := strings.TrimSpace(channel.ID)
		for {
			if id != "" {
				if _, ok := seen[id]; !ok {
					break
				}
			}
			generatedID, err := randomToken(10)
			if err != nil {
				return nil, err
			}
			id = "c_" + generatedID
		}
		seen[id] = struct{}{}
		item := NotifyChannel{
			ID:       id,
			Type:     channelType,
			Name:     strings.TrimSpace(channel.Name),
			Enabled:  channel.Enabled,
			Config:   normalizeNotifyStringMap(channel.Config, false),
			Secrets:  normalizeNotifyStringMap(channel.Secrets, true),
			LastTest: channel.LastTest,
		}
		if item.Name == "" {
			item.Name = channelType
		}
		normalized = append(normalized, item)
	}
	return normalized, nil
}

// normalizeNotifyStringMap 修剪键值并丢弃空项（键序稳定，保证结果与 map 遍历
// 顺序无关；secret 参数保留以区分调用意图，两侧均为 TrimSpace 语义）。
func normalizeNotifyStringMap(raw map[string]string, secret bool) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(raw))
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		value := strings.TrimSpace(raw[key])
		if trimmedKey == "" || value == "" {
			continue
		}
		normalized[trimmedKey] = value
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func cloneNotifyChannel(channel NotifyChannel) NotifyChannel {
	channel.Config = cloneNotifyStringMap(channel.Config)
	channel.Secrets = cloneNotifyStringMap(channel.Secrets)
	channel.SecretsSet = cloneNotifyBoolMap(channel.SecretsSet)
	if channel.LastTest != nil {
		lastTest := *channel.LastTest
		channel.LastTest = &lastTest
	}
	return channel
}

func cloneNotifyChannels(channels []NotifyChannel) []NotifyChannel {
	if len(channels) == 0 {
		return nil
	}
	cloned := make([]NotifyChannel, len(channels))
	for i := range channels {
		cloned[i] = cloneNotifyChannel(channels[i])
	}
	return cloned
}

func cloneNotifyStringMap(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(raw))
	for key, value := range raw {
		cloned[key] = value
	}
	return cloned
}

func cloneNotifyBoolMap(raw map[string]bool) map[string]bool {
	if len(raw) == 0 {
		return nil
	}
	cloned := make(map[string]bool, len(raw))
	for key, value := range raw {
		cloned[key] = value
	}
	return cloned
}

// cloneFloat64Ptr 复制可选数值快照（nil 保持 nil）。
func cloneFloat64Ptr(raw *float64) *float64 {
	if raw == nil {
		return nil
	}
	value := *raw
	return &value
}

// notifyChannelsForView 生成视图形态：Secrets 置空，改以 SecretsSet 标记已配置；
// SecretsClear 仅请求载体（B-08），返回前同样置空。
func notifyChannelsForView(channels []NotifyChannel) []NotifyChannel {
	if len(channels) == 0 {
		return nil
	}
	view := make([]NotifyChannel, 0, len(channels))
	for _, channel := range channels {
		item := cloneNotifyChannel(channel)
		if len(item.Secrets) > 0 {
			secretsSet := make(map[string]bool, len(item.Secrets))
			for key, value := range item.Secrets {
				secretsSet[key] = strings.TrimSpace(value) != ""
			}
			item.SecretsSet = secretsSet
		}
		item.Secrets = nil
		item.SecretsClear = nil
		view = append(view, item)
	}
	return view
}

// mergeNotifyChannelSecrets 在保存时按 ID 匹配已有渠道：某个 secret 为空就保留旧值
// （与 OAuth Client Secret 的掩码保存语义一致）；secrets_clear 中的 key（B-08/D-04）
// 例外——不从旧值补齐，并从提交值中删除，实现「清除可选密钥」。
func mergeNotifyChannelSecrets(incoming, existing []NotifyChannel) []NotifyChannel {
	if len(incoming) == 0 {
		return cloneNotifyChannels(incoming)
	}
	existingSecrets := make(map[string]map[string]string, len(existing))
	for _, channel := range existing {
		existingSecrets[channel.ID] = channel.Secrets
	}
	merged := make([]NotifyChannel, len(incoming))
	for i, channel := range incoming {
		item := cloneNotifyChannel(channel)
		cleared := make(map[string]struct{}, len(item.SecretsClear))
		for _, key := range item.SecretsClear {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			cleared[key] = struct{}{}
			delete(item.Secrets, key)
		}
		if stored, ok := existingSecrets[item.ID]; ok {
			for key, value := range stored {
				if _, skip := cleared[key]; skip {
					continue
				}
				if strings.TrimSpace(item.Secrets[key]) == "" && strings.TrimSpace(value) != "" {
					if item.Secrets == nil {
						item.Secrets = make(map[string]string)
					}
					item.Secrets[key] = value
				}
			}
		}
		merged[i] = item
	}
	return merged
}

// preserveChannelLastTest 在保存时沿用已记录的测试结果：渠道列表的保存不改动
// LastTest，只有测试推送接口写入。请求回传相同值时结果不变。
func preserveChannelLastTest(incoming, existing []NotifyChannel) []NotifyChannel {
	if len(incoming) == 0 || len(existing) == 0 {
		return incoming
	}
	existingLastTest := make(map[string]*ChannelTestResult, len(existing))
	for _, channel := range existing {
		if channel.LastTest == nil {
			continue
		}
		lastTest := *channel.LastTest
		existingLastTest[channel.ID] = &lastTest
	}
	if len(existingLastTest) == 0 {
		return incoming
	}
	for i := range incoming {
		if incoming[i].LastTest != nil {
			continue
		}
		if lastTest, ok := existingLastTest[incoming[i].ID]; ok {
			incoming[i].LastTest = lastTest
		}
	}
	return incoming
}

// redactNotifyChannelsForExport 在导出时清空 Secrets/SecretsSet，以及 Config 中的
// chat_ids / to（收件人列表视同敏感信息）。
func redactNotifyChannelsForExport(channels []NotifyChannel) []NotifyChannel {
	if len(channels) == 0 {
		return nil
	}
	redacted := make([]NotifyChannel, len(channels))
	for i, channel := range channels {
		item := cloneNotifyChannel(channel)
		item.Secrets = nil
		item.SecretsSet = nil
		item.Config = redactNotifyChannelConfigForExport(item.Config)
		redacted[i] = item
	}
	return redacted
}

func redactNotifyChannelConfigForExport(config map[string]string) map[string]string {
	if len(config) == 0 {
		return nil
	}
	redacted := make(map[string]string, len(config))
	for key, value := range config {
		if key == "chat_ids" || key == "to" {
			continue
		}
		redacted[key] = value
	}
	if len(redacted) == 0 {
		return nil
	}
	return redacted
}

// preserveRedactedNotifyChannels 在导入时按 ID 合并保留：导出文件中 Secrets 与
// chat_ids / to 均已脱敏为空，为空时沿用现有配置，避免导入清掉收件人与密钥。
func preserveRedactedNotifyChannels(incoming, existing []NotifyChannel) []NotifyChannel {
	if len(incoming) == 0 {
		return cloneNotifyChannels(incoming)
	}
	existingByID := make(map[string]NotifyChannel, len(existing))
	for _, channel := range existing {
		existingByID[channel.ID] = channel
	}
	merged := make([]NotifyChannel, len(incoming))
	for i, channel := range incoming {
		item := cloneNotifyChannel(channel)
		if stored, ok := existingByID[item.ID]; ok {
			for key, value := range stored.Secrets {
				if strings.TrimSpace(item.Secrets[key]) == "" && strings.TrimSpace(value) != "" {
					if item.Secrets == nil {
						item.Secrets = make(map[string]string)
					}
					item.Secrets[key] = value
				}
			}
			for _, key := range []string{"chat_ids", "to"} {
				if strings.TrimSpace(item.Config[key]) == "" && strings.TrimSpace(stored.Config[key]) != "" {
					if item.Config == nil {
						item.Config = make(map[string]string)
					}
					item.Config[key] = stored.Config[key]
				}
			}
		}
		merged[i] = item
	}
	return merged
}

// enabledNotifyChannels 返回当前应投递的启用渠道（深拷贝，调用方持有锁外使用）。
// 渠道列表为空时由旧告警字段即时合成迁移渠道：未落盘迁移的存量配置（以及直接
// 构造 Store 的旧测试）行为保持不变。
func enabledNotifyChannels(settings Settings) []NotifyChannel {
	if len(settings.NotifyChannels) == 0 {
		synthetic := settings
		migrateLegacyNotifyChannels(&synthetic)
		settings.NotifyChannels = synthetic.NotifyChannels
	}
	var enabled []NotifyChannel
	for _, channel := range settings.NotifyChannels {
		if !channel.Enabled {
			continue
		}
		enabled = append(enabled, cloneNotifyChannel(channel))
	}
	return enabled
}

func joinTelegramChatIDs(ids []int64) string {
	normalized := normalizeTelegramUserIDs(ids)
	if len(normalized) == 0 {
		return ""
	}
	parts := make([]string, 0, len(normalized))
	for _, id := range normalized {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// parseNotifyChatIDs 解析逗号分隔的 chat_ids 配置（容忍空白与重复）：接受非零
// 有符号 int64——Telegram 群/超级群/频道的 chat_id 为负数，与私聊用户 ID（正数）
// 共用该配置；0、空项、非整数与溢出项过滤，去重后保留首次出现顺序。
func parseNotifyChatIDs(raw string) []int64 {
	seen := make(map[int64]struct{})
	var ids []int64
	for _, part := range strings.Split(raw, ",") {
		value, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ids = append(ids, value)
	}
	return ids
}

func normalizeAdminPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") {
		return "", errors.New("admin path invalid")
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" {
		return "", errors.New("admin path invalid")
	}
	if strings.ContainsAny(trimmed, "?#") || strings.ContainsFunc(trimmed, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return "", errors.New("admin path invalid")
	}
	for i := 0; i < 3; i++ {
		decoded, err := url.PathUnescape(trimmed)
		if err != nil {
			return "", errors.New("admin path invalid")
		}
		if decoded == trimmed {
			break
		}
		trimmed = decoded
	}
	if strings.ContainsAny(trimmed, "?#") || strings.ContainsFunc(trimmed, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return "", errors.New("admin path invalid")
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	segments := strings.Split(trimmed, "/")
	normalizedSegments := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if segment == "." || segment == ".." || strings.ContainsAny(segment, ":\\") || strings.ContainsFunc(segment, func(r rune) bool {
			return r < 0x20 || r == 0x7f
		}) {
			return "", errors.New("admin path invalid")
		}
		normalizedSegments = append(normalizedSegments, segment)
	}
	if len(normalizedSegments) == 0 {
		return "", errors.New("admin path invalid")
	}
	trimmed = "/" + strings.Join(normalizedSegments, "/")
	for _, prefix := range []string{"/api", "/assets", "/ws"} {
		if trimmed == prefix || strings.HasPrefix(trimmed, prefix+"/") {
			return "", fmt.Errorf("admin path conflicts with %s", prefix)
		}
	}
	return trimmed, nil
}

func randomToken(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	limit := byte(256 - 256%len(tokenAlphabet))
	out := make([]byte, 0, length)
	buf := make([]byte, length)
	for len(out) < length {
		if _, err := io.ReadFull(secureRandomReader, buf); err != nil {
			return "", fmt.Errorf("crypto random failed: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, tokenAlphabet[int(b)%len(tokenAlphabet)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}

func normalizeUniqueStrings(values []string, skip func(string) bool) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || (skip != nil && skip(value)) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func normalizeGroups(groups []string) []string {
	return normalizeUniqueStrings(groups, func(value string) bool {
		_, reserved := reservedGroupNames[value]
		return reserved
	})
}

func normalizeTagValues(tags []string) []string {
	return normalizeUniqueStrings(tags, nil)
}

var reservedGroupNames = map[string]struct{}{
	"全部":  {},
	"ALL": {},
	"C&R": {},
}

func normalizeGroupName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if _, reserved := reservedGroupNames[trimmed]; reserved {
		return ""
	}
	return trimmed
}

func canonicalGroupSelection(group, tag string) string {
	if tag == "" {
		return group
	}
	return group + ":" + tag
}

func parseGroupSelection(value string) (string, string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", ""
	}
	if _, reserved := reservedGroupNames[raw]; reserved {
		return "", ""
	}
	group := raw
	tag := ""
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		group = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			tag = strings.TrimSpace(parts[1])
		}
	} else if strings.Contains(raw, "/") {
		parts := strings.SplitN(raw, "/", 2)
		group = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			tag = strings.TrimSpace(parts[1])
		}
	}
	group = normalizeGroupName(group)
	if group == "" {
		return "", ""
	}
	return group, tag
}

func groupSelectionSets(settings Settings) (map[string]struct{}, map[string]struct{}, bool) {
	groupNames := make(map[string]struct{})
	tagKeys := make(map[string]struct{})
	for _, node := range settings.GroupTree {
		groupNames[node.Name] = struct{}{}
		for _, tag := range node.Children {
			tagKeys[node.Name+"\x00"+tag.Name] = struct{}{}
		}
	}
	for _, name := range settings.Groups {
		groupNames[name] = struct{}{}
	}
	return groupNames, tagKeys, len(settings.GroupTree) > 0
}

func filterGroupSelections(selections []string, groupNames, tagKeys map[string]struct{}, treeMode bool) []string {
	kept := make([]string, 0, len(selections))
	for _, selection := range selections {
		group, tag := parseGroupSelection(selection)
		if group == "" {
			continue
		}
		if _, ok := groupNames[group]; !ok {
			continue
		}
		if tag != "" && treeMode {
			if _, tagOK := tagKeys[group+"\x00"+tag]; !tagOK {
				continue
			}
		}
		kept = append(kept, selection)
	}
	return kept
}

func normalizeGroupSelections(selections []string) []string {
	if len(selections) == 0 {
		return nil
	}
	type selectionEntry struct {
		group string
		tag   string
	}

	seen := make(map[string]struct{})
	tagsByGroup := make(map[string]map[string]struct{})
	entries := make([]selectionEntry, 0, len(selections))

	for _, raw := range selections {
		group, tag := parseGroupSelection(raw)
		if group == "" {
			continue
		}
		if tag != "" {
			if tagsByGroup[group] == nil {
				tagsByGroup[group] = make(map[string]struct{})
			}
			if _, ok := tagsByGroup[group][tag]; ok {
				continue
			}
			tagsByGroup[group][tag] = struct{}{}
			entry := canonicalGroupSelection(group, tag)
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			entries = append(entries, selectionEntry{group: group, tag: tag})
			continue
		}
		entry := canonicalGroupSelection(group, "")
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, selectionEntry{group: group})
	}

	if len(tagsByGroup) == 0 {
		normalized := make([]string, 0, len(entries))
		for _, entry := range entries {
			normalized = append(normalized, canonicalGroupSelection(entry.group, entry.tag))
		}
		return normalized
	}
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.tag == "" && len(tagsByGroup[entry.group]) > 0 {
			continue
		}
		filtered = append(filtered, canonicalGroupSelection(entry.group, entry.tag))
	}
	return filtered
}

func selectionsFromGroupTags(group string, tags []string) []string {
	group = normalizeGroupName(group)
	if group == "" {
		return nil
	}
	normalizedTags := normalizeTagValues(tags)
	if len(normalizedTags) == 0 {
		return []string{group}
	}
	result := make([]string, 0, len(normalizedTags))
	for _, tag := range normalizedTags {
		result = append(result, canonicalGroupSelection(group, tag))
	}
	return result
}

func primaryGroupTagsFromNormalizedSelections(selections []string) (string, []string, bool) {
	if len(selections) == 0 {
		return "", nil, true
	}

	seenEntries := make(map[string]struct{}, len(selections))
	standaloneGroups := make(map[string]struct{}, len(selections))
	tagsSeen := make(map[string]map[string]struct{})
	tagsByGroup := make(map[string][]string)
	primary := ""

	for _, value := range selections {
		raw := strings.TrimSpace(value)
		if raw == "" || raw == "全部" {
			return "", nil, false
		}

		group, tag := parseGroupSelection(raw)
		if group == "" {
			return "", nil, false
		}

		canonical := canonicalGroupSelection(group, tag)
		if raw != canonical {
			return "", nil, false
		}
		if _, ok := seenEntries[canonical]; ok {
			return "", nil, false
		}
		seenEntries[canonical] = struct{}{}

		if primary == "" {
			primary = group
		}

		if tag == "" {
			if _, ok := tagsSeen[group]; ok {
				return "", nil, false
			}
			standaloneGroups[group] = struct{}{}
			continue
		}
		if _, ok := standaloneGroups[group]; ok {
			return "", nil, false
		}
		if tagsSeen[group] == nil {
			tagsSeen[group] = make(map[string]struct{})
		}
		if _, ok := tagsSeen[group][tag]; ok {
			return "", nil, false
		}
		tagsSeen[group][tag] = struct{}{}
		tagsByGroup[group] = append(tagsByGroup[group], tag)
	}

	return primary, tagsByGroup[primary], true
}

func primaryGroupTagsFromSelections(selections []string) (string, []string) {
	if len(selections) == 0 {
		return "", nil
	}

	if group, tags, ok := primaryGroupTagsFromNormalizedSelections(selections); ok {
		return group, tags
	}

	normalized := normalizeGroupSelections(selections)
	if len(normalized) == 0 {
		return "", nil
	}
	group, tags, _ := primaryGroupTagsFromNormalizedSelections(normalized)
	return group, tags
}

func isValidGroupName(name string) bool {
	return !strings.ContainsAny(name, ":/")
}

func normalizeGroupTree(nodes []GroupNode) []GroupNode {
	seen := make(map[string]struct{})
	normalized := make([]GroupNode, 0, len(nodes))
	for _, node := range nodes {
		name := normalizeGroupName(node.Name)
		if name == "" || !isValidGroupName(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		children := normalizeTagNodes(node.Children)
		normalized = append(normalized, GroupNode{
			Name:     name,
			Children: children,
		})
	}
	return normalized
}

func normalizeTagNodes(nodes []GroupNode) []GroupNode {
	seen := make(map[string]struct{})
	var tags []GroupNode
	var walk func(items []GroupNode)
	walk = func(items []GroupNode) {
		for _, item := range items {
			name := normalizeGroupName(item.Name)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				tags = append(tags, GroupNode{Name: name})
			}
			if len(item.Children) > 0 {
				walk(item.Children)
			}
		}
	}
	walk(nodes)
	return tags
}

func flattenGroupTree(nodes []GroupNode) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range nodes {
		name := normalizeGroupName(item.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func buildGroupTree(groups []string) []GroupNode {
	var root []GroupNode
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" || trimmed == "全部" {
			continue
		}
		parts := strings.Split(trimmed, "/")
		groupName := normalizeGroupName(parts[0])
		if groupName == "" {
			continue
		}
		index := -1
		for i := range root {
			if root[i].Name == groupName {
				index = i
				break
			}
		}
		if index == -1 {
			root = append(root, GroupNode{Name: groupName})
			index = len(root) - 1
		}
		if len(parts) > 1 {
			tag := normalizeGroupName(strings.Join(parts[1:], "/"))
			if tag != "" {
				root[index].Children = append(root[index].Children, GroupNode{Name: tag})
			}
		}
	}
	return normalizeGroupTree(root)
}

func normalizeTestCatalog(items []TestCatalogItem) ([]TestCatalogItem, error) {
	if len(items) > maxTestCatalogItems {
		return nil, fmt.Errorf("测试节点数量不能超过 %d 个", maxTestCatalogItems)
	}
	seen := make(map[string]struct{})
	normalized := make([]TestCatalogItem, 0, len(items))
	for _, item := range items {
		host := strings.TrimSpace(item.Host)
		if host == "" {
			return nil, errors.New("测试节点地址不能为空")
		}
		if hasUnsafeText(host) {
			return nil, errors.New("测试节点地址包含非法字符")
		}
		if !isValidTestHost(host) {
			return nil, errors.New("测试节点地址格式不正确")
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, errors.New("测试节点名称不能为空")
		}
		if hasUnsafeText(name) {
			return nil, errors.New("测试节点名称包含非法字符")
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "icmp" && itemType != "tcp" {
			if item.Port > 0 {
				itemType = "tcp"
			} else {
				itemType = "icmp"
			}
		}
		port := item.Port
		if itemType == "icmp" {
			port = 0
		} else if port <= 0 || port > 65535 {
			return nil, errors.New("TCP 端口需为 1-65535")
		}
		// F2：icmp 与 tcp 一样保留 interval（0 表示持续探测），统一钳到 0-3600。
		interval := item.IntervalSec
		if interval < 0 {
			interval = 0
		}
		if interval > 3600 {
			interval = 3600
		}
		id := strings.TrimSpace(item.ID)
		if id == "" {
			generatedID, err := randomToken(10)
			if err != nil {
				return nil, err
			}
			id = generatedID
		}
		for {
			if _, ok := seen[id]; !ok {
				break
			}
			generatedID, err := randomToken(10)
			if err != nil {
				return nil, err
			}
			id = generatedID
		}
		seen[id] = struct{}{}
		// O-01：Scope != nil 且 Mode 非空时经 normalizeAlertScope 规范化；
		// Mode == "" 视为 nil（不下发）；非法 mode 拒绝保存。
		var scope *AlertScope
		if item.Scope != nil && strings.TrimSpace(item.Scope.Mode) != "" {
			normalizedScope, err := normalizeAlertScope(*item.Scope)
			if err != nil {
				return nil, err
			}
			scope = &normalizedScope
		}
		normalized = append(normalized, TestCatalogItem{
			ID:          id,
			Name:        name,
			Type:        itemType,
			Host:        host,
			Port:        port,
			IntervalSec: interval,
			Scope:       scope,
		})
	}
	return normalized, nil
}

func hasUnsafeText(value string) bool {
	return strings.ContainsAny(value, "<>\"'`")
}

func isValidTestHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") || strings.Contains(host, " ") {
		return false
	}
	if isAmbiguousIPv4LiteralHost(host) {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return isValidHostname(host)
}

func isAmbiguousIPv4LiteralHost(host string) bool {
	value := strings.TrimRight(strings.Trim(strings.ToLower(host), "[]"), ".")
	if value == "" || strings.Contains(value, ":") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) > 4 {
		return false
	}
	allIPv4LiteralParts := true
	for _, part := range parts {
		if !isIPv4LiteralPart(part) {
			allIPv4LiteralParts = false
			break
		}
	}
	if !allIPv4LiteralParts {
		return false
	}
	if len(parts) != 4 {
		return true
	}
	for _, part := range parts {
		if len(part) > 1 && strings.HasPrefix(part, "0") {
			return true
		}
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 || strconv.Itoa(num) != part {
			return true
		}
	}
	return false
}

func isIPv4LiteralPart(part string) bool {
	if part == "" {
		return false
	}
	if strings.HasPrefix(part, "0x") {
		if len(part) == 2 {
			return false
		}
		for _, r := range part[2:] {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
				continue
			}
			return false
		}
		return true
	}
	for _, r := range part {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isValidHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
