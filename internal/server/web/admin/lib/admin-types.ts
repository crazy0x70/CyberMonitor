export interface ApiErrorPayload {
  error?: string;
}

export interface LoginResponse {
  expires_at: number;
}

export interface LoginConfigResponse {
  turnstile_enabled?: boolean;
  turnstile_site_key?: string;
  password_login_enabled?: boolean;
  oauth_providers?: OAuthLoginProvider[];
}

export interface OAuthLoginProvider {
  id: string;
  display_name: string;
  type: string;
}

interface OAuth2ProviderSettings {
  enabled?: boolean;
  display_name?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  allowed_logins?: string[];
  allowed_emails?: string[];
  allowed_email_domains?: string[];
  require_verified_email?: boolean;
}

interface OIDCProviderSettings {
  enabled?: boolean;
  display_name?: string;
  issuer_url?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  allowed_subjects?: string[];
  allowed_emails?: string[];
  allowed_email_domains?: string[];
  require_email_verified?: boolean;
}

export interface AdminAuthSettings {
  password_login_enabled?: boolean;
  github?: OAuth2ProviderSettings;
  oidc?: OIDCProviderSettings;
}

export interface GroupNode {
  name: string;
  children?: GroupNode[];
}

// F1：一次分组归属迁移（对应后端 SettingsUpdate.GroupMoves）。
// from / to 为 selection 字符串："A"（分组级）或 "A:t"（标签级）。
export interface GroupMove {
  from: string;
  to: string;
}

export interface GroupSelection {
  group: string;
  tag: string;
}

export interface TestCatalogItem {
  id?: string;
  name: string;
  type: string;
  host: string;
  port?: number;
  interval_sec?: number;
  // O-01：下发范围（后端 persist.go TestCatalogItem.Scope）。undefined 表示
  // 「不下发」（仅节点手动选择生效）；mode=all 时 exclude 生效，mode=include
  // 时 nodes / groups 任一命中即下发（exclude 同样生效，D-05）。
  scope?: AlertScope;
}

export interface AIProviderConfig {
  api_key?: string;
  api_key_set?: boolean;
  base_url?: string;
  model?: string;
  allow_private_base_url?: boolean;
}

interface AIProviderProfile extends AIProviderConfig {
  id?: string;
  name?: string;
}

interface AISettings {
  command_provider?: string;
  prompt?: string;
  openai?: AIProviderConfig;
  openai_compatibles?: AIProviderProfile[];
}

// F5 通知渠道测试结果（POST /api/v1/admin/alerts/test 的 {channel} 草稿请求体
// 返回 {ok, error, latency_ms}；同时由服务端写入渠道的 last_test）。
export interface ChannelTestResult {
  at: number;
  ok: boolean;
  error?: string;
  latency_ms?: number;
}

// F5 多渠道通知模型（后端 persist.go NotifyChannel）。
// 视图形态：Secrets 恒为空，改以 secrets_set 标记已配置的敏感字段；
// 保存载荷只需带 id / type / name / enabled / config / secrets（非空 secret）。
// secrets_clear（B-08 / D-04）：要清除的可选密钥 key 列表，仅保存 / 测试载荷使用，
// 服务端合并后丢弃，视图不回传。
export interface NotifyChannel {
  id?: string;
  type?: string;
  name?: string;
  enabled?: boolean;
  config?: Record<string, string>;
  secrets?: Record<string, string>;
  secrets_set?: Record<string, boolean>;
  secrets_clear?: string[];
  last_test?: ChannelTestResult | null;
}

// F4 告警规则范围（后端 persist.go AlertScope）：mode=all 时 exclude 生效；
// mode=include 时 nodes / groups 任一命中即适用（groups 值为 "A" 或 "A:t"）。
export interface AlertScope {
  mode?: string;
  nodes?: string[];
  groups?: string[];
  exclude?: string[];
}

// F4 告警规则模型（后端 persist.go AlertRule）。threshold 的存储单位随指标
// （net_in / net_out 为 B/s，UI 按 Mbps 输入换算后存储）；channel_ids 空 = 全部
// 已启用渠道；duration_sec 0 = 单次采样即判定；repeat 为 "once" | "backoff"。
export interface AlertRule {
  id?: string;
  name?: string;
  enabled?: boolean;
  metric?: string;
  op?: string;
  threshold?: number;
  duration_sec?: number;
  ratio?: number;
  scope?: AlertScope;
  channel_ids?: string[];
  notify_recover?: boolean;
  repeat?: string;
  probe_name?: string;
  lead_days?: number[];
}

// SettingsView.alert_rule_status 的条目：某规则当前处于 FIRING 状态的节点数
// （运行时聚合，只读，不参与保存）。
export interface AlertRuleStatusView {
  firing: number;
}

// F4 模拟评估（POST /api/v1/admin/alerts/rules/preview）的单节点结果；
// state 为 "pass" | "fail" | "unknown"。
export interface AlertRulePreviewItem {
  node_id: string;
  name: string;
  value: number;
  state: string;
}

export interface SettingsView {
  admin_path: string;
  admin_user: string;
  turnstile_site_key?: string;

  turnstile_secret_key?: string;
  agent_endpoint?: string;

  agent_token?: string;
  agent_token_set?: boolean;
  site_title?: string;
  site_icon?: string;
  site_background_image?: string;
  home_title?: string;
  home_subtitle?: string;
  locale?: string;
  region_group_enabled?: boolean;

  alert_webhook?: string;
  alert_webhook_set?: boolean;
  alert_offline_sec?: number;

  alert_telegram_token?: string;
  alert_telegram_token_set?: boolean;
  alert_telegram_user_ids?: number[];
  notify_channels?: NotifyChannel[];
  // F4：alert_rules 为完整规则列表（含内置 offline 规则）；alert_rule_status 为
  // 运行时聚合（每条规则 FIRING 节点数），只读。
  alert_rules?: AlertRule[];
  alert_rule_status?: Record<string, AlertRuleStatusView>;
  login_fail_limit?: number;
  login_fail_window_sec?: number;
  login_lock_sec?: number;
  admin_auth?: AdminAuthSettings;
  ai_settings?: AISettings;
  version?: string;
  commit?: string;
  groups?: string[];
  group_tree?: GroupNode[];
  test_catalog?: TestCatalogItem[];
}

export interface SettingsUpdate {
  admin_path?: string;
  admin_user?: string;
  admin_pass?: string;
  turnstile_site_key?: string;
  turnstile_secret_key?: string;
  agent_token?: string;
  agent_endpoint?: string;
  site_title?: string;
  site_icon?: string;
  site_background_image?: string;
  home_title?: string;
  home_subtitle?: string;
  locale?: string;
  region_group_enabled?: boolean;
  alert_webhook?: string;
  alert_offline_sec?: number;
  alert_telegram_token?: string;
  alert_telegram_user_ids?: number[];
  notify_channels?: NotifyChannel[];
  // F4：完整规则列表（含内置 offline 规则）；省略 = 本次请求不改规则。
  alert_rules?: AlertRule[];
  login_fail_limit?: number;
  login_fail_window_sec?: number;
  login_lock_sec?: number;
  admin_auth?: AdminAuthSettings;
  ai_settings?: AISettings;
  groups?: string[];
  group_tree?: GroupNode[];
  group_moves?: GroupMove[];
  test_catalog?: TestCatalogItem[];
}

export interface ConfigImportResponse {
  settings?: SettingsView;
}

export type AdminLogLevel = "all" | "info" | "warning" | "error" | "debug" | "silent";

export interface AdminLogEntry {
  id: number;
  timestamp: number;
  time: string;
  level: Exclude<AdminLogLevel, "all">;
  source: string;
  message: string;
}

export interface AdminLogsResponse {
  entries: AdminLogEntry[];
  levels: AdminLogLevel[];
  limit: number;
}

export interface NodeDeleteResponse {
  status: string;
  history_error?: string;
}

interface NetworkTestResult {
  name: string;
  type: string;
  host: string;
  port?: number;
  latency_ms?: number | null;
  packet_loss: number;
  status: string;
  error?: string;
  checked_at: number;
}

interface CPUInfo {
  usage_percent: number;
  load1: number;
  load5: number;
  load15: number;
  model?: string;
  cores?: number;
}

interface MemInfo {
  total: number;
  used: number;
  free: number;
  used_percent: number;
}

interface DiskPartition {
  device: string;
  mountpoint: string;
  fstype: string;
  total: number;
  used: number;
  free: number;
  used_percent: number;
}

interface DiskIO {
  read_bytes: number;
  write_bytes: number;
  read_bytes_per_sec: number;
  write_bytes_per_sec: number;
}

interface NetworkIO {
  bytes_sent: number;
  bytes_recv: number;
  tx_bytes_per_sec: number;
  rx_bytes_per_sec: number;
}

interface GPUInfo {
  index: number;
  id?: string;
  name?: string;
  vendor?: string;
  driver_version?: string;
  utilization_percent: number;
  memory_total: number;
  memory_used: number;
  memory_free: number;
  memory_used_percent: number;
  temperature_c?: number;
  power_w?: number;
}

interface NodeStats {
  node_id: string;
  node_name: string;
  node_alias?: string;
  node_group?: string;
  hostname: string;
  public_ipv4?: string;
  public_ipv6?: string;
  os: string;
  arch: string;
  static_info?: boolean;
  static_updated_at?: number;
  agent_version?: string;
  uptime_sec: number;
  timestamp: number;
  net_speed_mbps?: number;
  cpu: CPUInfo;
  memory: MemInfo;
  disk: DiskPartition[];
  disk_type?: string;
  disk_io: DiskIO;
  network: NetworkIO;
  gpu?: GPUInfo[];
  gpu_collected?: boolean;
  process_count?: number;
  tcp_conns?: number;
  udp_conns?: number;
  network_tests?: NetworkTestResult[];
}

export interface TestSelection {
  test_id: string;
  interval_sec?: number;
}

export interface NodeView {
  stats: NodeStats;
  last_seen: number;
  first_seen?: number;
  status: string;
  server_id?: string;
  alert_enabled: boolean;
  alias?: string;
  group?: string;
  tags?: string[];
  groups?: string[];
  region?: string;
  disk_type?: string;
  net_speed_mbps?: number;
  expire_at?: number;
  auto_renew?: boolean;
  renew_interval_sec?: number;
  // F4 流量配额（后端 NodeView 同名 JSON 字段，omitempty；0 / 空为未设置）。
  traffic_limit_bytes?: number;
  traffic_limit_type?: string;
  traffic_reset_day?: number;
  // A-02：管理端专属的流量用量字段（仅 admin 快照 / /api/v1/admin/nodes 返回，
  // 公开快照与公开 WS 载荷不含；0 / 未定义为无数据）。
  traffic_used_bytes?: number;
  traffic_cycle_start?: number;
  // O-01：管理端专属的范围下发探测目录项 ID（只读，仅 admin 快照 /
  // /api/v1/admin/nodes 返回，公开快照与公开 WS 载荷不含——红线 4）。
  // 已被节点手动选择的目录项不列入（手动选择优先）。
  scoped_test_ids?: string[];
  hidden_from_display?: boolean;
  hidden_from_cr?: boolean;
  hidden_from_all?: boolean;
  test_interval_sec?: number;
  test_selections?: TestSelection[];
  agent_update_supported: boolean;
  agent_update_mode?: string;
  agent_update_state?: string;
  agent_update_target_version?: string;
  agent_update_message?: string;
}

export interface PublicSettings {
  site_title?: string;
  site_icon?: string;
  site_background_image?: string;
  home_title?: string;
  home_subtitle?: string;
  locale?: string;
  region_group_enabled?: boolean;
}

export interface BootPublicSettings extends PublicSettings {
  version?: string;
  commit?: string;
}

export interface AdminBootPayload {
  settings?: BootPublicSettings | null;
  base_path?: string;
}

export interface SystemUpdateInfo {
  current_version: string;
  latest_version?: string;
  available: boolean;
  updating: boolean;
  supported: boolean;
  mode: string;
  message?: string;
  html_url?: string;
  published_at?: string;
  last_checked_at?: number;
  last_started_at?: number;
  last_finished_at?: number;
}

export interface AgentUpdateInfo {
  current_version: string;
  latest_version?: string;
  available: boolean;
  supported: boolean;
  mode: string;
  message?: string;
  html_url?: string;
  published_at?: string;
}

// F7 主控运行状态（GET /api/v1/admin/system/status 响应，字段与后端 SystemStatus 一致）。
// Dashboard（每 10s 轮询）与基础设置 system 分区「运行信息」卡各自拉取一份。
export interface SystemStatusView {
  version?: string;
  commit?: string;
  go_version?: string;
  started_at?: number;
  uptime_sec?: number;
  goroutines?: number;
  mem?: { alloc?: number; sys?: number; heap_inuse?: number };
  process?: { cpu_percent?: number; rss?: number };
  host?: { load1?: number; cpu_percent?: number; mem_used_percent?: number };
  ws_clients?: { admin?: number; public?: number };
  data_dir?: { state_bytes?: number; tsdb_bytes?: number; free_bytes?: number };
  // A-10：当前告警聚合——firing 为告警中 (规则, 节点) 数（阈值类 FIRING + 离线
  // 告警中的节点），nodes 为涉及的去重节点数。
  alerts?: { firing?: number; nodes?: number };
}

// F7 探测总览（GET /api/v1/admin/probes/overview?range=1h|24h）：服务端跨节点按探测
// 目标聚合的窗口统计；无有效延迟 / 丢包样本时对应字段为 null。
export interface ProbeTargetOverview {
  name?: string;
  type?: string;
  host?: string;
  port?: number;
  nodes?: number;
  samples?: number;
  availability_pct?: number;
  avg_latency_ms?: number | null;
  p95_latency_ms?: number | null;
  avg_loss_pct?: number | null;
}

export interface ProbeNodeOverview {
  node_id: string;
  targets: number;
  samples: number;
  availability_pct: number;
  avg_latency_ms?: number | null;
  p95_latency_ms?: number | null;
  avg_loss_pct?: number | null;
}

export type ProbeOverviewRange = "1h" | "24h";

export interface ProbesOverviewResponse {
  range_key: string;
  from: number;
  to: number;
  targets: ProbeTargetOverview[];
  nodes?: ProbeNodeOverview[];
}

export interface Snapshot {
  type: string;
  generated_at: number;
  nodes: NodeView[];
  groups?: string[];
  settings?: PublicSettings;
}

export interface NodeDelta {
  type: "node_delta";
  generated_at: number;
  node: NodeView;
}

export const DEFAULT_TCP_INTERVAL = 5;
export const MAX_TCP_INTERVAL = 3600;

export interface NodeProfilePayload {
  alias?: string;
  group?: string;
  tags?: string[];
  groups?: string[];
  region?: string;
  hide_from_display?: boolean;
  hide_from_cr?: boolean;
  hide_from_all?: boolean;
  disk_type?: string;
  net_speed_mbps?: number;
  expire_at?: number;
  auto_renew?: boolean;
  renew_interval_sec?: number;
  test_selections?: TestSelection[];
  alert_enabled?: boolean;
  // F4 流量配额（后端 NodeProfileUpdate 指针字段；traffic_reset_day 0 = 清空恢复默认）。
  traffic_limit_bytes?: number;
  traffic_limit_type?: string;
  traffic_reset_day?: number;
}

export interface AlertTestPayload {
  webhook?: string;
  telegram_token?: string;
  telegram_user_ids?: number[];
}
