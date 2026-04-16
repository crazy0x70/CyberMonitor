export interface ApiErrorPayload {
  error?: string;
}

export interface LoginResponse {
  expires_at: number;
}

export interface LoginConfigResponse {
  turnstile_enabled?: boolean;
  turnstile_site_key?: string;
}

export interface GroupNode {
  name: string;
  children?: GroupNode[];
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
}

export interface AIProviderConfig {
  api_key?: string;
  base_url?: string;
  model?: string;
}

export interface AIProviderProfile extends AIProviderConfig {
  id?: string;
  name?: string;
}

export interface AISettings {
  default_provider?: string;
  command_provider?: string;
  prompt?: string;
  openai?: AIProviderConfig;
  gemini?: AIProviderConfig;
  volcengine?: AIProviderConfig;
  openai_compatible?: AIProviderConfig;
  openai_compatibles?: AIProviderProfile[];
}

export interface SettingsView {
  admin_path: string;
  admin_user: string;
  turnstile_site_key?: string;
  turnstile_secret_key?: string;
  agent_endpoint?: string;
  agent_token?: string;
  site_title?: string;
  site_icon?: string;
  home_title?: string;
  home_subtitle?: string;
  alert_webhook?: string;
  alert_offline_sec?: number;
  alert_all?: boolean;
  alert_nodes?: string[];
  alert_telegram_token?: string;
  alert_telegram_user_ids?: number[];
  alert_telegram_user_id?: number;
  login_fail_limit?: number;
  login_fail_window_sec?: number;
  login_lock_sec?: number;
  ai_settings?: AISettings;
  version?: string;
  commit?: string;
  groups?: string[];
  group_tree?: GroupNode[];
  test_catalog?: TestCatalogItem[];
  session_token?: string;
  session_expires_at?: number;
}

export interface ConfigImportResponse {
  settings?: SettingsView;
  reauth_required?: boolean;
}

export interface NetworkTestConfig {
  name: string;
  type: string;
  host: string;
  port?: number;
  interval_sec?: number;
}

export interface NetworkTestResult {
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

export interface CPUInfo {
  usage_percent: number;
  load1: number;
  load5: number;
  load15: number;
  model?: string;
  cores?: number;
}

export interface MemInfo {
  total: number;
  used: number;
  free: number;
  used_percent: number;
}

export interface DiskPartition {
  device: string;
  mountpoint: string;
  fstype: string;
  total: number;
  used: number;
  free: number;
  used_percent: number;
}

export interface DiskIO {
  read_bytes: number;
  write_bytes: number;
  read_bytes_per_sec: number;
  write_bytes_per_sec: number;
}

export interface NetworkIO {
  bytes_sent: number;
  bytes_recv: number;
  tx_bytes_per_sec: number;
  rx_bytes_per_sec: number;
}

export interface NodeStats {
  node_id: string;
  node_name: string;
  node_alias?: string;
  node_group?: string;
  hostname: string;
  public_ipv4?: string;
  public_ipv6?: string;
  os: string;
  arch: string;
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
  test_interval_sec?: number;
  tests?: NetworkTestConfig[];
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
  home_title?: string;
  home_subtitle?: string;
  version?: string;
  commit?: string;
}

export interface AdminBootPayload {
  settings?: PublicSettings | null;
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

export interface Snapshot {
  type: string;
  generated_at: number;
  nodes: NodeView[];
  groups?: string[];
  settings?: PublicSettings;
  test_history?: Record<string, unknown>;
}

export interface NodeProfilePayload {
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
  test_interval_sec?: number;
  tests?: NetworkTestConfig[];
  test_selections?: TestSelection[];
  alert_enabled?: boolean;
}

export interface AlertTestPayload {
  webhook?: string;
  telegram_token?: string;
  telegram_user_ids?: number[];
}
