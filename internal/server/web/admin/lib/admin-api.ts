import type {
  AdminBootPayload,
  AlertRule,
  AlertRulePreviewItem,
  AlertTestPayload,
  AgentUpdateInfo,
  AIProviderConfig,
  AdminLogLevel,
  AdminLogsResponse,
  ApiErrorPayload,
  ChannelTestResult,
  ConfigImportResponse,
  LoginConfigResponse,
  LoginResponse,
  NodeDeleteResponse,
  NodeProfilePayload,
  NotifyChannel,
  ProbeOverviewRange,
  ProbesOverviewResponse,
  SettingsUpdate,
  SettingsView,
  Snapshot,
  SystemStatusView,
  SystemUpdateInfo,
} from "@/lib/admin-types";

const ADMIN_TOKEN_KEY = "cm_admin_token";

type AdminUnauthorizedListener = () => void;

const adminUnauthorizedListeners = new Set<AdminUnauthorizedListener>();

export class AdminApiError extends Error {
  status: number;
  retryAfterSec?: number;

  constructor(message: string, status: number, retryAfterSec?: number) {
    super(message);
    this.name = "AdminApiError";
    this.status = status;
    this.retryAfterSec = retryAfterSec;
  }
}

export function getStoredAdminToken() {
  try {
    return window.sessionStorage.getItem(ADMIN_TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setStoredAdminToken(token: string) {
  try {
    if (token) {
      window.sessionStorage.setItem(ADMIN_TOKEN_KEY, "session");
      return;
    }
    window.sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  } catch {
    // sessionStorage 不可用（隐私模式等）时放弃持久化，令牌仅存内存。
  }
}

export function addAdminUnauthorizedListener(listener: AdminUnauthorizedListener) {
  adminUnauthorizedListeners.add(listener);
  return () => {
    adminUnauthorizedListeners.delete(listener);
  };
}

function notifyAdminUnauthorized() {
  for (const listener of Array.from(adminUnauthorizedListeners)) {
    listener();
  }
}

async function parseErrorMessage(resp: Response, fallback: string) {
  try {
    const payload = (await resp.json()) as ApiErrorPayload;
    if (payload?.error) {
      return payload.error;
    }
  } catch {
    // 响应体不是 JSON 时忽略，由调用方使用 fallback 文案。
  }
  return fallback;
}

async function unwrapResponse<T>(resp: Response, fallback: string) {
  if (!resp.ok) {
    const retryAfterHeader = resp.headers.get("Retry-After");
    const retryAfterSec = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
    const message = await parseErrorMessage(resp, fallback);
    throw new AdminApiError(message, resp.status, Number.isFinite(retryAfterSec) ? retryAfterSec : undefined);
  }
  return (await resp.json()) as T;
}

function normalizeBasePath(value: string) {
  let path = value.trim();
  if (!path || path.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(path)) {
    return "";
  }
  let settled = false;
  for (let i = 0; i < 4; i += 1) {
    try {
      const decoded = decodeURIComponent(path);
      if (decoded === path) {
        settled = true;
        break;
      }
      path = decoded;
      if (hasInvalidBasePathChar(path)) {
        return "";
      }
    } catch {
      return "";
    }
  }
  if (!settled) {
    return "";
  }
  if (!path.startsWith("/")) {
    path = `/${path}`;
  }
  if (hasInvalidBasePathChar(path)) {
    return "";
  }
  const segments = path.split("/").filter(Boolean);
  if (
    segments.length === 0 ||
    segments.some((segment) => segment === "." || segment === ".." || segment.includes(":") || segment.includes("\\"))
  ) {
    return "";
  }
  return `/${segments.join("/")}`;
}

function hasInvalidBasePathChar(value: string) {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (char === "?" || char === "#" || code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function adminBasePath() {
  return normalizeBasePath(readAdminBootPayload().base_path || "");
}

function apiPath(path: string) {
  if (!path.startsWith("/")) {
    return path;
  }
  const basePath = adminBasePath();
  return basePath ? `${basePath}${path}` : path;
}

function adminAppPath(adminPath: string) {
  const normalizedAdminPath = normalizeBasePath(adminPath);
  if (!normalizedAdminPath) {
    return "";
  }
  return `${apiPath(normalizedAdminPath)}/`;
}

export function adminAppLocation(adminPath: string) {
  const nextPath = adminAppPath(adminPath);
  if (!nextPath || typeof window === "undefined") {
    return nextPath;
  }
  return `${nextPath}${window.location.search}${window.location.hash}`;
}

export function publicMonitorPath() {
  const basePath = adminBasePath();
  return basePath ? `${basePath}/` : "/";
}

export function adminOAuthLoginLocation(providerID: string, returnTo = "") {
  const params = new URLSearchParams({ provider: providerID });
  if (returnTo.trim()) {
    params.set("return_to", returnTo.trim());
  }
  return `${apiPath("/api/v1/login/oauth/start")}?${params.toString()}`;
}

function adminSocketURL() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${apiPath("/ws")}`;
}

async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  const resp = await fetch(apiPath(path), { ...init, headers, credentials: "same-origin" });
  if (resp.status === 401) {
    setStoredAdminToken("");
    notifyAdminUnauthorized();
  }
  return resp;
}

export async function fetchLoginConfig() {
  const resp = await fetch(apiPath("/api/v1/login/config"));
  return unwrapResponse<LoginConfigResponse>(resp, "加载登录配置失败");
}

export async function fetchPublicSnapshot() {
  const resp = await fetch(apiPath("/api/v1/public/snapshot"));
  return unwrapResponse<Snapshot>(resp, "加载公开展示配置失败");
}

export async function fetchSessionStatus() {
  const resp = await apiFetch("/api/v1/admin/session");
  return unwrapResponse<{ authenticated: boolean }>(resp, "检测登录会话失败");
}

export function readAdminBootPayload(): AdminBootPayload {
  if (typeof window === "undefined") {
    return {};
  }
  const meta = document.querySelector('meta[name="cm-admin-boot"]');
  const encoded = meta?.getAttribute("content")?.trim();
  if (encoded) {
    try {
      return JSON.parse(window.atob(encoded)) as AdminBootPayload;
    } catch {
      // boot payload 解码失败时回落到 window.__CM_ADMIN_BOOT__。
    }
  }
  const payload = window.__CM_ADMIN_BOOT__;
  if (!payload || typeof payload !== "object") {
    return {};
  }
  return payload;
}

export async function loginAdmin(username: string, password: string, turnstileToken = "") {
  const resp = await fetch(apiPath("/api/v1/login"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password, turnstile_token: turnstileToken }),
  });
  const data = await unwrapResponse<LoginResponse>(resp, "登录失败");
  setStoredAdminToken("session");
  return data;
}

export async function fetchSettings() {
  const resp = await apiFetch("/api/v1/admin/settings");
  return unwrapResponse<SettingsView>(resp, "加载设置失败");
}

export async function saveSettings(payload: SettingsUpdate) {
  const resp = await apiFetch(
    "/api/v1/admin/settings",
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return unwrapResponse<SettingsView>(resp, "保存设置失败");
}

export async function exportConfig() {
  const resp = await apiFetch("/api/v1/admin/config/export");
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, "导出配置失败");
    throw new AdminApiError(message, resp.status);
  }
  return {
    blob: await resp.blob(),
    disposition: resp.headers.get("Content-Disposition") || "",
  };
}

export async function importConfig(payload: Record<string, unknown>) {
  const resp = await apiFetch(
    "/api/v1/admin/config/import",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return unwrapResponse<ConfigImportResponse>(resp, "导入配置失败");
}

export async function logoutAdmin() {
  const resp = await fetch(apiPath("/api/v1/logout"), {
    method: "POST",
    credentials: "same-origin",
  });
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, "退出登录失败");
    throw new AdminApiError(message, resp.status);
  }
  setStoredAdminToken("");
}

export async function fetchNodes() {
  const resp = await apiFetch("/api/v1/admin/nodes");
  return unwrapResponse<Snapshot>(resp, "加载节点失败");
}

export async function fetchAdminLogs(level: AdminLogLevel = "all", limit = 300) {
  const params = new URLSearchParams({
    level,
    limit: String(limit),
  });
  const resp = await apiFetch(`/api/v1/admin/logs?${params.toString()}`);
  return unwrapResponse<AdminLogsResponse>(resp, "加载日志失败");
}

export async function saveNodeProfile(nodeID: string, payload: NodeProfilePayload) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return unwrapResponse<{ status: string }>(resp, "保存节点失败");
}

export async function deleteNodeProfile(nodeID: string) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`,
    { method: "DELETE" },
  );
  return unwrapResponse<NodeDeleteResponse>(resp, "删除节点失败");
}

// F3 第 3 条：force=true 时携带 ?force=1，服务端跳过缓存强制刷新更新信息
// （「检查」按钮传入 true；常规轮询 / 首次加载走默认缓存视图）。
export async function fetchSystemUpdateInfo(force = false) {
  const query = force ? "?force=1" : "";
  const resp = await apiFetch(`/api/v1/admin/system/update${query}`);
  return unwrapResponse<SystemUpdateInfo>(resp, "获取服务端更新状态失败");
}

export async function triggerSystemUpdate() {
  const resp = await apiFetch(
    "/api/v1/admin/system/update",
    { method: "POST" },
  );
  return unwrapResponse<{ status: string; target_version?: string }>(resp, "触发服务端更新失败");
}

// F7：主控运行状态（GET /api/v1/admin/system/status）。Dashboard「主控负载 / 主控状态」
// 与基础设置「运行信息」卡的数据源，由调用方各自拉取。
export async function fetchSystemStatus() {
  const resp = await apiFetch("/api/v1/admin/system/status");
  return unwrapResponse<SystemStatusView>(resp, "加载主控状态失败");
}

// F7：探测总览（GET /api/v1/admin/probes/overview?range=1h|24h），跨节点聚合的
// 可用率 / 平均延迟 / P95 / 平均丢包。
export async function fetchProbesOverview(range: ProbeOverviewRange) {
  const params = new URLSearchParams({ range });
  const resp = await apiFetch(`/api/v1/admin/probes/overview?${params.toString()}`);
  return unwrapResponse<ProbesOverviewResponse>(resp, "加载探测总览失败");
}

export async function triggerAgentUpdate(nodeID: string) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/agent/update`,
    { method: "POST" },
  );
  return unwrapResponse<{ status: string; target_version?: string }>(resp, "下发 Agent 更新失败");
}

export async function fetchAgentUpdateInfo(nodeID: string) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/agent/update`,
  );
  return unwrapResponse<AgentUpdateInfo>(resp, "获取 Agent 更新状态失败");
}

export async function testAlertChannels(payload: AlertTestPayload) {
  const resp = await apiFetch(
    "/api/v1/admin/alerts/test",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return unwrapResponse<{ status: string }>(resp, "测试告警失败");
}

// F5 渠道草稿测试：POST {channel} 请求体（接受未保存草稿，secret 为空时服务端按
// 同 ID 已存值补齐），返回 {ok, error, latency_ms} 并写入该渠道的 last_test。
// 旧的 webhook/telegram 请求体走 testAlertChannels，保持兼容。
export async function testNotifyChannelDraft(channel: NotifyChannel) {
  const resp = await apiFetch(
    "/api/v1/admin/alerts/test",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel }),
    },
  );
  return unwrapResponse<ChannelTestResult>(resp, "测试发送失败");
}

// F4 模拟评估：POST 一条规则草稿（请求体即 AlertRule 本身，接受未保存草稿），
// 返回每个适用节点的 {node_id, name, value, state}，不修改样本环与状态机。
export async function previewAlertRule(rule: AlertRule) {
  const resp = await apiFetch(
    "/api/v1/admin/alerts/rules/preview",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rule),
    },
  );
  return unwrapResponse<{ results: AlertRulePreviewItem[] }>(resp, "模拟评估失败");
}

export async function testAIProvider(provider: string, config: AIProviderConfig | null) {
  const resp = await apiFetch(
    "/api/v1/admin/ai/test",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, config }),
    },
  );
  return unwrapResponse<{ status: string }>(resp, "测试 Provider 失败");
}

export async function fetchAIModels(provider: string, config: AIProviderConfig | null) {
  const resp = await apiFetch(
    "/api/v1/admin/ai/models",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, config }),
    },
  );
  return unwrapResponse<{ models: string[] }>(resp, "获取模型列表失败");
}

interface AdminSocketConnection {
  close: () => void;
}

// 实时连接状态：主动 close()（页面卸载 / 登出）不回调，只有真正的断开才报 closed。
export type AdminSocketStatus = "connecting" | "open" | "closed";

interface AdminSocketOptions {
  reconnectDelayMs?: number;
  reconnectMaxDelayMs?: number;
  staleTimeoutMs?: number;
  // 状态回调：connecting（每次尝试建连）/ open / closed（非主动关闭）。
  onStatus?: (status: AdminSocketStatus) => void;
}

const DEFAULT_STALE_TIMEOUT_MS = 70000;

export function connectAdminSocket(
  onSnapshot: (snapshot: Snapshot) => void,
  options: AdminSocketOptions = {},
): AdminSocketConnection {
  const reconnectDelayMs = Math.max(0, Number(options.reconnectDelayMs ?? 1000));
  const reconnectMaxDelayMs = Math.max(
    reconnectDelayMs,
    Number(options.reconnectMaxDelayMs ?? 8000),
  );
  const staleTimeoutMs = Math.max(
    1000,
    Number(options.staleTimeoutMs ?? DEFAULT_STALE_TIMEOUT_MS),
  );
  let nextReconnectDelayMs = reconnectDelayMs;
  let socket: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let staleTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  // 回调由调用方提供，抛错（例如已卸载组件）不得中断重连。
  const emitStatus = (status: AdminSocketStatus) => {
    try {
      options.onStatus?.(status);
    } catch {
      // 状态回调异常不影响建连 / 重连流程，直接忽略。
    }
  };

  const clearStaleTimer = () => {
    if (staleTimer) {
      clearTimeout(staleTimer);
      staleTimer = null;
    }
  };

  const armStaleTimer = () => {
    clearStaleTimer();
    if (closed || !socket) {
      return;
    }
    staleTimer = setTimeout(() => {
      staleTimer = null;
      const activeSocket = socket;
      socket = null;
      try {
        activeSocket?.close();
      } catch {
        // 关闭已失效的 socket 可能抛错，不影响后续重连。
      }
    }, staleTimeoutMs);
  };

  const handleMessage = (event: MessageEvent) => {
    armStaleTimer();
    try {
      const payload = JSON.parse(event.data) as Snapshot;
      if (isSnapshotPayload(payload)) {
        onSnapshot(payload);
      }
    } catch {
      // 解析失败的帧直接丢弃，保持连接与重连逻辑不受影响。
    }
  };

  const clearReconnectTimer = () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  const connect = () => {
    if (closed) {
      return;
    }
    socket = new WebSocket(adminSocketURL());
    socket.addEventListener("open", () => {
      nextReconnectDelayMs = reconnectDelayMs;
      armStaleTimer();
      emitStatus("open");
    });
    socket.addEventListener("message", handleMessage);
    socket.addEventListener("close", () => {
      clearStaleTimer();
      socket = null;
      // 先通知界面断线，再按退避重连；重连期间保持 closed（不切回
      // connecting），避免断线横幅每次重试闪烁。
      if (!closed) {
        emitStatus("closed");
      }
      if (!closed && !reconnectTimer) {
        const delay = nextReconnectDelayMs;
        nextReconnectDelayMs = reconnectDelayMs === 0
          ? 0
          : Math.min(reconnectMaxDelayMs, Math.max(reconnectDelayMs, nextReconnectDelayMs * 2));
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connect();
        }, delay);
      }
    });
  };

  emitStatus("connecting");
  connect();

  return {
    close() {
      closed = true;
      clearReconnectTimer();
      clearStaleTimer();
      const activeSocket = socket;
      socket = null;
      activeSocket?.close();
    },
  };
}

function isSnapshotPayload(payload: unknown): payload is Snapshot {
  return Boolean(payload && typeof payload === "object" && Array.isArray((payload as Snapshot).nodes));
}
