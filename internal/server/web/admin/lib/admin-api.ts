import type {
  AdminBootPayload,
  AlertTestPayload,
  AgentUpdateInfo,
  AIProviderConfig,
  AdminLogLevel,
  AdminLogsResponse,
  ApiErrorPayload,
  ConfigImportResponse,
  LoginConfigResponse,
  LoginResponse,
  NodeDelta,
  NodeDeleteResponse,
  NodeProfilePayload,
  NodeView,
  SettingsView,
  Snapshot,
  SystemUpdateInfo,
} from "@/lib/admin-types";

export const ADMIN_TOKEN_KEY = "cm_admin_token";

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
    // session cookie remains the source of truth when sessionStorage is unavailable
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
    // ignore
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

export function adminAppPath(adminPath: string) {
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
      // ignore malformed boot payload
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

export async function saveSettings(payload: Record<string, unknown>) {
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
  const resp = await apiFetch("/api/v1/admin/nodes?history=0");
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

export async function fetchSystemUpdateInfo() {
  const resp = await apiFetch("/api/v1/admin/system/update");
  return unwrapResponse<SystemUpdateInfo>(resp, "获取服务端更新状态失败");
}

export async function triggerSystemUpdate() {
  const resp = await apiFetch(
    "/api/v1/admin/system/update",
    { method: "POST" },
  );
  return unwrapResponse<{ status: string; target_version?: string }>(resp, "触发服务端更新失败");
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

export async function testAIProvider(provider: string, config: AIProviderConfig) {
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

export async function fetchAIModels(provider: string, config: AIProviderConfig) {
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

export interface AdminSocketConnection {
  close: () => void;
}

interface AdminSocketOptions {
  reconnectDelayMs?: number;
  reconnectMaxDelayMs?: number;
}

export function connectAdminSocket(
  onSnapshot: (snapshot: Snapshot) => void,
  onNodeDelta?: (node: NodeView) => void,
  options: AdminSocketOptions = {},
): AdminSocketConnection {
  const reconnectDelayMs = Math.max(0, Number(options.reconnectDelayMs ?? 1000));
  const reconnectMaxDelayMs = Math.max(
    reconnectDelayMs,
    Number(options.reconnectMaxDelayMs ?? 8000),
  );
  let nextReconnectDelayMs = reconnectDelayMs;
  let socket: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  const handleMessage = (event: MessageEvent) => {
    try {
      const payload = JSON.parse(event.data) as Snapshot | NodeDelta;
      if (isSnapshotPayload(payload)) {
        onSnapshot(payload);
      } else if (isNodeDeltaPayload(payload)) {
        onNodeDelta?.(payload.node);
      }
    } catch {
      // ignore invalid frames
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
    });
    socket.addEventListener("message", handleMessage);
    socket.addEventListener("close", () => {
      socket = null;
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

  connect();

  return {
    close() {
      closed = true;
      clearReconnectTimer();
      const activeSocket = socket;
      socket = null;
      activeSocket?.close();
    },
  };
}

function isSnapshotPayload(payload: unknown): payload is Snapshot {
  return Boolean(payload && typeof payload === "object" && Array.isArray((payload as Snapshot).nodes));
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasStableNodeID(stats: Record<string, unknown>) {
  return typeof stats.node_id === "string" && stats.node_id.trim() !== "" ||
    typeof stats.node_name === "string" && stats.node_name.trim() !== "";
}

function isNodeViewPayload(payload: unknown): payload is NodeView {
  if (!isObjectRecord(payload)) {
    return false;
  }
  if (!isObjectRecord(payload.stats)) {
    return false;
  }
  return (
    hasStableNodeID(payload.stats) &&
    isObjectRecord(payload.stats.cpu) &&
    isObjectRecord(payload.stats.memory)
  );
}

function isNodeDeltaPayload(payload: unknown): payload is NodeDelta {
  if (!isObjectRecord(payload)) {
    return false;
  }
  const delta = payload as Partial<NodeDelta>;
  return delta.type === "node_delta" && isNodeViewPayload(delta.node);
}
