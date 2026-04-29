import type {
  AdminBootPayload,
  AlertTestPayload,
  AgentUpdateInfo,
  AIProviderConfig,
  ApiErrorPayload,
  ConfigImportResponse,
  LoginConfigResponse,
  LoginResponse,
  NodeProfilePayload,
  NodeView,
  SettingsView,
  Snapshot,
  SystemUpdateInfo,
} from "@/lib/admin-types";

export const ADMIN_TOKEN_KEY = "cm_admin_token";

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
  return window.sessionStorage.getItem(ADMIN_TOKEN_KEY) || "";
}

export function setStoredAdminToken(token: string) {
  if (token) {
    window.sessionStorage.setItem(ADMIN_TOKEN_KEY, "session");
    return;
  }
  window.sessionStorage.removeItem(ADMIN_TOKEN_KEY);
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

async function apiFetch(path: string, init: RequestInit = {}, token = getStoredAdminToken()) {
  const headers = new Headers(init.headers || {});
  const resp = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (resp.status === 401 && token) {
    setStoredAdminToken("");
  }
  return resp;
}

export async function fetchLoginConfig() {
  const resp = await fetch("/api/v1/login/config");
  return unwrapResponse<LoginConfigResponse>(resp, "加载登录配置失败");
}

export async function fetchPublicSnapshot() {
  const resp = await fetch("/api/v1/public/snapshot");
  return unwrapResponse<Snapshot>(resp, "加载公开展示配置失败");
}

export async function fetchSessionStatus() {
  const resp = await fetch("/api/v1/admin/session", { credentials: "same-origin" });
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
  const resp = await fetch("/api/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password, turnstile_token: turnstileToken }),
  });
  const data = await unwrapResponse<LoginResponse>(resp, "登录失败");
  setStoredAdminToken("session");
  return data;
}

export async function fetchSettings(token = getStoredAdminToken()) {
  const resp = await apiFetch("/api/v1/admin/settings", {}, token);
  return unwrapResponse<SettingsView>(resp, "加载设置失败");
}

export async function saveSettings(payload: Record<string, unknown>, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/settings",
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    token,
  );
  return unwrapResponse<SettingsView>(resp, "保存设置失败");
}

export async function exportConfig(token = getStoredAdminToken()) {
  const resp = await apiFetch("/api/v1/admin/config/export", {}, token);
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, "导出配置失败");
    throw new AdminApiError(message, resp.status);
  }
  return {
    blob: await resp.blob(),
    disposition: resp.headers.get("Content-Disposition") || "",
  };
}

export async function importConfig(payload: Record<string, unknown>, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/config/import",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    token,
  );
  return unwrapResponse<ConfigImportResponse>(resp, "导入配置失败");
}

export async function logoutAdmin() {
  const resp = await fetch("/api/v1/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, "退出登录失败");
    throw new AdminApiError(message, resp.status);
  }
  setStoredAdminToken("");
}

export async function fetchNodes(token = getStoredAdminToken()) {
  const resp = await apiFetch("/api/v1/admin/nodes?history=0", {}, token);
  return unwrapResponse<Snapshot>(resp, "加载节点失败");
}

export async function saveNodeProfile(nodeID: string, payload: NodeProfilePayload, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    token,
  );
  return unwrapResponse<NodeView>(resp, "保存节点失败");
}

export async function deleteNodeProfile(nodeID: string, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}`,
    { method: "DELETE" },
    token,
  );
  await unwrapResponse<{ status: string }>(resp, "删除节点失败");
}

export async function fetchSystemUpdateInfo(token = getStoredAdminToken()) {
  const resp = await apiFetch("/api/v1/admin/system/update", {}, token);
  return unwrapResponse<SystemUpdateInfo>(resp, "获取服务端更新状态失败");
}

export async function triggerSystemUpdate(token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/system/update",
    { method: "POST" },
    token,
  );
  return unwrapResponse<{ status: string; target_version?: string }>(resp, "触发服务端更新失败");
}

export async function triggerAgentUpdate(nodeID: string, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/agent/update`,
    { method: "POST" },
    token,
  );
  return unwrapResponse<{ status: string; target_version?: string }>(resp, "下发 Agent 更新失败");
}

export async function fetchAgentUpdateInfo(nodeID: string, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    `/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/agent/update`,
    {},
    token,
  );
  return unwrapResponse<AgentUpdateInfo>(resp, "获取 Agent 更新状态失败");
}

export async function testAlertChannels(payload: AlertTestPayload, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/alerts/test",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    token,
  );
  return unwrapResponse<{ status: string }>(resp, "测试告警失败");
}

export async function testAIProvider(provider: string, config: AIProviderConfig, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/ai/test",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, config }),
    },
    token,
  );
  return unwrapResponse<{ status: string }>(resp, "测试 Provider 失败");
}

export async function fetchAIModels(provider: string, config: AIProviderConfig, token = getStoredAdminToken()) {
  const resp = await apiFetch(
    "/api/v1/admin/ai/models",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, config }),
    },
    token,
  );
  return unwrapResponse<{ models: string[] }>(resp, "获取模型列表失败");
}

export function connectAdminSocket(token: string, onSnapshot: (snapshot: Snapshot) => void) {
  void token;
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${protocol}://${window.location.host}/ws`;
  const socket = new WebSocket(url);
  socket.addEventListener("message", (event) => {
    try {
      const payload = JSON.parse(event.data) as Snapshot;
      if (Array.isArray(payload.nodes)) {
        onSnapshot(payload);
      }
    } catch {
      // ignore invalid frames
    }
  });
  return socket;
}
