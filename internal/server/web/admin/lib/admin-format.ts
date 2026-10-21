import type {
  GroupNode,
  GroupSelection,
  NodeView,
} from "@/lib/admin-types";

export function formatVersionLabel(value?: string | null) {
  const normalized = String(value || "").trim();

  if (!normalized) return "--";
  if (normalized.startsWith("v")) return normalized;
  return /^\d/.test(normalized) ? `v${normalized}` : normalized;
}

// 与前台 monitor.js formatBytes 同规格（1024 进制，B→TB）。
export function formatBinaryBytes(bytes: number | null | undefined) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes || 0);
  if (!Number.isFinite(value) || value < 0) {
    value = 0;
  }
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[index]}`;
}

// 运行时长（中文单位）：「1 天 5 小时」/「3 小时 12 分钟」/「5 分钟」/「42 秒」。
export function formatUptimeZh(totalSeconds: number | null | undefined) {
  const total = Math.max(0, Math.floor(Number(totalSeconds || 0)));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) {
    return `${days} 天 ${hours} 小时`;
  }
  if (hours > 0) {
    return `${hours} 小时 ${minutes} 分钟`;
  }
  if (minutes > 0) {
    return `${minutes} 分钟`;
  }
  return `${total} 秒`;
}

export function toDateTimeLocalValue(value?: number) {
  if (!value) return "";
  const date = new Date(value * 1000);
  const pad = (num: number) => String(num).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function parseDateTimeLocalValue(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const timestamp = new Date(trimmed).getTime();
  if (Number.isNaN(timestamp)) {
    return 0;
  }
  return Math.floor(timestamp / 1000);
}

export function getErrorMessage(error: unknown, fallback: string) {
  if (error instanceof Error) {
    const message = error.message.trim();
    if (message) {
      return message;
    }
  }
  return fallback;
}

export function resolveNodeId(node: NodeView) {
  return node.stats.node_id || node.stats.node_name || "";
}

export function resolveNodeName(node: NodeView) {
  return node.alias || node.stats.node_alias || node.stats.node_name || node.stats.node_id;
}

// B-06（D-02）：磁盘使用率 = Σ已用 / Σ总量（服务器总硬盘口径，Agent 已过滤并
// 去重分区）；总量为 0 / 无分区时返回 null（未知），与服务端 nodeDiskUsage 同口径。
export function nodeDiskPercent(
  stats: NodeView["stats"],
): number | null {
  let total = 0;
  let used = 0;
  for (const partition of stats?.disk || []) {
    total += Number(partition?.total || 0);
    used += Number(partition?.used || 0);
  }
  if (!Number.isFinite(total) || !Number.isFinite(used) || total <= 0) {
    return null;
  }
  return (used / total) * 100;
}

export function resolveNodeIdentitySummary(node: NodeView) {
  const parts = [
    resolveNodeId(node),
    String(node.stats.public_ipv4 || "").trim(),
    String(node.stats.public_ipv6 || "").trim(),
  ].filter(Boolean);
  return parts.join(" / ");
}

export function flattenGroupTree(tree: GroupNode[]) {
  return (tree || [])
    .map((group) => ({
      group: group.name,
      tags: (group.children || []).map((tag) => tag.name),
    }))
    .filter((item) => item.group);
}

function trimSelectionPart(value?: string | null) {
  return String(value || "").trim();
}

function splitSelectionValue(raw: string, separator: ":" | "/") {
  const [group, ...rest] = raw.split(separator);
  return {
    group: group.trim(),
    tag: rest.join(separator).trim(),
  };
}

function normalizeParsedSelection(selection: GroupSelection) {
  const group = trimSelectionPart(selection.group);
  if (!group) {
    return null;
  }
  return {
    group,
    tag: trimSelectionPart(selection.tag),
  };
}

function parseNormalizedSelection(value: string) {
  return normalizeParsedSelection(parseSelectionValue(value));
}

function buildSelectionKey(selection: GroupSelection) {
  return `${selection.group}::${selection.tag}`;
}

function stringifySelectionValue(selection: GroupSelection) {
  return selection.tag ? `${selection.group}:${selection.tag}` : selection.group;
}

function buildSelectionValues(group: string, tags: string[]) {
  if (!group) return [];
  if (!tags.length) return [group];
  return tags.map((tag) => `${group}:${tag}`);
}

export function parseSelectionValue(value: string) {
  const raw = trimSelectionPart(value);
  if (!raw) return { group: "", tag: "" };
  if (raw.includes(":")) {
    return splitSelectionValue(raw, ":");
  }
  if (raw.includes("/")) {
    return splitSelectionValue(raw, "/");
  }
  return { group: raw, tag: "" };
}

// 节点展示名排序（节点列表与首页探测表共用）：数字段按数值比较
// （de-vps-4 < de-vps-14、hk2 < hk10），大小写不敏感，与服务端快照排序一致。
const nodeDisplayNameCollator = new Intl.Collator("zh-CN", {
  numeric: true,
  sensitivity: "base",
});

export function compareNodeDisplayName(left: string, right: string) {
  const primary = nodeDisplayNameCollator.compare(
    String(left || ""),
    String(right || ""),
  );
  if (primary !== 0) return primary;
  // 自然顺序相等（只差大小写或前导零）时回退到原始字节序，保证顺序可复现。
  const leftText = String(left || "");
  const rightText = String(right || "");
  if (leftText === rightText) return 0;
  return leftText < rightText ? -1 : 1;
}

export function normalizeSelectionValues(values: string[]) {
  return Array.from(
    new Set(
      (values || [])
        .map((item) => String(item || "").trim())
        .filter(Boolean),
    ),
  ).sort((a, b) => a.localeCompare(b, "zh-CN"));
}

export function resolveNodeSelectionValues(
  node: Pick<NodeView, "group" | "groups" | "tags">,
) {

  return normalizeSelectionValues(
    Array.isArray(node.groups) && node.groups.length > 0
      ? node.groups
      : buildSelectionValues(node.group || "", node.tags || []),
  );
}

function resolveSelectionValues(values: string[]) {
  const seenSelections = new Set<string>();

  return normalizeSelectionValues(values)
    .map(parseNormalizedSelection)
    .filter((item): item is GroupSelection => Boolean(item))
    .filter((item) => {
      const key = buildSelectionKey(item);
      if (seenSelections.has(key)) {
        return false;
      }
      seenSelections.add(key);
      return true;
    });
}

export function resolveNodeSelections(
  node: Pick<NodeView, "group" | "groups" | "tags" | "stats">,
) {
  return resolveSelectionValues(resolveNodeSelectionValues(node));
}

export function upsertSelectionValue(currentValues: string[], nextValue: string) {
  const nextSelection = parseNormalizedSelection(nextValue);
  if (!nextSelection) {
    return normalizeSelectionValues(currentValues);
  }
  const filtered = currentValues.filter(
    (value) => parseSelectionValue(value).group !== nextSelection.group,
  );
  return normalizeSelectionValues([...filtered, stringifySelectionValue(nextSelection)]);
}

export type AdminPage =
  | "dashboard"
  | "servers"
  | "groups"
  | "probes"
  | "settings"
  | "alerts"
  | "ai"
  | "logs";

export const ADMIN_PAGE_QUERY_KEY = "page";
export const ADMIN_SECTION_QUERY_KEY = "section";

export function adminPageHref(page: AdminPage, section?: string | null) {
  const normalizedSection = String(section || "").trim();
  if (typeof window === "undefined") {
    const pagePart = page === "dashboard" ? "/" : `/?${ADMIN_PAGE_QUERY_KEY}=${page}`;
    return normalizedSection
      ? `${pagePart}&${ADMIN_SECTION_QUERY_KEY}=${encodeURIComponent(normalizedSection)}`
      : pagePart;
  }
  let nextURL: URL;
  try {
    nextURL = new URL(window.location.href);
  } catch {

    const fallbackPart = page === "dashboard" ? "/" : `/?${ADMIN_PAGE_QUERY_KEY}=${page}`;
    return normalizedSection
      ? `${fallbackPart}&${ADMIN_SECTION_QUERY_KEY}=${encodeURIComponent(normalizedSection)}`
      : fallbackPart;
  }
  if (page === "dashboard") {
    nextURL.searchParams.delete(ADMIN_PAGE_QUERY_KEY);
  } else {
    nextURL.searchParams.set(ADMIN_PAGE_QUERY_KEY, page);
  }
  // 未显式带分区的导航（跨页/无分区页）清除 section 与 hash：
  // hash 是被 section 查询参数取代的旧锚点形式，跨页残留会串页（R7）。
  if (normalizedSection) {
    nextURL.searchParams.set(ADMIN_SECTION_QUERY_KEY, normalizedSection);
  } else {
    nextURL.searchParams.delete(ADMIN_SECTION_QUERY_KEY);
  }
  nextURL.hash = "";
  return `${nextURL.pathname}${nextURL.search}${nextURL.hash}`;
}

export function shouldHandleAdminNavigation(
  event: Pick<MouseEvent, "defaultPrevented" | "button" | "metaKey" | "ctrlKey" | "shiftKey" | "altKey">,
) {
  return !(
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  );
}

export function formatNodeRenewal(node: NodeView) {
  if (!node.expire_at) {
    return "未设置";
  }
  const date = new Date(node.expire_at * 1000).toLocaleDateString("zh-CN");
  if (!node.auto_renew || !node.renew_interval_sec) {
    return date;
  }
  const seconds = node.renew_interval_sec;
  const short =
    seconds === 30 * 86400
      ? "月"
      : seconds === 90 * 86400
        ? "季"
        : seconds === 180 * 86400
          ? "半年"
          : seconds === 365 * 86400
            ? "年"
            : "";
  return short ? `${date} · ${short}` : date;
}
