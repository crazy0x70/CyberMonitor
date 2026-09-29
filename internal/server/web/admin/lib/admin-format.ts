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

export function parseTelegramUserIds(raw: string) {
  return Array.from(
    new Set(
      raw
        .split(/[,，\s]+/)
        .map((item) => Number.parseInt(item.trim(), 10))
        .filter((item) => Number.isFinite(item) && item > 0),
    ),
  );
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

function resolveNodeFreshness(node: NodeView) {
  const statsTimestamp = Number(node.stats?.timestamp || 0);
  if (Number.isFinite(statsTimestamp) && statsTimestamp > 0) {
    return statsTimestamp;
  }
  const lastSeen = Number(node.last_seen || 0);
  return Number.isFinite(lastSeen) && lastSeen > 0 ? lastSeen : 0;
}

function shouldReplaceNodeView(existing: NodeView | undefined, candidate: NodeView) {
  if (!existing) {
    return true;
  }
  const candidateFreshness = resolveNodeFreshness(candidate);
  const existingFreshness = resolveNodeFreshness(existing);
  if (candidateFreshness !== existingFreshness) {
    return candidateFreshness > existingFreshness;
  }
  const candidateLastSeen = Number(candidate.last_seen || 0);
  const existingLastSeen = Number(existing.last_seen || 0);
  return candidateLastSeen >= existingLastSeen;
}

export function upsertNodeView(current: NodeView[], node: NodeView) {
  const nodeID = resolveNodeId(node).trim();
  if (!nodeID) {
    return current;
  }
  const index = current.findIndex((item) => resolveNodeId(item).trim() === nodeID);
  if (index < 0) {
    return [...current, node];
  }
  if (!shouldReplaceNodeView(current[index], node)) {
    return current;
  }
  const next = [...current];
  next[index] = node;
  return next;
}

export function resolveNodeName(node: NodeView) {
  return node.alias || node.stats.node_alias || node.stats.node_name || node.stats.node_id;
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

export function adminPageHref(page: AdminPage) {
  if (typeof window === "undefined") {
    return page === "dashboard" ? "/" : `/?${ADMIN_PAGE_QUERY_KEY}=${page}`;
  }
  let nextURL: URL;
  try {
    nextURL = new URL(window.location.href);
  } catch {

    return page === "dashboard" ? "/" : `/?${ADMIN_PAGE_QUERY_KEY}=${page}`;
  }
  if (page === "dashboard") {
    nextURL.searchParams.delete(ADMIN_PAGE_QUERY_KEY);
  } else {
    nextURL.searchParams.set(ADMIN_PAGE_QUERY_KEY, page);
  }
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
