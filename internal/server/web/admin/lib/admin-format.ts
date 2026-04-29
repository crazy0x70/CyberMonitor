import type {
  GroupNode,
  GroupSelection,
  NodeView,
  TestCatalogItem,
} from "@/lib/admin-types";

export function formatDateTime(value?: number) {
  if (!value) return "--";
  return new Date(value * 1000).toLocaleString("zh-CN", {
    hour12: false,
  });
}

export function formatRelativeTime(value?: number) {
  if (!value) return "--";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - value);
  if (diff < 5) return "刚刚";
  if (diff < 60) return `${diff} 秒前`;
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

export function formatBytes(value?: number) {
  const num = Number(value || 0);
  if (!Number.isFinite(num) || num <= 0) return "--";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = num;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  return `${current.toFixed(current >= 100 || index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatRate(value?: number) {
  const bytes = formatBytes(value);
  return bytes === "--" ? bytes : `${bytes}/s`;
}

export function formatMbps(value?: number) {
  const num = Number(value || 0);
  if (!Number.isFinite(num) || num <= 0) return "--";
  return `${num} Mbps`;
}

export function formatVersionLabel(value?: string | null) {
  const normalized = String(value || "").trim();
  if (!normalized) return "--";
  return normalized.startsWith("v") ? normalized : `v${normalized}`;
}

export function toDateInputValue(value?: number) {
  if (!value) return "";
  return new Date(value * 1000).toISOString().slice(0, 10);
}

export function parseDateInputValue(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const timestamp = new Date(`${trimmed}T00:00:00`).getTime();
  if (Number.isNaN(timestamp)) return 0;
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

export function buildSelectionValues(group: string, tags: string[]) {
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
  node: Pick<NodeView, "group" | "groups" | "tags" | "stats">,
) {
  return normalizeSelectionValues(
    Array.isArray(node.groups) && node.groups.length > 0
      ? node.groups
      : buildSelectionValues(node.group || node.stats.node_group || "", node.tags || []),
  );
}

export function resolveSelectionValues(values: string[]) {
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

export function resolveProbeLabel(item: TestCatalogItem) {
  const type = (item.type || "icmp").toUpperCase();
  const host = item.host || "--";
  const port = item.port ? `:${item.port}` : "";
  return `${type} ${host}${port}`;
}
