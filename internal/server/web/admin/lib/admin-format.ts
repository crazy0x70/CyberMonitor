import type { GroupNode, NodeView, TestCatalogItem } from "@/lib/admin-types";

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

export function resolveNodeId(node: NodeView) {
  return node.stats.node_id || node.stats.node_name || "";
}

export function resolveNodeName(node: NodeView) {
  return node.alias || node.stats.node_alias || node.stats.node_name || node.stats.node_id;
}

export function flattenGroupTree(tree: GroupNode[]) {
  return (tree || [])
    .map((group) => ({
      group: group.name,
      tags: (group.children || []).map((tag) => tag.name),
    }))
    .filter((item) => item.group);
}

export function buildSelectionValues(group: string, tags: string[]) {
  if (!group) return [];
  if (!tags.length) return [group];
  return tags.map((tag) => `${group}:${tag}`);
}

export function parseSelectionValue(value: string) {
  const raw = String(value || "").trim();
  if (!raw) return { group: "", tag: "" };
  if (raw.includes(":")) {
    const [group, ...rest] = raw.split(":");
    return { group: group.trim(), tag: rest.join(":").trim() };
  }
  return { group: raw, tag: "" };
}

export function resolveProbeLabel(item: TestCatalogItem) {
  const type = (item.type || "icmp").toUpperCase();
  const host = item.host || "--";
  const port = item.port ? `:${item.port}` : "";
  return `${type} ${host}${port}`;
}
