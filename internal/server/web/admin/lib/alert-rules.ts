// =====================================================================
// A-01 步骤 1：共享告警规则元数据与草稿工具。
// 从 NotificationAlert.tsx 原样抽出（F4「告警策略」与节点抽屉共用）：
// 指标表、分组、单位、默认阈值、持续时间选项、草稿类型、草稿↔载荷转换
// （buildRulePayload 及其反向 makeRuleDraft）、校验函数与条件文案。
// 两页需保持同一规格——admin-i18n.ts 的 F4 正则模板共用，勿改文案格式。
// =====================================================================

import type { AlertRule, AlertScope, SettingsView } from "@/lib/admin-types";

export const OFFLINE_ALERT_RULE_ID = "offline";
// 新规则 id："r_" + 10 位随机字母数字，与后端 normalizeAlertRule 的生成规则一致。
export const ALERT_RULE_ID_PREFIX = "r_";

// 指标分组（F4 指标表）：资源 / 网络 / 探测 / 生命周期；阈值单位随指标。
// net_in / net_out 以 B/s 存储、UI 按 Mbps 输入（×125000 换算）；探测类必须
// 指定探测目标（probe_name）；offline / expiry / traffic_quota 为事件类规则，
// 不编辑 op / 持续时间。
export type AlertMetricGroupID = "resource" | "network" | "probe" | "lifecycle";

export interface AlertMetricSpec {
  value: string;
  label: string;
  unit: string;
  group: AlertMetricGroupID;
  kind: "threshold" | "event";
  inputMbps?: boolean;
  needsProbe?: boolean;
  defaultThreshold?: string;
}

export const ALERT_METRIC_GROUP_LABELS: Record<AlertMetricGroupID, string> = {
  resource: "资源",
  network: "网络",
  probe: "探测",
  lifecycle: "生命周期",
};

export const ALERT_METRIC_SPECS: AlertMetricSpec[] = [
  { value: "cpu", label: "CPU 使用率", unit: "%", group: "resource", kind: "threshold", defaultThreshold: "90" },
  { value: "load1", label: "1 分钟负载", unit: "", group: "resource", kind: "threshold", defaultThreshold: "1" },
  { value: "load5", label: "5 分钟负载", unit: "", group: "resource", kind: "threshold", defaultThreshold: "1" },
  { value: "load15", label: "15 分钟负载", unit: "", group: "resource", kind: "threshold", defaultThreshold: "1" },
  { value: "memory", label: "内存使用率", unit: "%", group: "resource", kind: "threshold", defaultThreshold: "90" },
  { value: "disk", label: "磁盘使用率", unit: "%", group: "resource", kind: "threshold", defaultThreshold: "90" },
  { value: "gpu", label: "GPU 使用率", unit: "%", group: "resource", kind: "threshold", defaultThreshold: "95" },
  { value: "gpu_temp", label: "GPU 温度", unit: "℃", group: "resource", kind: "threshold", defaultThreshold: "85" },
  { value: "net_in", label: "入站带宽", unit: "Mbps", group: "network", kind: "threshold", inputMbps: true, defaultThreshold: "100" },
  { value: "net_out", label: "出站带宽", unit: "Mbps", group: "network", kind: "threshold", inputMbps: true, defaultThreshold: "100" },
  { value: "tcp_conn", label: "TCP 连接数", unit: "个", group: "network", kind: "threshold", defaultThreshold: "1000" },
  { value: "process_count", label: "进程数", unit: "个", group: "network", kind: "threshold", defaultThreshold: "500" },
  { value: "probe_latency", label: "探测延迟", unit: "ms", group: "probe", kind: "threshold", needsProbe: true, defaultThreshold: "200" },
  { value: "probe_loss", label: "丢包率", unit: "%", group: "probe", kind: "threshold", needsProbe: true, defaultThreshold: "50" },
  { value: "expiry", label: "到期提醒", unit: "", group: "lifecycle", kind: "event" },
  { value: "traffic_quota", label: "流量配额", unit: "%", group: "lifecycle", kind: "event", defaultThreshold: "80" },
];

const ALERT_METRIC_SPEC_MAP = new Map(ALERT_METRIC_SPECS.map((spec) => [spec.value, spec]));

// 与后端 defaultExpiryLeadDay* 一致的默认提醒点。
export const DEFAULT_EXPIRY_LEAD_DAYS = [7, 3, 1];

// 持续时间选项（F4 定稿：立即 / 1 / 3 / 5 / 10 / 30 分钟）。
const RULE_DURATION_OPTIONS: Array<{ value: string; minutes: number; label: string }> = [
  { value: "0", minutes: 0, label: "立即" },
  { value: "60", minutes: 1, label: "1 分钟" },
  { value: "180", minutes: 3, label: "3 分钟" },
  { value: "300", minutes: 5, label: "5 分钟" },
  { value: "600", minutes: 10, label: "10 分钟" },
  { value: "1800", minutes: 30, label: "30 分钟" },
];

// 持续时间选项的共享抽屉渲染视图（value / label）。
export function ruleDurationChoices(): Array<{ value: string; label: string }> {
  return RULE_DURATION_OPTIONS.map(({ value, label }) => ({ value, label }));
}

// 持续时间秒 → 显示标签（选项内取选项 label，其余按分钟数显示）。
export function ruleDurationLabel(durationSec: number): string {
  return (
    RULE_DURATION_OPTIONS.find((item) => item.value === String(durationSec))?.label ||
    `${Math.max(1, Math.round(durationSec / 60))} 分钟`
  );
}

export const MBPS_TO_BYTES_PER_SEC = 125000;

export function alertMetricSpec(metric: string): AlertMetricSpec | undefined {
  return ALERT_METRIC_SPEC_MAP.get(metric);
}

export function alertMetricLabel(metric: string) {
  if (metric === OFFLINE_ALERT_RULE_ID) {
    return "节点离线";
  }
  return alertMetricSpec(metric)?.label || metric;
}

// 数值展示：toFixed(3) 后去尾零（90 → "90"，2.50 → "2.5"）。
export function trimRuleNumber(value: number) {
  return String(Number(value.toFixed(3)));
}

// 存储阈值 → 输入框值（net_in / net_out 按 Mbps 展示）。
export function alertThresholdToInput(metric: string, threshold: number | undefined) {
  const raw = Number(threshold || 0);
  if (alertMetricSpec(metric)?.inputMbps) {
    return trimRuleNumber(raw / MBPS_TO_BYTES_PER_SEC);
  }
  return trimRuleNumber(raw);
}

export function parseAlertThresholdInput(value: string): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

export function generateRuleID(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  let id = "";
  for (const byte of bytes) {
    id += alphabet[byte % alphabet.length];
  }
  return `${ALERT_RULE_ID_PREFIX}${id}`;
}

// 规则抽屉草稿：threshold 为输入框字符串（按指标单位），scope 拆为平铺数组。
export type AlertRuleDraft = {
  id: string;
  name: string;
  enabled: boolean;
  metric: string;
  op: string;
  threshold: string;
  durationSec: number;
  scopeMode: "all" | "include";
  scopeNodes: string[];
  scopeGroups: string[];
  scopeExclude: string[];
  channelIds: string[];
  notifyRecover: boolean;
  repeat: string;
  probeName: string;
  leadDays: number[];
};

export function normalizeRuleMetric(raw: string | undefined) {
  if (raw === OFFLINE_ALERT_RULE_ID || ALERT_METRIC_SPEC_MAP.has(raw || "")) {
    return raw as string;
  }
  return "cpu";
}

export function makeRuleDraft(rule: AlertRule): AlertRuleDraft {
  const metric = normalizeRuleMetric(rule.metric);
  return {
    id: rule.id || generateRuleID(),
    name: rule.name || "",
    enabled: rule.enabled !== false,
    metric,
    op: rule.op === "lt" ? "lt" : "gt",
    threshold: alertThresholdToInput(metric, rule.threshold),
    durationSec: Math.max(0, Math.round(Number(rule.duration_sec || 0))),
    scopeMode: rule.scope?.mode === "include" ? "include" : "all",
    scopeNodes: [...(rule.scope?.nodes || [])],
    scopeGroups: [...(rule.scope?.groups || [])],
    scopeExclude: [...(rule.scope?.exclude || [])],
    channelIds: [...(rule.channel_ids || [])],
    notifyRecover: rule.notify_recover !== false,
    repeat: rule.repeat === "backoff" ? "backoff" : "once",
    probeName: rule.probe_name || "",
    leadDays: [...(rule.lead_days || [])],
  };
}

export function makeRuleDrafts(settings: SettingsView | null): AlertRuleDraft[] {
  return (settings?.alert_rules ?? []).map(makeRuleDraft);
}

// 深拷贝规则草稿（抽屉表单与列表草稿不共享内部数组）。
export function copyRuleDraft(rule: AlertRuleDraft): AlertRuleDraft {
  return {
    ...rule,
    scopeNodes: [...rule.scopeNodes],
    scopeGroups: [...rule.scopeGroups],
    scopeExclude: [...rule.scopeExclude],
    channelIds: [...rule.channelIds],
    leadDays: [...rule.leadDays],
  };
}

// 规则草稿 → 后端 AlertRule 载荷（保存与模拟评估共用；Mbps 输入换算回 B/s，
// 空 channel_ids / lead_days 不下发，由服务端按缺省处理）。
export function buildRulePayload(draft: AlertRuleDraft): AlertRule {
  const spec = alertMetricSpec(draft.metric);
  const inputThreshold = parseAlertThresholdInput(draft.threshold) ?? 0;
  const threshold = spec?.inputMbps ? inputThreshold * MBPS_TO_BYTES_PER_SEC : inputThreshold;
  const scope: AlertScope = {
    mode: draft.scopeMode,
    nodes: draft.scopeMode === "include" ? draft.scopeNodes : [],
    groups: draft.scopeMode === "include" ? draft.scopeGroups : [],
    // D-05：exclude 无论哪种模式都原样提交（all 与 include 均生效）。
    exclude: draft.scopeExclude,
  };
  return {
    id: draft.id,
    name: draft.name.trim(),
    enabled: draft.enabled,
    metric: draft.metric,
    op: draft.op === "lt" ? "lt" : "gt",
    threshold,
    duration_sec: draft.durationSec,
    scope,
    channel_ids: draft.channelIds.length > 0 ? draft.channelIds : undefined,
    notify_recover: draft.notifyRecover,
    repeat: draft.repeat === "backoff" ? "backoff" : "once",
    probe_name: spec?.needsProbe ? draft.probeName : undefined,
    lead_days: draft.leadDays.length > 0 ? draft.leadDays : undefined,
  };
}

// 规则草稿校验：字段 key → 错误文案（抽屉内字段下方报错）。
export function validateRuleDraft(rule: AlertRuleDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!rule.name.trim()) {
    errors.name = "请输入规则名称。";
  }
  const spec = alertMetricSpec(rule.metric);
  if (spec?.kind === "threshold" && parseAlertThresholdInput(rule.threshold) === null) {
    errors.threshold = "请输入有效的阈值。";
  }
  if (spec?.needsProbe && !rule.probeName.trim()) {
    errors.probe = "请选择探测目标。";
  }
  if (rule.scopeMode === "include" && rule.scopeNodes.length === 0 && rule.scopeGroups.length === 0) {
    errors.scope = "指定范围时至少选择一个节点或分组。";
  }
  return errors;
}

// 分组 selection（"A" / "A:t"）→ 展示文本。
export function formatGroupSelectionLabel(selection: string) {
  const separator = selection.indexOf(":");
  if (separator < 0) {
    return selection;
  }
  return `${selection.slice(0, separator)} / ${selection.slice(separator + 1)}`;
}

// 列表「范围」列：「全部节点」/「N 个节点」/「分组：美国」等。
export function ruleScopeText(rule: AlertRuleDraft): string {
  if (rule.scopeMode === "include") {
    const parts: string[] = [];
    if (rule.scopeNodes.length > 0) {
      parts.push(`${rule.scopeNodes.length} 个节点`);
    }
    if (rule.scopeGroups.length > 0) {
      const first = formatGroupSelectionLabel(rule.scopeGroups[0]);
      parts.push(
        rule.scopeGroups.length > 1
          ? `分组：${first} 等 ${rule.scopeGroups.length} 项`
          : `分组：${first}`,
      );
    }
    return parts.join(" · ");
  }
  return rule.scopeExclude.length > 0 ? `全部节点 · 排除 ${rule.scopeExclude.length} 台` : "全部节点";
}

// 列表 / 行内「条件」文案：「CPU 使用率 > 90% · 持续 5 分钟」这类描述。
export function ruleConditionText(rule: AlertRuleDraft): string {
  if (rule.metric === OFFLINE_ALERT_RULE_ID) {
    return `离线判定 ${Math.max(1, Math.round(rule.durationSec / 60))} 分钟`;
  }
  const spec = alertMetricSpec(rule.metric);
  if (!spec) {
    return "—";
  }
  if (spec.kind === "event") {
    if (rule.metric === "expiry") {
      const days = rule.leadDays.length > 0 ? rule.leadDays : DEFAULT_EXPIRY_LEAD_DAYS;
      return `提前 ${days.join(" · ")} 天提醒`;
    }
    const startPct = parseAlertThresholdInput(rule.threshold) ?? 80;
    return `流量配额 ≥ ${trimRuleNumber(startPct)}%`;
  }
  const op = rule.op === "lt" ? "<" : ">";
  const threshold = parseAlertThresholdInput(rule.threshold) ?? 0;
  const thresholdText = spec.inputMbps
    ? `${trimRuleNumber(threshold)} Mbps`
    : `${trimRuleNumber(threshold)}${spec.unit}`;
  const probeSuffix = spec.needsProbe && rule.probeName ? `（${rule.probeName}）` : "";
  let condition = `${spec.label}${probeSuffix} ${op} ${thresholdText}`;
  if (rule.durationSec > 0) {
    condition += ` · 持续 ${Math.round(rule.durationSec / 60)} 分钟`;
  }
  return condition;
}

// 模拟评估结果值：按指标单位展示（net_in/net_out B/s → Mbps；offline 为秒数）。
export function formatRulePreviewValue(metric: string, value: number): string {
  if (metric === OFFLINE_ALERT_RULE_ID) {
    return `${Math.round(value)} 秒`;
  }
  if (metric === "expiry") {
    return `${Math.round(value)} 天`;
  }
  const spec = alertMetricSpec(metric);
  if (!spec) {
    return trimRuleNumber(value);
  }
  if (spec.inputMbps) {
    return `${(value * 8 / 1e6).toFixed(1)} Mbps`;
  }
  if (metric === "load1" || metric === "load5" || metric === "load15") {
    return value.toFixed(2);
  }
  if (metric === "tcp_conn" || metric === "process_count") {
    return `${Math.round(value)}${spec.unit}`;
  }
  return `${value.toFixed(1)}${spec.unit}`;
}
