import { useEffect, useMemo, useRef, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import {
  AdminDataTable,
  type AdminDataTableColumn,
  adminStatusBadgeClass,
} from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import { AlertRuleDrawer } from "@/components/alert-rule-drawer";
import {
  Check,
  ChevronRight,
  ChevronsUpDown,
  FolderTree,
  Loader2,
  Plus,
  RefreshCw,
  Rocket,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  AdminGroupedFieldRow,
  AdminGroupedSwitchRow,
} from "@/components/admin-section-panel";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { useAsyncAction, useDirtyNotification } from "@/lib/admin-hooks";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  DEFAULT_TCP_INTERVAL, MAX_TCP_INTERVAL, type AgentUpdateInfo,
  AlertRule,
  NodeDeleteResponse,
  NodeProfilePayload,
  NodeView,
  SettingsUpdate,
  SettingsView,
  TestCatalogItem,
  TestSelection, } from "@/lib/admin-types";
import {
  flattenGroupTree,
  formatNodeRenewal,
  formatVersionLabel,
  getErrorMessage,
  normalizeSelectionValues,
  parseDateTimeLocalValue,
  resolveNodeSelectionValues,
  resolveNodeIdentitySummary,
  parseSelectionValue,
  resolveNodeId,
  resolveNodeName,
  toDateTimeLocalValue,
  upsertSelectionValue,
} from "@/lib/admin-format";
import {
  buildAgentInstallCommand,
  buildAgentWindowsInstallCommand,
} from "@/lib/agent-install";
import {
  adminActionButtonClass,
  adminCodeBlockPanelClass,
  adminCompactActionButtonClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDangerOutlineButtonClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminHelpTextClass,
  adminInputClass,
  adminOutlineButtonClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminSegmentedItemActiveClass,
  adminSegmentedItemClass,
  adminSegmentedItemInactiveClass,
  adminSegmentedTrackClass,
  adminSubtleOutlineBadgeClass,
} from "@/lib/admin-ui";
import {
  OFFLINE_ALERT_RULE_ID,
  buildRulePayload,
  copyRuleDraft,
  generateRuleID,
  makeRuleDraft,
  ruleConditionText,
  type AlertRuleDraft,
} from "@/lib/alert-rules";
import { fetchSettings } from "@/lib/admin-api";

const maxTestsPerNode = 128;

const REGION_ALIASES: Record<string, string> = {
  新加坡: "SG", 日本: "JP", 香港: "HK", 中国香港: "HK", 台湾: "TW",
  中国台湾: "TW", 美国: "US", 英国: "UK", 加拿大: "CA", 德国: "DE",
  法国: "FR", 荷兰: "NL", 中国: "CN", 中国大陆: "CN", 韩国: "KR",
  澳门: "MO", 澳大利亚: "AU", 俄罗斯: "RU",
  singapore: "SG", japan: "JP", "hong kong": "HK", hongkong: "HK",
  taiwan: "TW", "united states": "US", usa: "US", "united kingdom": "UK",
  uk: "UK", canada: "CA", germany: "DE", france: "FR", netherlands: "NL",
  china: "CN", korea: "KR", macau: "MO", macao: "MO", australia: "AU",
  russia: "RU",
};

function normalizeRegionInput(value: string): string {
  const key = value.trim().toLowerCase();
  if (!key) return "";
  const mapped = REGION_ALIASES[key];
  if (mapped) return mapped;
  const upper = key.toUpperCase();
  return /^[A-Z]{2}$/.test(upper) ? upper : "";
}

const outlineActionClass = `${adminOutlineButtonClass} h-9 px-4`;

const agentInstallLinuxId = "server-management-agent-install-linux";

const agentInstallWindowsId = "server-management-agent-install-windows";

type RenewPlan = "none" | "month" | "quarter" | "half" | "year";

// A-01 步骤 3：「续费周期」下拉的中文标签（与 RenewPlan 一一对应，不增删选项）。
const RENEW_PLAN_LABELS: Record<RenewPlan, string> = {
  none: "不续费",
  month: "每月",
  quarter: "每季",
  half: "每半年",
  year: "每年",
};

type SelectionDraft = Record<string, string>;
type GroupCatalogItem = {
  group: string;
  tags: string[];
};

type SelectedGroupState = {
  count: number;
  items: Array<{
    value: string;
    label: string;
    level: string;
  }>;
  label: string;
  stats: Map<
    string,
    {
      groupSelected: boolean;
      selectedTags: Set<string>;
    }
  >;
};

type NodeListEntry = {
  node: NodeView;
  nodeGroups: string[];
  nodeId: string;
  nodeName: string;
  statusRank: number;
  searchText: string;
};

type FormState = {
  alias: string;
  region: string;
  diskType: string;
  netSpeedMbps: string;
  alertEnabled: boolean;
  visibleInCR: boolean;
  visibleInAll: boolean;
  expireAt: string;
  renewPlan: RenewPlan;
  groups: string[];
  testSelections: SelectionDraft;
  // A-02 流量配额：配额为数值文本 + 单位（TB / GB / MB，D-06 十进制，空 = 不限量）；
  // 计算方式与重置日为 Select 字符串。
  trafficLimitValue: string;
  trafficLimitUnit: TrafficLimitUnit;
  trafficLimitType: "sum" | "max" | "up" | "down";
  trafficResetDay: string;
};

type TestDraftEntry = {
  item: TestCatalogItem;
  itemId: string;
  active: boolean;
  isTCP: boolean;
  intervalValue: string;
  defaultIntervalSec: number;
};

type TestDraftState = {
  items: TestDraftEntry[];
  summary: {
    selected: number;
    tcpCustom: number;
  };
};

export interface ServerManagementProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  loading?: boolean;
  onDirtyChange?: (dirty: boolean) => void;
  onCheckAgentUpdate: (nodeID: string) => Promise<AgentUpdateInfo>;
  onRefresh: () => Promise<void>;
  onSaveNode: (nodeID: string, payload: NodeProfilePayload) => Promise<void>;
  onDeleteNode: (nodeID: string) => Promise<NodeDeleteResponse>;
  onTriggerAgentUpdate: (nodeID: string) => Promise<{ status: string; target_version?: string }>;
  // F4：节点抽屉「为此节点新增规则」的保存通道（App 的 updateSettings），
  // 走统一通道保存 alert_rules 并同步刷新 App 内 settings 状态。
  onSaveSettings?: (payload: SettingsUpdate) => Promise<SettingsView>;
}


function planToSeconds(plan: RenewPlan) {
  switch (plan) {
    case "month":
      return 30 * 86400;
    case "quarter":
      return 90 * 86400;
    case "half":
      return 180 * 86400;
    case "year":
      return 365 * 86400;
    default:
      return 0;
  }
}

function resolveRenewPlan(autoRenew?: boolean, renewIntervalSec?: number): RenewPlan {
  if (!autoRenew || !renewIntervalSec) {
    return "none";
  }
  const targets = [
    { key: "month" as const, seconds: 30 * 86400 },
    { key: "quarter" as const, seconds: 90 * 86400 },
    { key: "half" as const, seconds: 180 * 86400 },
    { key: "year" as const, seconds: 365 * 86400 },
  ];
  return targets.reduce(
    (best, current) =>
      Math.abs(renewIntervalSec - current.seconds) < Math.abs(renewIntervalSec - best.seconds)
        ? current
        : best,
    targets[0],
  ).key;
}

function defaultInterval(item?: TestCatalogItem) {
  const raw = Number(item?.interval_sec || 0);
  if (!Number.isFinite(raw) || raw <= 0) {
    // F2：ICMP 的 0 表示持续（跟随 agent tick），不回落到 TCP 的 5 秒。
    return isTCPTest(item) ? DEFAULT_TCP_INTERVAL : 0;
  }
  return Math.min(Math.trunc(raw), MAX_TCP_INTERVAL);
}

function isTCPTest(test?: Partial<TestCatalogItem>) {
  return String(test?.type || "icmp").trim().toLowerCase() === "tcp";
}

function hasTestSelection(testSelections: SelectionDraft, testID?: string) {
  return Boolean(testID && Object.prototype.hasOwnProperty.call(testSelections, testID));
}

function buildTestSelectionValue(item?: TestCatalogItem, intervalSec?: number) {
  // F2：icmp 与 tcp 同语义——selection > 目录条目间隔 > 类型回退（icmp 0 = 持续）。
  const rawInterval = Math.trunc(Number(intervalSec) || 0);
  return String(
    Number.isFinite(rawInterval) && rawInterval > 0
      ? Math.min(rawInterval, MAX_TCP_INTERVAL)
      : defaultInterval(item),
  );
}

function parseTestSelectionInterval(item: TestCatalogItem, rawValue: string) {
  const parsedInterval = Number.parseInt(rawValue, 10);
  return Number.isFinite(parsedInterval) && parsedInterval >= 0
    ? Math.min(parsedInterval, MAX_TCP_INTERVAL)
    : defaultInterval(item);
}

function buildTestDraftEntries(
  catalog: TestCatalogItem[],
  testSelections?: SelectionDraft,
): TestDraftEntry[] {
  const draft = testSelections || {};

  return catalog.map((item) => {
    const itemId = item.id || "";
    return {
      item,
      itemId,
      active: hasTestSelection(draft, itemId),
      isTCP: isTCPTest(item),
      intervalValue: itemId ? draft[itemId] || "" : "",
      defaultIntervalSec: defaultInterval(item),
    };
  });
}

function buildTestDraftState(
  catalog: TestCatalogItem[],
  testSelections?: SelectionDraft,
): TestDraftState {
  const items = buildTestDraftEntries(catalog, testSelections);
  let selected = 0;
  let tcpCustom = 0;

  items.forEach(({ active, isTCP, intervalValue, defaultIntervalSec }) => {
    if (active) {
      selected += 1;
      if (isTCP) {
        const currentValue = Number.parseInt(intervalValue, 10);
        if (Number.isFinite(currentValue) && currentValue !== defaultIntervalSec) {
          tcpCustom += 1;
        }
      }
    }
  });

  return {
    items,
    summary: {
      selected,
      tcpCustom,
    },
  };
}

function buildInitialSelections(node: NodeView, catalog: TestCatalogItem[]) {
  const selections: SelectionDraft = {};
  const meta = new Map<string, TestCatalogItem>();

  catalog.forEach((item) => {
    if (item.id) {
      meta.set(item.id, item);
    }
  });

  if (Array.isArray(node.test_selections) && node.test_selections.length > 0) {
    node.test_selections.forEach((selection) => {
      if (!selection?.test_id) {
        return;
      }
      const matched = meta.get(selection.test_id);
      selections[selection.test_id] = buildTestSelectionValue(matched, selection.interval_sec);
    });
    return selections;
  }

  return selections;
}

function buildFormState(node: NodeView, catalog: TestCatalogItem[]): FormState {
  const resetDay = Number(node.traffic_reset_day || 0);
  return {
    alias: node.alias || node.stats.node_alias || "",
    region: node.region || "",
    visibleInCR: node.hidden_from_cr !== true,
    visibleInAll: node.hidden_from_all !== true,
    diskType: node.disk_type || "",
    netSpeedMbps: node.net_speed_mbps ? String(node.net_speed_mbps) : "",
    alertEnabled: node.alert_enabled !== false,
    expireAt: toDateTimeLocalValue(node.expire_at),
    renewPlan: resolveRenewPlan(node.auto_renew, node.renew_interval_sec),
    groups: resolveNodeSelectionValues(node),
    testSelections: buildInitialSelections(node, catalog),
    trafficLimitValue: trafficBytesToUnitInput(Number(node.traffic_limit_bytes || 0)).value,
    trafficLimitUnit: trafficBytesToUnitInput(Number(node.traffic_limit_bytes || 0)).unit,
    trafficLimitType: normalizeTrafficLimitTypeInput(node.traffic_limit_type),
    trafficResetDay: resetDay >= 1 && resetDay <= 28 ? String(resetDay) : "1",
  };
}

function formDraftSignature(form: FormState) {
  return JSON.stringify({
    alias: form.alias,
    alertEnabled: form.alertEnabled,
    visibleInCR: form.visibleInCR,
    visibleInAll: form.visibleInAll,
    diskType: form.diskType,
    expireAt: form.expireAt,
    groups: normalizeSelectionValues(form.groups),
    netSpeedMbps: form.netSpeedMbps,
    region: form.region,
    renewPlan: form.renewPlan,
    trafficLimitValue: form.trafficLimitValue,
    trafficLimitUnit: form.trafficLimitUnit,
    trafficLimitType: form.trafficLimitType,
    trafficResetDay: form.trafficResetDay,
    testSelections: Object.entries(form.testSelections)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [key, value]),
  });
}

function formSourceSignature(form: FormState, catalogSignature: string) {
  return JSON.stringify({
    draft: formDraftSignature(form),
    testCatalog: catalogSignature,
  });
}

function buildPayload(
  form: FormState,
  catalog: TestCatalogItem[],
  catalogLoaded: boolean,
): NodeProfilePayload {
  const expireAt = parseDateTimeLocalValue(form.expireAt);
  if (form.expireAt && !expireAt) {
    throw new Error("到期时间格式无效，请重新选择");
  }

  const autoRenew = expireAt > 0 && form.renewPlan !== "none";
  const renewIntervalSec = autoRenew ? planToSeconds(form.renewPlan) : 0;
  const normalizedSpeed = Number.parseInt(form.netSpeedMbps, 10);

  const region = normalizeRegionInput(form.region);
  if (form.region.trim() && !region) {
    throw new Error("地区代码无效：请输入两位字母代码（如 SG / JP / HK）。");
  }

  // A-02 流量配额：数值 × 单位（D-06 十进制倍率）→ 字节（空 = 0 即不限量；
  // 非法输入直接报错，不做静默回退；最多两位小数）。
  const trafficLimitInput = form.trafficLimitValue.trim();
  let trafficLimitBytes = 0;
  if (trafficLimitInput) {
    const dotIndex = trafficLimitInput.indexOf(".");
    if (dotIndex >= 0 && trafficLimitInput.length - dotIndex - 1 > 2) {
      throw new Error("配额需为大于或等于 0 的数字，最多两位小数。");
    }
    const trafficLimit = Number(trafficLimitInput);
    if (!Number.isFinite(trafficLimit) || trafficLimit < 0 || !hasAtMostTwoDecimals(trafficLimit)) {
      throw new Error("配额需为大于或等于 0 的数字，最多两位小数。");
    }
    trafficLimitBytes = Math.round(trafficLimit * TRAFFIC_UNIT_BYTES[form.trafficLimitUnit]);
  }
  const trafficResetDay = Number.parseInt(form.trafficResetDay, 10);

  const payload: NodeProfilePayload = {
    alias: form.alias.trim(),
    alert_enabled: form.alertEnabled,
    hide_from_cr: !form.visibleInCR,
    hide_from_all: !form.visibleInAll,
    auto_renew: autoRenew,
    disk_type: form.diskType.trim(),
    groups: normalizeSelectionValues(form.groups),
    net_speed_mbps:
      Number.isFinite(normalizedSpeed) && normalizedSpeed >= 0 ? normalizedSpeed : 0,
    region,
    traffic_limit_bytes: trafficLimitBytes,
    traffic_limit_type: form.trafficLimitType,
    traffic_reset_day: trafficResetDay >= 1 && trafficResetDay <= 28 ? trafficResetDay : 1,
  };

  // 探测项目录未加载（settings 请求失败）时不得下发 test_selections：
  // 省略该键表示服务端保持节点已下发的探测项不变，避免静默清空。
  // 目录已加载时，即使 selections 为空也必须下发 [] 以清空
  // （运维主动取消勾选全部探测项属合法路径）。
  if (catalogLoaded) {
    const selections: TestSelection[] = buildTestDraftEntries(catalog, form.testSelections)
      .filter((entry) => entry.active && entry.itemId)
      .map(({ item, itemId, intervalValue }) => ({
        test_id: itemId,
        interval_sec: parseTestSelectionInterval(item, intervalValue),
      }));
    payload.test_selections = selections;
  }

  payload.expire_at = expireAt;
  if (renewIntervalSec > 0) {
    payload.renew_interval_sec = renewIntervalSec;
  }

  return payload;
}

async function copyTextToClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("copy failed");
  }
}

// A-09 第 5 条：状态徽标统一规格（高 20px、--r-full、前置 6px 圆点、无边框），
// 在线 ok / 离线 danger。
function renderStatusBadge(status: string) {
  if (status === "online") {
    return <span className={adminStatusBadgeClass("ok")}>在线</span>;
  }
  return <span className={adminStatusBadgeClass("danger")}>离线</span>;
}

const nodeTableColumns: ReadonlyArray<AdminDataTableColumn<NodeListEntry>> = [
  {
    key: "name",
    label: "名称",
    align: "left",
    render: (entry) => (
      <span className="flex min-w-0 items-center gap-2">
        <span
          className="min-w-0 truncate text-sm font-medium text-[var(--label-1)]"
          title={entry.nodeName}
        >
          {entry.nodeName}
        </span>
        {renderStatusBadge(entry.node.status)}
        {entry.node.alert_enabled === false ? (
          <span className={adminStatusBadgeClass("warn")}>告警已关闭</span>
        ) : null}
      </span>
    ),
  },
  {
    key: "ipv4",
    label: "IPv4",
    width: "160px",
    mono: true,
    render: (entry) => {
      const value = String(entry.node.stats.public_ipv4 || "").trim();
      return value ? (
        <span className="data-text block truncate text-sm" title={value}>{value}</span>
      ) : (
        <span className="text-sm text-[var(--label-3)]">--</span>
      );
    },
  },
  {
    key: "ipv6",
    label: "IPv6",
    width: "240px",
    mono: true,
    render: (entry) => {
      const value = String(entry.node.stats.public_ipv6 || "").trim();
      return value ? (
        <span className="data-text block truncate text-sm" title={value}>{value}</span>
      ) : (
        <span className="text-sm text-[var(--label-3)]">--</span>
      );
    },
  },
  {
    key: "agent",
    label: "Agent",
    width: "96px",
    mono: true,
    render: (entry) => formatVersionLabel(entry.node.stats.agent_version),
  },
  {
    key: "renew",
    label: "续期",
    width: "180px",
    render: (entry) => formatNodeRenewal(entry.node),
  },
];

function escapeSelectorValue(value: string) {
  if (typeof CSS !== "undefined" && typeof CSS.escape === "function") {
    return CSS.escape(value);
  }
  return value.replace(/"/g, '\\"');
}

function buildGroupCatalog(
  tree: SettingsView["group_tree"] | undefined,
  nodeListEntries: NodeListEntry[],
): GroupCatalogItem[] {
  const values = new Map<string, Set<string>>();

  flattenGroupTree(tree || []).forEach((item) => {
    const group = String(item.group || "").trim();
    if (!group) {
      return;
    }
    if (!values.has(group)) {
      values.set(group, new Set());
    }
    item.tags.forEach((tag) => {
      const normalized = String(tag || "").trim();
      if (normalized) {
        values.get(group)?.add(normalized);
      }
    });
  });

  nodeListEntries.forEach((entry) => {
    entry.nodeGroups.forEach((value) => {
      const parsed = parseSelectionValue(value);
      const group = String(parsed.group || "").trim();
      const tag = String(parsed.tag || "").trim();
      if (!group) {
        return;
      }
      if (!values.has(group)) {
        values.set(group, new Set());
      }
      if (tag) {
        values.get(group)?.add(tag);
      }
    });
  });

  return Array.from(values.entries())
    .map(([group, tags]) => ({
      group,
      tags: Array.from(tags).sort((a, b) => a.localeCompare(b, "zh-CN")),
    }))
    .sort((a, b) => a.group.localeCompare(b.group, "zh-CN"));
}

function buildSelectedGroupState(values: string[] | undefined): SelectedGroupState {
  const items: SelectedGroupState["items"] = [];
  const stats = new Map<
    string,
    {
      groupSelected: boolean;
      selectedTags: Set<string>;
    }
  >();
  normalizeSelectionValues(values || []).forEach((normalized) => {
    const parsed = parseSelectionValue(normalized);
    const group = String(parsed.group || "").trim();
    const tag = String(parsed.tag || "").trim();
    if (!group) {
      return;
    }

    items.push({
      value: normalized,
      label: tag ? `${group} / ${tag}` : group,
      level: tag ? "标签" : "分组",
    });

    const current = stats.get(group) || {
      groupSelected: false,
      selectedTags: new Set<string>(),
    };
    if (tag) {
      current.selectedTags.add(tag);
    } else {
      current.groupSelected = true;
    }
    stats.set(group, current);
  });

  let label = "请选择分组与标签";
  if (items.length === 1) {
    label = items[0].label;
  } else if (items.length > 1) {
    label = `${items[0].label} 等 ${items.length} 项`;
  }

  return {
    count: items.length,
    items,
    label,
    stats,
  };
}

// A-02 流量配额单位（D-06 十进制：1 TB = 1000 GB = 1,000,000 MB）。
const TRAFFIC_UNITS = ["TB", "GB", "MB"] as const;
type TrafficLimitUnit = (typeof TRAFFIC_UNITS)[number];
const TRAFFIC_UNIT_BYTES: Record<TrafficLimitUnit, number> = {
  TB: 10 ** 12,
  GB: 10 ** 9,
  MB: 10 ** 6,
};

// 计算方式下拉的中文标签（A-02）。
const TRAFFIC_LIMIT_TYPE_LABELS: Record<"sum" | "max" | "up" | "down", string> = {
  sum: "上下行合计",
  max: "取较大值",
  up: "仅上行",
  down: "仅下行",
};

// 值 ≤ 2 位小数即可精确表示（浮点容差内）。
function hasAtMostTwoDecimals(value: number): boolean {
  return Math.abs(Math.round(value * 100) - value * 100) < 1e-6;
}

// 字节 → 输入框（数值 + 单位）：从 TB → GB → MB 依次尝试，取第一个使
// 「数值 ≥ 1 且最多 2 位小数即可精确表示」的单位；都不满足时用 MB 保留 2 位
// 小数；未设置（0）时默认单位 GB。
function trafficBytesToUnitInput(bytes: number): { value: string; unit: TrafficLimitUnit } {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return { value: "", unit: "GB" };
  }
  for (const unit of TRAFFIC_UNITS) {
    const scaled = bytes / TRAFFIC_UNIT_BYTES[unit];
    if (scaled >= 1 && hasAtMostTwoDecimals(scaled)) {
      return { value: String(Number(scaled.toFixed(2))), unit };
    }
  }
  return { value: (bytes / TRAFFIC_UNIT_BYTES.MB).toFixed(2), unit: "MB" };
}

// =====================================================================
// F4 节点抽屉个性化：适用告警规则列表、单节点规则抽屉（Scope 预设当前节点）
// 与流量配额。A-01 步骤 1 起规则元数据 / 校验 / 抽屉已抽到 lib/alert-rules.ts
// 与 components/alert-rule-drawer.tsx（两页共用），此处仅保留节点侧的
// 范围匹配与流量配额换算。
// =====================================================================

// 「仅此节点」判定：include 且 nodes 恰好为 [本节点] 且无分组。
function isNodeOnlyRule(rule: AlertRuleDraft, nodeID: string): boolean {
  return (
    rule.scopeMode === "include" &&
    rule.scopeNodes.length === 1 &&
    rule.scopeNodes[0] === nodeID &&
    rule.scopeGroups.length === 0
  );
}

// A-01 步骤 3（D-08）：两条规则载荷除 scope.exclude 外是否相同（用于保存合并时
// 「仅改 exclude 只替换该规则的 scope.exclude」，保留别处对其他字段的最新修改）。
function rulePayloadSameExceptExclude(a: AlertRule, b: AlertRule): boolean {
  return (
    (a.id || "") === (b.id || "") &&
    (a.name || "") === (b.name || "") &&
    (a.enabled !== false) === (b.enabled !== false) &&
    (a.metric || "") === (b.metric || "") &&
    (a.op || "gt") === (b.op || "gt") &&
    Number(a.threshold || 0) === Number(b.threshold || 0) &&
    Number(a.duration_sec || 0) === Number(b.duration_sec || 0) &&
    JSON.stringify(a.channel_ids || []) === JSON.stringify(b.channel_ids || []) &&
    (a.notify_recover !== false) === (b.notify_recover !== false) &&
    (a.repeat || "once") === (b.repeat || "once") &&
    (a.probe_name || "") === (b.probe_name || "") &&
    JSON.stringify(a.lead_days || []) === JSON.stringify(b.lead_days || []) &&
    (a.scope?.mode || "") === (b.scope?.mode || "") &&
    JSON.stringify(a.scope?.nodes || []) === JSON.stringify(b.scope?.nodes || []) &&
    JSON.stringify(a.scope?.groups || []) === JSON.stringify(b.scope?.groups || [])
  );
}

// A-01 步骤 3（D-08）：把节点抽屉的规则草稿差异按规则 ID 应用到最新 alert_rules：
// 新增追加到末尾；删除按 ID 移除；修改按 ID 整条替换（仅改 exclude 时只替换该规则
// 的 scope.exclude）。latest 中已不存在的被修改规则跳过并返回其名称供 toast 提示。
function mergeNodeRuleDrafts(
  baseline: AlertRule[],
  current: AlertRuleDraft[],
  latest: AlertRule[],
): { rules: AlertRule[]; modifiedButMissing: string[] } {
  const baselineById = new Map(baseline.map((rule) => [rule.id || "", rule]));
  const currentPayloads = current.map(buildRulePayload);
  const currentById = new Map(currentPayloads.map((rule) => [rule.id || "", rule]));
  const displayName = (rule: AlertRule) =>
    rule.name?.trim() || (rule.metric === OFFLINE_ALERT_RULE_ID ? "节点离线" : rule.id || "");

  const rules: AlertRule[] = [];
  const modifiedButMissing: string[] = [];
  for (const rule of latest) {
    const id = rule.id || "";
    const draft = currentById.get(id);
    if (!draft) {
      // 草稿中不存在：基线里有 = 本抽屉删除；基线里没有 = 与草稿无关的新规则。
      if (!baselineById.has(id)) {
        rules.push(rule);
      }
      continue;
    }
    const baselineRule = baselineById.get(id);
    const changed = !baselineRule || JSON.stringify(baselineRule) !== JSON.stringify(draft);
    if (changed && rulePayloadSameExceptExclude(rule, draft)) {
      // 仅改 exclude：保留最新规则的其他字段，只替换 scope.exclude。
      rules.push({
        ...rule,
        scope: { ...rule.scope, exclude: [...(draft.scope?.exclude || [])] },
      });
      continue;
    }
    rules.push(draft);
  }
  // 新增：基线中无、草稿中有。latest 中已存在同 ID（别处已建）时不重复追加。
  for (const draft of currentPayloads) {
    const id = draft.id || "";
    if (baselineById.has(id)) {
      const baselineRule = baselineById.get(id)!;
      const changed = JSON.stringify(baselineRule) !== JSON.stringify(draft);
      if (changed && !latest.some((rule) => rule.id === id)) {
        modifiedButMissing.push(displayName(draft));
      }
      continue;
    }
    if (!latest.some((rule) => rule.id === id)) {
      rules.push(draft);
    }
  }
  return { rules, modifiedButMissing };
}

// 计算方式输入归一：后端 normalizeTrafficLimitType 对未知值回落 sum。
function normalizeTrafficLimitTypeInput(raw: string | undefined): "sum" | "max" | "up" | "down" {
  return raw === "max" || raw === "up" || raw === "down" ? raw : "sum";
}

export default function ServerManagement({
  settings,
  nodes,
  loading = false,
  onDirtyChange,
  onCheckAgentUpdate,
  onRefresh,
  onSaveNode,
  onDeleteNode,
  onSaveSettings,
  onTriggerAgentUpdate,
}: ServerManagementProps) {
  const [search, setSearch] = useState("");
  const [editingNodeId, setEditingNodeId] = useState("");
  const [form, setForm] = useState<FormState | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [updateAllDialogOpen, setUpdateAllDialogOpen] = useState(false);
  const [updatingAllAgents, setUpdatingAllAgents] = useState(false);
  const [refreshingAgentUpdate, setRefreshingAgentUpdate] = useState(false);
  const [agentUpdateInfo, setAgentUpdateInfo] = useState<AgentUpdateInfo | null>(null);
  const [updatingAgent, setUpdatingAgent] = useState(false);
  const [sourceConflict, setSourceConflict] = useState(false);
  const [installPlatform, setInstallPlatform] = useState<"unix" | "windows">("unix");
  // A-01 步骤 3（D-08）：节点抽屉的规则草稿（完整列表，AlertRuleDraft 形态）与
  // 打开抽屉时的基线（settings.alert_rules 的原始存储形态）。抽屉内的全部规则
  // 操作只改草稿，随「保存配置」一次提交；「取消」放弃。
  const [nodeRules, setNodeRules] = useState<AlertRuleDraft[] | null>(null);
  const nodeRulesBaselineRef = useRef<AlertRule[] | null>(null);
  // 共享规则抽屉的当前编辑对象（新增时为预设草稿）。
  const [nodeRuleForm, setNodeRuleForm] = useState<AlertRuleDraft | null>(null);
  const formInitializationKeyRef = useRef("");
  const formBaselineSignatureRef = useRef("");
  const formSourceSignatureRef = useRef("");
  const agentUpdateRequestSeqRef = useRef(0);
  const lastOpenedNodeCardRef = useRef("");
  const restoreFocusTimerRef = useRef<number | null>(null);
  const nodeDrawerBodyRef = useRef<HTMLDivElement>(null);
  const nodeRuleDrawerReturnRef = useRef<{ scrollTop: number; trigger: HTMLElement | null }>({
    scrollTop: 0,
    trigger: null,
  });
  const addNodeRuleButtonRef = useRef<HTMLButtonElement | null>(null);
  const runAction = useAsyncAction();

  const testCatalog = settings?.test_catalog || [];
  // 区分「catalog 未知」（settings 尚未/未能加载）与「catalog 确实为空」
  // （运维真的没配探测项）。只有前者才禁止下发 test_selections。
  const catalogLoaded = settings !== null;
  const testCatalogSignature = useMemo(
    () =>
      JSON.stringify(
        testCatalog.map((item) => [
          item.id || "",
          item.type || "",
          item.host || "",
          Number(item.port || 0),
          Number(item.interval_sec || 0),
        ]),
      ),
    [testCatalog],
  );
  const { metrics, nodeListEntries, nodeLookup } = useMemo(() => {
    const entries: NodeListEntry[] = [];
    const lookup = new Map<string, NodeView>();
    let online = 0;
    let ungrouped = 0;

    nodes.forEach((node) => {
      if (node.status === "online") {
        online += 1;
      }

      const nodeId = resolveNodeId(node);
      const nodeName = resolveNodeName(node);
      const nodeGroups = resolveNodeSelectionValues(node);
      if (nodeGroups.length === 0) {
        ungrouped += 1;
      }
      entries.push({
        node,
        nodeGroups,
        nodeId,
        nodeName,
        statusRank: node.status === "online" ? 0 : 1,
        searchText: [nodeName, nodeId, node.stats.hostname, node.region, ...nodeGroups]
          .filter(Boolean)
          .join(" ")
          .toLowerCase(),
      });
      lookup.set(nodeId, node);
    });

    return {
      metrics: {
        total: nodes.length,
        online,
        offline: nodes.length - online,
        ungrouped,
      },
      nodeListEntries: entries,
      nodeLookup: lookup,
    };
  }, [nodes]);

  const groupCatalog = useMemo(
    () => buildGroupCatalog(settings?.group_tree, nodeListEntries),
    [nodeListEntries, settings?.group_tree],
  );

  const sortedNodeListEntries = useMemo(
    () =>
      [...nodeListEntries].sort((a, b) => {
        if (a.statusRank !== b.statusRank) {
          return a.statusRank - b.statusRank;
        }
        return a.nodeName.localeCompare(b.nodeName, "zh-CN");
      }),
    [nodeListEntries],
  );

  const metricItems = [
    { label: "节点总数", value: metrics.total },
    { label: "在线节点", value: metrics.online },
    { label: "离线节点", value: metrics.offline },
    { label: "未分组节点", value: metrics.ungrouped },
  ] as const;

  const filteredNodes = useMemo(() => {
    const keyword = search.trim().toLowerCase();
    if (!keyword) {
      return sortedNodeListEntries;
    }
    return sortedNodeListEntries.filter((entry) => entry.searchText.includes(keyword));
  }, [search, sortedNodeListEntries]);

  const agentEndpoint = settings?.agent_endpoint?.trim() || "";
  const agentToken = settings?.agent_token?.trim() || "";
  const linuxInstallCommand = useMemo(
    () => buildAgentInstallCommand(agentEndpoint, agentToken),
    [agentEndpoint, agentToken],
  );
  const windowsInstallCommand = useMemo(
    () => buildAgentWindowsInstallCommand(agentEndpoint, agentToken),
    [agentEndpoint, agentToken],
  );
  const installReady = Boolean(linuxInstallCommand && windowsInstallCommand);
  const activeInstallCommand = installPlatform === "windows" ? windowsInstallCommand : linuxInstallCommand;

  const editingNode = useMemo(
    () => nodeLookup.get(editingNodeId) || null,
    [editingNodeId, nodeLookup],
  );
  const currentFormSignature = form ? formDraftSignature(form) : "";
  // A-01 步骤 3（D-08）：规则草稿签名与基线（makeRuleDraft→buildRulePayload 往返形态，
  // 与保存载荷同源）比较，规则草稿有变化同样激活「保存配置」。
  const nodeRulesSignature = useMemo(
    () => (nodeRules ? JSON.stringify(nodeRules.map((draft) => JSON.stringify(buildRulePayload(draft)))) : ""),
    [nodeRules],
  );
  const nodeRulesBaselineSignature = useMemo(() => {
    const baseline = nodeRulesBaselineRef.current;
    return baseline ? JSON.stringify(baseline.map((rule) => JSON.stringify(buildRulePayload(makeRuleDraft(rule))))) : "";
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formInitializationKeyRef.current]);
  const nodeRulesDirty = Boolean(nodeRules && nodeRulesSignature !== nodeRulesBaselineSignature);
  const isEditingDraftDirty = Boolean(
    (form && formBaselineSignatureRef.current && currentFormSignature !== formBaselineSignatureRef.current) ||
      nodeRulesDirty,
  );
  const editorBusy = saving || deleting || refreshing || refreshingAgentUpdate || updatingAgent;
  const editorInputDisabled = editorBusy || sourceConflict;
  const quotaEmpty = !form?.trafficLimitValue.trim();

  useDirtyNotification(onDirtyChange, isEditingDraftDirty);

  useEffect(
    () => () => {
      if (restoreFocusTimerRef.current !== null) {
        window.clearTimeout(restoreFocusTimerRef.current);
      }
    },
    [],
  );

  useEffect(() => {
    if (!editingNode) {
      setForm(null);
      setAgentUpdateInfo(null);
      setSourceConflict(false);
      setNodeRules(null);
      setNodeRuleForm(null);
      nodeRulesBaselineRef.current = null;
      formInitializationKeyRef.current = "";
      formBaselineSignatureRef.current = "";
      formSourceSignatureRef.current = "";
      return;
    }
    const nextKey = editingNodeId;
    const nextForm = buildFormState(editingNode, testCatalog);
    const nextDraftSignature = formDraftSignature(nextForm);
    const nextSourceSignature = formSourceSignature(nextForm, testCatalogSignature);
    const currentDraftMatchesIncoming = currentFormSignature === nextDraftSignature;
    if (formInitializationKeyRef.current !== nextKey) {
      setForm(nextForm);
      setAgentUpdateInfo(null);
      setSourceConflict(false);
      // A-01 步骤 3（D-08）：规则草稿以打开抽屉时的服务端规则为基线。
      setNodeRules((settings?.alert_rules ?? []).map(makeRuleDraft));
      setNodeRuleForm(null);
      nodeRulesBaselineRef.current = settings?.alert_rules ?? [];
      formInitializationKeyRef.current = nextKey;
      formBaselineSignatureRef.current = nextDraftSignature;
      formSourceSignatureRef.current = nextSourceSignature;
      return;
    }
    if (formSourceSignatureRef.current === nextSourceSignature || saving || deleting) {
      return;
    }
    if (isEditingDraftDirty) {
      if (currentDraftMatchesIncoming) {
        formBaselineSignatureRef.current = nextDraftSignature;
        formSourceSignatureRef.current = nextSourceSignature;
        setSourceConflict(false);
        return;
      }
      formSourceSignatureRef.current = nextSourceSignature;
      setSourceConflict(true);
      toast.warning("服务端节点配置已更新，当前未保存修改已保留。请取消后重新打开再保存。");
      return;
    }
    setForm(nextForm);
    setSourceConflict(false);
    formBaselineSignatureRef.current = nextDraftSignature;
    formSourceSignatureRef.current = nextSourceSignature;
  }, [currentFormSignature, deleting, editingNode, editingNodeId, isEditingDraftDirty, saving, settings?.alert_rules, testCatalog, testCatalogSignature]);

  const patchForm = (updater: (current: FormState) => FormState) => {
    if (editorInputDisabled) {
      return;
    }
    setForm((current) => (current ? updater(current) : current));
  };
  const updateFormField = <Key extends keyof FormState>(key: Key, value: FormState[Key]) => {
    patchForm((current) => ({
      ...current,
      [key]: value,
    }));
  };
  const selectedGroupState = useMemo(
    () => buildSelectedGroupState(form?.groups),
    [form?.groups],
  );
  const selectedGroupCount = selectedGroupState.count;
  const testDraftState = useMemo(
    () => buildTestDraftState(testCatalog, form?.testSelections),
    [form?.testSelections, testCatalog],
  );
  // O-01：范围下发带来的目录项（管理端 scoped_test_ids，只读）。这些项勾选且
  // 禁用、右侧标注「来自探测设置」；间隔可编辑（编辑即变为手动选择，保存后
  // 作为覆盖）。已被手动选择的目录项不在该列表中（手动选择优先）。
  const scopedTestIdSet = useMemo(
    () => new Set(editingNode?.scoped_test_ids || []),
    [editingNode],
  );
  const hasExpireAt = Boolean(form?.expireAt.trim());
  const editingAgentVersion = editingNode?.stats.agent_version?.trim() || "";
  const agentUpdateDisabledReason = !editingNode
    ? "请选择节点后再执行更新"
    : !editingNode.agent_update_supported
      ? editingNode.agent_update_message?.trim() || "当前 Agent 已禁用远程更新"
      : !editingAgentVersion
        ? "当前节点还没有上报 Agent 版本"
        : "";
  const agentAlreadyLatest = Boolean(
    editingNode?.agent_update_supported && agentUpdateInfo?.latest_version && !agentUpdateInfo.available,
  );
  const agentUpdateActionDisabledReason =
    agentUpdateDisabledReason || (agentAlreadyLatest ? "当前 Agent 已是最新版" : "");
  const agentLatestVersionLabel = !editingNode
    ? "--"
    : !editingNode.agent_update_supported
      ? "已禁用更新"
      : refreshingAgentUpdate && !agentUpdateInfo
        ? "检查中…"
        : agentAlreadyLatest
          ? "当前已为最新版"
        : agentUpdateInfo?.latest_version
          ? formatVersionLabel(agentUpdateInfo.latest_version)
          : editingNode.agent_update_target_version
            ? formatVersionLabel(editingNode.agent_update_target_version)
            : "未检查";
  // 只有真正渲染版本号时才用数据字体；「检查中…/未检查/已禁用更新」是说明文案，必须留在 UI 字体。
  const agentLatestVersionIsValue =
    !!editingNode &&
    editingNode.agent_update_supported &&
    !(refreshingAgentUpdate && !agentUpdateInfo) &&
    !agentAlreadyLatest &&
    !!(agentUpdateInfo?.latest_version || editingNode.agent_update_target_version);

  // ---- A-01 步骤 3：节点抽屉「告警」卡的规则列表与共享规则抽屉 ----

  // 列表数据（M-05 / D-06）：仅此节点专属规则（include 且 nodes 恰为 [本节点]、
  // 无分组；内置 offline 规则除外），按草稿顺序排列。
  const nodeOnlyRules = useMemo(() => {
    if (!editingNode || !nodeRules) {
      return [];
    }
    const nodeID = resolveNodeId(editingNode);
    if (!nodeID) {
      return [];
    }
    return nodeRules.filter(
      (rule) => isNodeOnlyRule(rule, nodeID) && rule.metric !== OFFLINE_ALERT_RULE_ID,
    );
  }, [editingNode, nodeRules]);

  const handleOpen = (node: NodeView) => {
    const nodeID = resolveNodeId(node);
    if (restoreFocusTimerRef.current !== null) {
      window.clearTimeout(restoreFocusTimerRef.current);
      restoreFocusTimerRef.current = null;
    }
    lastOpenedNodeCardRef.current = nodeID;
    setEditingNodeId(nodeID);
  };

  const closeEditor = (force = false) => {
    if (!force && editorBusy) {
      return;
    }
    if (!force && isEditingDraftDirty) {
      toast.warning("节点配置有未保存修改，请先保存或使用放弃修改。");
      return;
    }
    const restoreNodeID = lastOpenedNodeCardRef.current;
    setEditingNodeId("");
    // F4：节点抽屉关闭时一并收起「为此节点新增规则」抽屉，避免孤悬。
    closeNodeRuleDrawer();
    onDirtyChange?.(false);
    if (!restoreNodeID) {
      return;
    }
    // Dialog 有 ~100ms 退出动画且期间保持滚动锁，单 rAF 内 scrollTo 会失效；
    // 弹窗期间列表也可能因 WS 推送重排，旧 scrollY 已不对准原卡片。改为
    // 等动画结束后直接滚回目标卡片本身。
    restoreFocusTimerRef.current = window.setTimeout(() => {
      restoreFocusTimerRef.current = null;
      const selector = `[data-node-card-id="${escapeSelectorValue(restoreNodeID)}"]`;
      const target = document.querySelector<HTMLElement>(selector);
      if (!target) {
        return;
      }
      target.scrollIntoView({ block: "center" });
      target.focus({ preventScroll: true });
    }, 150);
  };

  const handleRefresh = () => {
    if (editorBusy) {
      return;
    }
    if (isEditingDraftDirty) {
      toast.warning("当前节点配置有未保存修改，请先保存或取消后再刷新。");
      return;
    }
    void runAction({
      action: () => onRefresh(),
      fallbackError: "刷新节点列表失败",
      successToast: "节点列表已刷新",
      setBusy: setRefreshing,
    });
  };

  // 批量下发：逐台调用既有单节点更新接口，各自计结果；等待注册的纯档案
  // 节点无 Agent 可更新，跳过。已是最新/不支持的平台由接口返回或计入失败。
  const handleTriggerAllAgentUpdates = async () => {
    const targets = nodes.filter(
      (node) => node.status !== "waiting_registration" && resolveNodeId(node),
    );
    if (targets.length === 0) {
      toast.info("没有可下发更新的节点");
      return;
    }
    if (updatingAllAgents) {
      return;
    }
    setUpdatingAllAgents(true);
    let dispatched = 0;
    let upToDate = 0;
    let failed = 0;
    try {
      for (const node of targets) {
        try {
          const result = await onTriggerAgentUpdate(resolveNodeId(node));
          if (result.status === "up_to_date") {
            upToDate += 1;
          } else {
            dispatched += 1;
          }
        } catch {
          failed += 1;
        }
      }
    } finally {
      setUpdatingAllAgents(false);
    }
    const summary = [
      dispatched ? `已下发 ${dispatched}` : "",
      upToDate ? `已是最新 ${upToDate}` : "",
      failed ? `失败 ${failed}` : "",
    ]
      .filter(Boolean)
      .join("，");
    if (summary) {
      toast.success(`批量更新完成：${summary}`);
    }
  };

  const handleToggleGroupSelection = (value: string) => {
    patchForm((current) => {
      const normalized = normalizeSelectionValues(current.groups);
      if (normalized.includes(value)) {
        return {
          ...current,
          groups: normalizeSelectionValues(normalized.filter((item) => item !== value)),
        };
      }
      return { ...current, groups: upsertSelectionValue(normalized, value) };
    });
  };

  const handleRemoveGroupSelection = (value: string) => {
    patchForm((current) => ({
      ...current,
      groups: normalizeSelectionValues(current.groups.filter((item) => item !== value)),
    }));
  };

  const handleToggleTest = ({ item, itemId, active }: TestDraftEntry) => {
    if (!itemId || !form) {
      return;
    }
    // 后端 normalizeTestSelections 超出 128 静默截断：在 UI 层拦下，避
    // 免保存成功提示后重开只剩前 128 项勾选。判定放在 updater 外
    // （updater 必须是纯函数，StrictMode 下副作用会双触发）。
    if (!active && Object.keys(form.testSelections).length >= maxTestsPerNode) {
      toast.warning(`单个节点最多选择 ${maxTestsPerNode} 个探测项。`);
      return;
    }
    patchForm((current) => {
      const nextSelections = { ...current.testSelections };
      if (active) {
        delete nextSelections[itemId];
      } else {
        nextSelections[itemId] = buildTestSelectionValue(item);
      }
      return { ...current, testSelections: nextSelections };
    });
  };

  const handleTestIntervalChange = (itemId: string, value: string) => {
    if (!itemId) {
      return;
    }
    patchForm((current) => ({
      ...current,
      testSelections: {
        ...current.testSelections,
        [itemId]: value,
      },
    }));
  };

  // A-01 步骤 3（D-08）：「保存配置」一次提交——规则草稿有变化时先取最新
  // alert_rules 按规则 ID 应用差异并 PATCH，再 PATCH 节点 profile。任一步失败
  // toast 报错、抽屉保持打开、草稿保留；规则已保存而节点设置失败时如实提示。
  const handleSave = () => {
    if (!editingNode || !form) {
      return;
    }
    if (sourceConflict) {
      toast.warning("服务端节点配置已更新，请取消后重新打开再保存。");
      return;
    }
    if (editorBusy) {
      return;
    }
    let profilePayload: NodeProfilePayload;
    try {
      profilePayload = buildPayload(form, testCatalog, catalogLoaded);
    } catch (error) {
      toast.error(getErrorMessage(error, "保存节点配置失败"));
      return;
    }
    const rulesDirty = nodeRulesDirty;
    void (async () => {
      setSaving(true);
      try {
        if (rulesDirty) {
          const baseline = nodeRulesBaselineRef.current ?? [];
          const latest = await runAction({
            action: () => fetchSettings(),
            fallbackError: "保存告警规则失败",
          });
          if (!latest) {
            return; // runAction 已 toast，抽屉保持打开、草稿保留
          }
          const { rules: merged, modifiedButMissing } = mergeNodeRuleDrafts(
            baseline,
            nodeRules ?? [],
            latest.alert_rules ?? [],
          );
          for (const name of modifiedButMissing) {
            toast.warning(`规则『${name}』已在别处删除，未保存对它的修改`);
          }
          const saved = await runAction({
            // 经 App 的 updateSettings 通道保存并刷新 settings，避免「告警策略」页
            // 草稿从过期视图初始化后覆盖本次修改。
            action: () => onSaveSettings!({ alert_rules: merged }),
            fallbackError: "保存告警规则失败",
          });
          if (!saved) {
            return;
          }
        }
        let profileSaved = false;
        await runAction({
          action: async () => {
            await onSaveNode(resolveNodeId(editingNode), profilePayload!);
            profileSaved = true;
          },
          fallbackError: "保存节点配置失败",
        });
        if (!profileSaved) {
          if (rulesDirty) {
            toast.error("告警规则已保存，节点设置保存失败");
          }
          return;
        }
        toast.success("节点配置已保存并下发");
        closeEditor(true);
      } finally {
        setSaving(false);
      }
    })();
  };

  const handleDelete = () => {
    if (!editingNode || editorInputDisabled) {
      return;
    }
    void runAction({
      action: () => onDeleteNode(resolveNodeId(editingNode)),
      fallbackError: "删除节点失败",
      successToast: (deleteResult) => (deleteResult.history_error ? null : "节点已删除"),
      onSuccess: () => {
        setDeleteDialogOpen(false);
        closeEditor(true);
      },
      setBusy: setDeleting,
    });
  };

  // ---- A-01 步骤 3（D-08）：节点抽屉「告警」卡的规则草稿操作与共享规则抽屉 ----
  //      抽屉内的全部规则操作只修改规则草稿（不发请求），随「保存配置」一次提交。

  const openNodeRuleDrawerForNew = (trigger: HTMLElement) => {
    if (!editingNode || editorInputDisabled) {
      return;
    }
    const nodeID = resolveNodeId(editingNode);
    if (!nodeID) {
      return;
    }
    nodeRuleDrawerReturnRef.current = {
      scrollTop: nodeDrawerBodyRef.current?.scrollTop ?? 0,
      trigger,
    };
    // 预设 scope={mode:"include", nodes:[本节点]}；默认形态对齐「告警策略」页的
    // 新增规则：「CPU > 90% · 持续 5 分钟」。
    setNodeRuleForm({
      id: generateRuleID(),
      name: "",
      enabled: true,
      metric: "cpu",
      op: "gt",
      threshold: "90",
      durationSec: 300,
      scopeMode: "include",
      scopeNodes: [nodeID],
      scopeGroups: [],
      scopeExclude: [],
      channelIds: [],
      notifyRecover: true,
      repeat: "once",
      probeName: "",
      leadDays: [],
    });
  };

  const openNodeRuleDrawerForEdit = (rule: AlertRuleDraft, trigger: HTMLElement) => {
    if (editorInputDisabled) {
      return;
    }
    nodeRuleDrawerReturnRef.current = {
      scrollTop: nodeDrawerBodyRef.current?.scrollTop ?? 0,
      trigger,
    };
    setNodeRuleForm(copyRuleDraft(rule));
  };

  const closeNodeRuleDrawer = () => {
    setNodeRuleForm(null);
    const { scrollTop, trigger } = nodeRuleDrawerReturnRef.current;
    requestAnimationFrame(() => {
      const body = nodeDrawerBodyRef.current;
      if (body) {
        body.scrollTop = scrollTop;
      }
      const focusTarget = trigger && trigger.isConnected ? trigger : addNodeRuleButtonRef.current;
      focusTarget?.focus({ preventScroll: true });
    });
  };

  // 共享抽屉「完成」：只写回节点抽屉的规则草稿（新增追加到末尾 / 修改按 ID 替换），
  // 不发请求；真正保存走「保存配置」。
  const handleNodeRuleDone = (draft: AlertRuleDraft) => {
    if (editorInputDisabled) {
      return;
    }
    setNodeRules((current) => {
      if (!current) {
        return [copyRuleDraft(draft)];
      }
      const index = current.findIndex((item) => item.id === draft.id);
      if (index < 0) {
        return [...current, copyRuleDraft(draft)];
      }
      const next = [...current];
      next[index] = copyRuleDraft(draft);
      return next;
    });
    closeNodeRuleDrawer();
  };

  // 「启用规则」Switch（M-05 / D-06）：切换规则自身的 enabled，只改本条草稿，
  // 不写 scope.exclude；随「保存配置」一次提交。
  const toggleNodeRuleEnabled = (rule: AlertRuleDraft, on: boolean) => {
    if (editorInputDisabled) {
      return;
    }
    setNodeRules((current) =>
      (current ?? []).map((item) => (item.id === rule.id ? { ...item, enabled: on } : item)),
    );
  };

  // 「仅此节点」规则的删除（确认后从草稿移除）。
  const removeNodeRuleDraft = (rule: AlertRuleDraft) => {
    if (editorInputDisabled) {
      return;
    }
    setNodeRules((current) => (current ?? []).filter((item) => item.id !== rule.id));
    closeNodeRuleDrawer();
  };

  const copyInstallCommand = (value: string) => {
    if (!value) {
      return;
    }
    void runAction({
      action: () => copyTextToClipboard(value),
      fallbackError: "复制失败，请手动选择命令后复制",
      fixedErrorText: true,
      successToast: "命令已复制",
    });
  };

  const handleCheckAgentUpdate = async () => {
    if (!editingNode || editorInputDisabled) {
      return;
    }
    const requestNodeID = resolveNodeId(editingNode);
    const requestSeq = agentUpdateRequestSeqRef.current + 1;
    agentUpdateRequestSeqRef.current = requestSeq;
    setRefreshingAgentUpdate(true);
    try {
      const info = await onCheckAgentUpdate(requestNodeID);
      if (agentUpdateRequestSeqRef.current !== requestSeq || formInitializationKeyRef.current !== requestNodeID) {
        return;
      }
      setAgentUpdateInfo(info);
      if (info.supported === false) {
        toast.error(info.message || "当前节点平台暂不支持后台自更新");
        return;
      }
      if (info.latest_version) {
        toast.success(
          info.available
            ? `已检查到最新版本 ${info.latest_version}`
            : "当前 Agent 已是最新版本",
        );
        return;
      }
      toast.success("已完成 Agent 版本检查");
    } catch (error) {
      toast.error(getErrorMessage(error, "检查 Agent 更新失败"));
    } finally {
      if (agentUpdateRequestSeqRef.current === requestSeq) {
        setRefreshingAgentUpdate(false);
      }
    }
  };

  const handleAgentUpdate = async () => {
    if (!editingNode || editorInputDisabled) {
      return;
    }
    const requestNodeID = resolveNodeId(editingNode);
    const requestSeq = agentUpdateRequestSeqRef.current + 1;
    agentUpdateRequestSeqRef.current = requestSeq;
    setUpdatingAgent(true);
    try {
      const result = await onTriggerAgentUpdate(requestNodeID);
      if (agentUpdateRequestSeqRef.current !== requestSeq || formInitializationKeyRef.current !== requestNodeID) {
        return;
      }
      if (result.status === "up_to_date") {
        toast.success("当前 Agent 已经是最新正式版");
      } else {
        toast.success(`Agent 更新任务已下发，目标版本 ${result.target_version || "latest"}`);
      }
      setAgentUpdateInfo((current) => ({
        current_version: editingAgentVersion,
        latest_version: result.target_version || current?.latest_version || "",
        available: result.status !== "up_to_date",
        supported: true,
        mode: current?.mode || editingNode.agent_update_mode || "binary",
        message: current?.message,
        html_url: current?.html_url,
        published_at: current?.published_at,
      }));
    } catch (error) {
      toast.error(getErrorMessage(error, "下发 Agent 更新失败"));
    } finally {
      if (agentUpdateRequestSeqRef.current === requestSeq) {
        setUpdatingAgent(false);
      }
    }
  };

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        as="section"
        title="节点管理"
        actionsClassName="grid grid-cols-2 gap-2 sm:flex sm:items-center"
        actions={
          <>
            {/* A-19 第 1 条：搜索框用 A-06 内凹样式（adminInputClass）、前置放大镜图标；
                A-13 第 2 条：桌面宽 min(360px, 40vw)，提示文字缩短避免截断；
                ⌘K 键盘提示按 0.1.2 不做（无快捷键逻辑）。 */}
            <div className="relative col-span-2 w-full sm:w-[min(360px,40vw)]">
              <Search
                aria-hidden="true"
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--label-3)]"
              />
              <Input
                aria-label="搜索节点"
                type="search"
                className={`${adminInputClass} pl-9`}
                name="node-search"
                autoComplete="off"
                placeholder="搜索名称、ID、主机名、IP"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
            <Button
              variant="outline"
              className={outlineActionClass}
              onClick={handleRefresh}
              disabled={refreshing || loading || editorBusy || isEditingDraftDirty}
            >
              {refreshing || loading ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              刷新节点
            </Button>
            <AlertDialog
              open={updateAllDialogOpen}
              onOpenChange={(open) => {
                if (updatingAllAgents && !open) {
                  return;
                }
                setUpdateAllDialogOpen(open);
              }}
            >
              <AlertDialogTrigger
                render={(
                  <Button
                    type="button"
                    variant="outline"
                    className={outlineActionClass}
                    disabled={updatingAllAgents || loading || nodes.length === 0}
                  >
                    {updatingAllAgents ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Rocket className="mr-2 h-4 w-4" />
                    )}
                    全部更新
                  </Button>
                )}
              />
              <AlertDialogContent className={adminDialogContentClass}>
                <AlertDialogHeader className={adminDialogHeaderClass}>
                  <AlertDialogTitle>
                    确认对全部 {nodes.length} 台节点下发 Agent 更新？
                  </AlertDialogTitle>
                </AlertDialogHeader>
                <AlertDialogFooter className={adminDialogFooterClass}>
                  <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                  <AlertDialogAction
                    className={adminPrimaryButtonClass}
                    disabled={updatingAllAgents}
                    onClick={handleTriggerAllAgentUpdates}
                  >
                    {updatingAllAgents ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                    确认下发
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </>
        }
      />

      <AdminMetricStrip ariaLabel="节点统计" items={metricItems} />

      {/* 快速接入在节点列表之上（用户第 17 轮：新建节点时第一眼要能复制命令）。 */}
      <AdminPanel title="Agent 快速接入">
        {installReady ? (
          <div className="space-y-4">
            {/* 地址已配置时不再单独展示：命令内已内嵌，重复行只增加噪音（用户第 18 轮）。 */}
            {/* 平台切换：与首页时间范围同款分段控件，两项等宽 */}
            <div role="group" aria-label="安装平台" className={cn(adminSegmentedTrackClass, "w-fit")}>
              <Button
                type="button"
                variant={null}
                aria-pressed={installPlatform === "unix"}
                className={cn(
                  adminSegmentedItemClass,
                  "min-w-[112px] flex-none",
                  installPlatform === "unix"
                    ? adminSegmentedItemActiveClass
                    : adminSegmentedItemInactiveClass,
                )}
                onClick={() => setInstallPlatform("unix")}
              >
                Linux/macOS
              </Button>
              <Button
                type="button"
                variant={null}
                aria-pressed={installPlatform === "windows"}
                className={cn(
                  adminSegmentedItemClass,
                  "min-w-[112px] flex-none",
                  installPlatform === "windows"
                    ? adminSegmentedItemActiveClass
                    : adminSegmentedItemInactiveClass,
                )}
                onClick={() => setInstallPlatform("windows")}
              >
                Windows
              </Button>
            </div>
            <code
              id={installPlatform === "windows" ? agentInstallWindowsId : agentInstallLinuxId}
              className={`${adminCodeBlockPanelClass} block w-full cursor-pointer select-text whitespace-pre-wrap break-all transition-colors duration-150 hover:border-[var(--separator-opaque)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]`}
              tabIndex={0}
              role="button"
              aria-label="点击复制完整接入命令，也可拖选部分文本手动复制"
              onClick={() => {
                const selection = window.getSelection();
                if (selection && selection.toString().length > 0) {
                  return;
                }
                copyInstallCommand(activeInstallCommand);
              }}
              onKeyDown={(event) => {
                if (event.key !== "Enter" && event.key !== " ") {
                  return;
                }
                event.preventDefault();
                copyInstallCommand(activeInstallCommand);
              }}
            >
              {activeInstallCommand}
            </code>
          </div>
        ) : (
          // A-19 第 2 条：原虚线提示框改为 A-14 信息横幅的 --accent-tint 版式
          // （无边框、--r-md、内边距 12px 16px、左 20px 图标圆）。0.1.2：不加「去配置」链接。
          <div className="flex items-start gap-4 rounded-[var(--r-md)] bg-[var(--accent-tint)] px-4 py-3">
            <span
              aria-hidden="true"
              className="flex size-5 shrink-0 items-center justify-center rounded-full bg-[var(--accent)] text-xs font-semibold leading-none text-white"
            >
              i
            </span>
            <p className="text-[13px] leading-relaxed">
              <span className="font-semibold text-[var(--label-1)]">尚未配置 Agent 对接地址：</span>
              <span className="text-[var(--label-2)]">
                请先在基础设置的接入配置中填写 Agent 对接地址。
              </span>
            </p>
          </div>
        )}
      </AdminPanel>

      <AdminPanel title="节点列表">
        <AdminDataTable
          ariaLabel="节点列表"
          columns={nodeTableColumns}
          fixed
          tableClassName="max-md:min-w-[60rem]"
          rows={filteredNodes}
          rowKey={(entry) => entry.nodeId}
          rowAttributes={(entry) => ({ "data-node-card-id": entry.nodeId })}
          onRowClick={(entry) => handleOpen(entry.node)}
          emptyLabel={
            nodes.length === 0 ? "当前还没有节点接入。" : "没有匹配的节点，请调整搜索条件。"
          }
        />
      </AdminPanel>

      <AdminDrawer
        open={Boolean(editingNode && form)}
        bodyRef={nodeDrawerBodyRef}
        onOpenChange={(open) => {
          if (!open) {
            closeEditor();
          }
        }}
        title={editingNode ? resolveNodeName(editingNode) : "节点配置编辑"}
        description={
          editingNode ? (
            <span className="data-text break-all">{resolveNodeIdentitySummary(editingNode)}</span>
          ) : undefined
        }
        footer={
          editingNode && form ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <AlertDialog
                open={deleteDialogOpen}
                onOpenChange={(open) => {
                  if (deleting && !open) {
                    return;
                  }
                  setDeleteDialogOpen(open);
                }}
              >
                <AlertDialogTrigger
                  render={(
                    <Button
                      type="button"
                      variant="destructive"
                      className={cn(adminDangerOutlineButtonClass, "h-9 min-w-[92px] px-4")}
                      disabled={editorInputDisabled}
                    >
                      {deleting ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Trash2 className="mr-2 h-4 w-4" />
                      )}
                      删除节点
                    </Button>
                  )}
                />
                <AlertDialogContent className={adminDialogContentClass}>
                  <AlertDialogHeader className={adminDialogHeaderClass}>
                    <AlertDialogTitle>
                      {editingNode
                        ? `确认删除节点“${resolveNodeName(editingNode)}”？`
                        : "确认删除节点？"}
                    </AlertDialogTitle>
                  </AlertDialogHeader>
                  <AlertDialogFooter className={adminDialogFooterClass}>
                    <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                    <AlertDialogAction
                      className={adminDialogDangerActionClass}
                      disabled={deleting || saving || refreshingAgentUpdate || updatingAgent}
                      onClick={handleDelete}
                    >
                      {deleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      确认删除
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
              <div className="ml-auto flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className={cn(adminOutlineButtonClass, "h-9 min-w-[84px] px-4")}
                  onClick={() => closeEditor(isEditingDraftDirty)}
                  disabled={editorBusy}
                >
                  {isEditingDraftDirty ? "放弃修改" : "取消"}
                </Button>
                <Button
                  type="button"
                  className={cn(adminPrimaryButtonClass, "h-9 min-w-[100px] px-4")}
                  onClick={handleSave}
                  disabled={!isEditingDraftDirty || editorInputDisabled}
                >
                  {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  保存配置
                </Button>
              </div>
            </div>
          ) : null
        }
      >
        {editingNode && form ? (
          <>
            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                Agent 更新
              </h3>
              {editingNode.agent_update_supported ? (
                <>
                  <div className="space-y-3">
                    <AdminKVField label="当前版本">
                      <span className="data-text text-sm font-medium text-[var(--label-1)]">
                        {formatVersionLabel(editingAgentVersion)}
                      </span>
                    </AdminKVField>
                    <AdminKVField label="最新版本">
                      <span
                        className={cn(
                          "text-sm font-medium text-[var(--label-1)]",
                          agentLatestVersionIsValue && "data-text",
                        )}
                      >
                        {agentLatestVersionLabel}
                      </span>
                    </AdminKVField>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      className={cn(adminActionButtonClass, "h-9 min-w-[104px] px-4")}
                      onClick={handleCheckAgentUpdate}
                      disabled={Boolean(agentUpdateDisabledReason) || editorInputDisabled}
                      title={agentUpdateDisabledReason || undefined}
                    >
                      {refreshingAgentUpdate ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <RefreshCw className="mr-2 h-4 w-4" />
                      )}
                      检查更新
                    </Button>
                    <Button
                      type="button"
                      className={cn(adminPrimaryButtonClass, "h-9 min-w-[104px] px-4")}
                      onClick={handleAgentUpdate}
                      disabled={Boolean(agentUpdateActionDisabledReason) || editorInputDisabled}
                      title={agentUpdateActionDisabledReason || undefined}
                    >
                      {updatingAgent ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      {updatingAgent ? "更新中" : "立即更新"}
                    </Button>
                  </div>
                </>
              ) : (
                <p className={adminHelpTextClass}>
                  {agentUpdateDisabledReason || "当前 Agent 已禁用远程更新"}
                </p>
              )}
            </section>

            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                显示与标注
              </h3>
              <div className="space-y-3">
                <AdminKVField label="Node ID">
                  <span className="data-text break-all text-xs text-[var(--label-3)]">
                    {resolveNodeId(editingNode)}
                  </span>
                </AdminKVField>
                <AdminKVField label="显示名称" htmlFor="node-alias">
                  <Input
                    id="node-alias"
                    name="node-alias"
                    autoComplete="off"
                    maxLength={120}
                    className={adminInputClass}
                    value={form.alias}
                    disabled={editorInputDisabled}
                    onChange={(event) => updateFormField("alias", event.target.value)}
                    placeholder={editingNode.stats.node_name || editingNode.stats.hostname}
                  />
                </AdminKVField>
                <AdminKVField label="地区代码" htmlFor="node-region">
                  <Input
                    id="node-region"
                    name="node-region"
                    autoComplete="off"
                    maxLength={2}
                    className={adminInputClass}
                    value={form.region}
                    disabled={editorInputDisabled}
                    onChange={(event) =>
                      updateFormField(
                        "region",
                        event.target.value.replace(/[^a-zA-Z]/g, "").toUpperCase(),
                      )
                    }
                    placeholder="两位代码，如 SG / JP / HK"
                  />
                </AdminKVField>
                <AdminKVField label="磁盘类型" htmlFor="node-disk-type">
                  <Input
                    id="node-disk-type"
                    name="node-disk-type"
                    autoComplete="off"
                    className={adminInputClass}
                    value={form.diskType}
                    disabled={editorInputDisabled}
                    onChange={(event) => updateFormField("diskType", event.target.value)}
                    placeholder="NVMe / SSD / HDD"
                  />
                </AdminKVField>
                <AdminKVField label="带宽（Mbps）" htmlFor="node-net-speed">
                  <Input
                    id="node-net-speed"
                    name="node-net-speed"
                    className={`${adminInputClass} data-text`}
                    type="number"
                    min={0}
                    autoComplete="off"
                    value={form.netSpeedMbps}
                    disabled={editorInputDisabled}
                    onChange={(event) => updateFormField("netSpeedMbps", event.target.value)}
                    placeholder="1000"
                  />
                </AdminKVField>
                {/* A-01 步骤 3：原「生命周期与告警」卡的两个前台显示开关移到本卡末尾（字段 id 不变）。 */}
                <AdminKVField label="在 C&R 视图显示" htmlFor="node-visible-cr">
                  <Switch
                    id="node-visible-cr"
                    checked={form.visibleInCR}
                    disabled={editorBusy || sourceConflict}
                    onCheckedChange={(checked: boolean) => {
                      if (editorBusy || sourceConflict) {
                        return;
                      }
                      updateFormField("visibleInCR", Boolean(checked));
                    }}
                  />
                </AdminKVField>
                <AdminKVField label="在 ALL 视图显示" htmlFor="node-visible-all">
                  <Switch
                    id="node-visible-all"
                    checked={form.visibleInAll}
                    disabled={editorBusy || sourceConflict}
                    onCheckedChange={(checked: boolean) => {
                      if (editorBusy || sourceConflict) {
                        return;
                      }
                      updateFormField("visibleInAll", Boolean(checked));
                    }}
                  />
                </AdminKVField>
              </div>
            </section>

            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                探测下发策略
              </h3>
              <p className={adminHelpTextClass}>
                {`已选 ${testDraftState.summary.selected} 个探测节点。${
                  testDraftState.summary.tcpCustom > 0
                    ? ` 其中 ${testDraftState.summary.tcpCustom} 个 TCP 节点使用了自定义间隔。`
                    : ""
                }`}
              </p>
              {!catalogLoaded ? (
                <p className="text-sm text-[var(--label-3)]">
                  设置数据未加载，保存不会改动本节点已下发的探测项，请刷新后重试。
                </p>
              ) : testCatalog.length === 0 ? (
                <p className="text-sm text-[var(--label-3)]">请先在“探测设置”页配置探测节点。</p>
              ) : (
                <div>
                  {testDraftState.items.map((entry) => {
                    const { item, itemId, active, isTCP, intervalValue, defaultIntervalSec } =
                      entry;
                    const host = item.host || "--";
                    const endpoint = item.port ? `${host}:${item.port}` : host;
                    // O-01：范围下发的目录项——勾选 + 禁用；间隔输入可编辑
                    //（编辑即写入手动选择，active 变 true 后复选框恢复可操作）。
                    const scoped = itemId ? scopedTestIdSet.has(itemId) : false;
                    const scopedOnly = scoped && !active;
                    return (
                      <label
                        key={item.id || endpoint}
                        className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-[var(--separator)] py-2.5 last:border-b-0"
                      >
                        <input
                          type="checkbox"
                          className="h-4 w-4 rounded border-slate-300 text-primary focus:ring-[var(--primary-ring)] dark:border-neutral-700 dark:bg-[var(--surface-2)]"
                          checked={active || scoped}
                          disabled={!itemId || editorInputDisabled || scopedOnly}
                          onChange={() => handleToggleTest(entry)}
                        />
                        <span className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2">
                          <span className="text-sm font-medium text-[var(--label-1)]">
                            {item.name || host || "未命名探测节点"}
                          </span>
                          <span className="data-text truncate text-xs text-[var(--label-3)]">
                            {endpoint}
                          </span>
                        </span>
                        <span className="text-xs text-[var(--label-3)]">{isTCP ? "TCP" : "ICMP"}</span>
                        {scopedOnly ? (
                          <span className="text-xs text-[var(--label-3)]">来自探测设置</span>
                        ) : null}
                        {/* F2：icmp 也可配置间隔；目录条目未设间隔时提示「持续」。 */}
                        <span className="flex items-center gap-1.5">
                          <Input
                            name={itemId ? `probe-interval-${itemId}` : "probe-interval"}
                            className="h-9 w-20 rounded-lg border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-sm"
                            type="number"
                            min={0}
                            max={MAX_TCP_INTERVAL}
                            autoComplete="off"
                            disabled={(!active && !scoped) || !itemId || editorInputDisabled}
                            value={intervalValue}
                            onChange={(event) =>
                              handleTestIntervalChange(itemId, event.target.value)
                            }
                            placeholder={
                              !isTCP && defaultIntervalSec <= 0
                                ? "持续"
                                : String(defaultIntervalSec)
                            }
                          />
                          <span className="text-xs text-[var(--label-3)]">秒</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              )}
            </section>

            {/* A-01 步骤 3：「到期时间」卡（替代原「生命周期与告警」）。 */}
            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                到期时间
              </h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <AdminKVField label="截止时间" htmlFor="node-expire-at">
                    <div className="flex w-full items-center gap-1.5">
                      <Input
                        id="node-expire-at"
                        name="node-expire-at"
                        className={adminInputClass}
                        type="datetime-local"
                        autoComplete="off"
                        value={form.expireAt}
                        disabled={editorInputDisabled}
                        onChange={(event) => updateFormField("expireAt", event.target.value)}
                      />
                      {form.expireAt ? (
                        <Button
                          type="button"
                          variant={null}
                          className="h-9 shrink-0 whitespace-nowrap px-2 text-[13px] font-medium text-[var(--label-2)] hover:text-[var(--label-1)]"
                          disabled={editorInputDisabled}
                          onClick={() => updateFormField("expireAt", "")}
                        >
                          清除
                        </Button>
                      ) : null}
                    </div>
                  </AdminKVField>
                </div>
                <div>
                  <AdminKVField label="续费周期" htmlFor="node-renew-plan">
                    <Select
                      value={form.renewPlan}
                      onValueChange={(value) => {
                        if (editorInputDisabled || value === null) {
                          return;
                        }
                        updateFormField("renewPlan", value as RenewPlan);
                      }}
                      disabled={!hasExpireAt || editorInputDisabled}
                    >
                      <SelectTrigger id="node-renew-plan" className={adminSelectTriggerClass}>
                        <SelectValue>{RENEW_PLAN_LABELS[form.renewPlan]}</SelectValue>
                      </SelectTrigger>
                      <SelectContent className={adminSelectContentClass}>
                        <SelectItem value="none">不续费</SelectItem>
                        <SelectItem value="month">每月</SelectItem>
                        <SelectItem value="quarter">每季</SelectItem>
                        <SelectItem value="half">每半年</SelectItem>
                        <SelectItem value="year">每年</SelectItem>
                      </SelectContent>
                    </Select>
                  </AdminKVField>
                </div>
              </div>
            </section>

            {/* A-01 步骤 3：「告警」卡（替代原「告警规则」卡与「接收告警」字段）。
                规则操作只改草稿，随「保存配置」一次提交（D-08）。 */}
            <section>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-[var(--label-1)]">告警设置</h3>
                  <p className="text-[13px] text-[var(--label-2)]">关闭后此节点不再触发任何告警</p>
                </div>
                <Switch
                  aria-label="接收告警"
                  checked={form.alertEnabled}
                  disabled={editorInputDisabled}
                  onCheckedChange={(checked: boolean) => {
                    if (editorInputDisabled) {
                      return;
                    }
                    updateFormField("alertEnabled", Boolean(checked));
                  }}
                />
              </div>
              {settings === null ? (
                <p className="mt-3 text-sm text-[var(--label-3)]">设置数据未加载，无法查看告警规则。</p>
              ) : (
                <>
                  <div className={cn("mt-1.5", !form.alertEnabled && "opacity-50")}>
                    {nodeOnlyRules.length === 0 ? (
                      <p className="py-2.5 text-sm text-[var(--label-3)]">此节点暂无专属规则</p>
                    ) : (
                      nodeOnlyRules.map((rule) => {
                        const ruleDisabled = rule.enabled === false;
                        return (
                          <div
                            key={rule.id || ruleConditionText(rule)}
                            className={cn(
                              "flex items-center gap-2 border-b border-[var(--separator)] py-2.5 last:border-b-0",
                              ruleDisabled && "opacity-50",
                            )}
                          >
                            <span className="min-w-0 flex-1">
                              <span
                                className="block truncate text-sm font-medium text-[var(--label-1)]"
                                data-admin-i18n-skip={rule.name.trim() ? true : undefined}
                              >
                                {rule.name.trim() ||
                                  (rule.metric === OFFLINE_ALERT_RULE_ID ? "节点离线" : "未命名规则")}
                              </span>
                              <span className="block truncate text-[13px] text-[var(--label-3)]">
                                {ruleConditionText(rule)}
                              </span>
                            </span>
                            <AlertDialog>
                              <AlertDialogTrigger
                                render={(
                                  <button
                                    type="button"
                                    aria-label="删除规则"
                                    className="flex size-8 shrink-0 items-center justify-center rounded-full text-[var(--label-4)] transition-colors hover:text-[var(--danger)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--danger)]"
                                    disabled={editorInputDisabled || !form.alertEnabled}
                                  >
                                    <Trash2 aria-hidden="true" className="h-4 w-4" />
                                  </button>
                                )}
                              />
                              <AlertDialogContent className={adminDialogContentClass}>
                                <AlertDialogHeader className={adminDialogHeaderClass}>
                                  <AlertDialogTitle>
                                    {`删除规则『${rule.name.trim() || (rule.metric === OFFLINE_ALERT_RULE_ID ? "节点离线" : "未命名规则")}』？此规则只作用于本节点，删除后不可恢复。`}
                                  </AlertDialogTitle>
                                </AlertDialogHeader>
                                <AlertDialogFooter className={adminDialogFooterClass}>
                                  <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                                  <AlertDialogAction
                                    className={adminDialogDangerActionClass}
                                    onClick={() => removeNodeRuleDraft(rule)}
                                  >
                                    确认删除
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                            <Switch
                              size="sm"
                              aria-label="启用规则"
                              checked={rule.enabled !== false}
                              disabled={editorInputDisabled || !form.alertEnabled}
                              onCheckedChange={(checked: boolean) =>
                                toggleNodeRuleEnabled(rule, Boolean(checked))
                              }
                            />
                            <button
                              type="button"
                              aria-label="编辑规则"
                              className="flex size-8 shrink-0 items-center justify-center rounded-full text-[var(--label-4)] outline-none transition-colors duration-[var(--dur-2)] hover:text-[var(--label-2)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]"
                              onClick={(event) => openNodeRuleDrawerForEdit(rule, event.currentTarget)}
                            >
                              <ChevronRight aria-hidden="true" className="h-4 w-4" />
                            </button>
                          </div>
                        );
                      })
                    )}
                  </div>
                  <Button
                    ref={addNodeRuleButtonRef}
                    type="button"
                    variant="outline"
                    className={cn(
                      adminCompactActionButtonClass,
                      "mt-3 flex h-9 w-fit px-3",
                      !form.alertEnabled && "opacity-50",
                    )}
                    disabled={editorInputDisabled || !form.alertEnabled}
                    onClick={(event) => openNodeRuleDrawerForNew(event.currentTarget)}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    为此节点新增规则
                  </Button>
                </>
              )}
            </section>

            {/* A-02 流量配额：一行三列（配额 + 单位 / 计算方式 / 重置日）。 */}
            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                流量配额
              </h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,0.8fr)]">
                <AdminKVField label="配额" htmlFor="node-traffic-limit">
                  {/* 数字输入 + 紧贴右侧的单位 Select，共用外框与圆角，中间 1px 分隔。 */}
                  <div className="flex h-9 w-full items-stretch overflow-hidden rounded-lg border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] transition-colors focus-within:border-[var(--primary)] focus-within:ring-[3px] focus-within:ring-[var(--primary-ring)]">
                    <Input
                      id="node-traffic-limit"
                      name="node-traffic-limit"
                      className="data-text min-w-0 flex-1 rounded-none border-0 bg-transparent shadow-none focus-visible:ring-0 focus-visible:ring-offset-0 dark:bg-transparent"
                      type="number"
                      min={0}
                      step="0.01"
                      inputMode="decimal"
                      autoComplete="off"
                      value={form.trafficLimitValue}
                      disabled={editorInputDisabled}
                      onChange={(event) => updateFormField("trafficLimitValue", event.target.value)}
                      placeholder="不限量"
                    />
                    <Select
                      value={form.trafficLimitUnit}
                      onValueChange={(value) => {
                        if (editorInputDisabled || value === null) {
                          return;
                        }
                        updateFormField("trafficLimitUnit", value as TrafficLimitUnit);
                      }}
                      disabled={editorInputDisabled}
                    >
                      <SelectTrigger
                        aria-label="单位"
                        className="h-auto w-[68px] shrink-0 rounded-none border-0 border-l border-[var(--hairline)] bg-transparent shadow-none focus-visible:ring-0 focus-visible:ring-offset-0 dark:bg-transparent"
                      >
                        <SelectValue>{form.trafficLimitUnit}</SelectValue>
                      </SelectTrigger>
                      <SelectContent className={adminSelectContentClass}>
                        {TRAFFIC_UNITS.map((unit) => (
                          <SelectItem key={unit} value={unit}>
                            {unit}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </AdminKVField>
                <AdminKVField label="计算方式" htmlFor="node-traffic-limit-type">
                  <Select
                    value={form.trafficLimitType}
                    onValueChange={(value) => {
                      if (editorInputDisabled || value === null) {
                        return;
                      }
                      updateFormField("trafficLimitType", normalizeTrafficLimitTypeInput(value));
                    }}
                    disabled={quotaEmpty || editorInputDisabled}
                  >
                    <SelectTrigger id="node-traffic-limit-type" className={adminSelectTriggerClass}>
                      <SelectValue>
                        {TRAFFIC_LIMIT_TYPE_LABELS[form.trafficLimitType]}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent className={adminSelectContentClass}>
                      <SelectItem value="sum">上下行合计</SelectItem>
                      <SelectItem value="max">取较大值</SelectItem>
                      <SelectItem value="up">仅上行</SelectItem>
                      <SelectItem value="down">仅下行</SelectItem>
                    </SelectContent>
                  </Select>
                </AdminKVField>
                <AdminKVField label="重置日" htmlFor="node-traffic-reset-day">
                  <Select
                    value={form.trafficResetDay}
                    onValueChange={(value) => {
                      if (editorInputDisabled || value === null) {
                        return;
                      }
                      updateFormField("trafficResetDay", value);
                    }}
                    disabled={quotaEmpty || editorInputDisabled}
                  >
                    <SelectTrigger id="node-traffic-reset-day" className={adminSelectTriggerClass}>
                      <SelectValue>{`每月 ${form.trafficResetDay} 日`}</SelectValue>
                    </SelectTrigger>
                    <SelectContent className={adminSelectContentClass}>
                      {Array.from({ length: 28 }, (_, index) => index + 1).map((day) => (
                        <SelectItem key={day} value={String(day)}>
                          {`每月 ${day} 日`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </AdminKVField>
              </div>
            </section>

            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                分组与标签
              </h3>
              {groupCatalog.length === 0 ? (
                <p className="text-sm text-[var(--label-3)]">当前还没有分组树，请先在“分组管理”页维护结构。</p>
              ) : (
                <DropdownMenu>
                  <DropdownMenuTrigger
                    render={(
                      <Button
                        id="node-group-selection-trigger"
                        type="button"
                        variant="outline"
                        className="h-9 w-full justify-between rounded-lg border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-3 text-left text-sm font-medium text-slate-700 shadow-none hover:bg-[var(--cm-control-hover)] dark:text-neutral-200"
                        disabled={editorInputDisabled}
                      >
                        <span
                          className={`truncate ${
                            selectedGroupCount === 0
                              ? "text-slate-500 dark:text-neutral-400"
                              : "text-slate-700 dark:text-neutral-200"
                          }`}
                        >
                          {selectedGroupState.label}
                        </span>
                        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 text-slate-500 dark:text-neutral-400" />
                      </Button>
                    )}
                  />
                  <DropdownMenuContent
                    align="start"
                    className="w-[min(26rem,calc(100vw-3rem))] rounded-[14px] border border-slate-200/90 bg-[var(--surface-3)] p-2 shadow-[var(--cm-elev-2)] dark:border-neutral-800 dark:bg-[var(--surface-3)]"
                    sideOffset={10}
                  >
                    <div className="border-b border-slate-200/80 px-2 pb-2 text-xs leading-5 text-slate-500 dark:border-neutral-800 dark:text-neutral-400">
                      点击分组或其下方标签即可选择；同一分组下会在分组与标签之间互斥。
                    </div>
                    <div className="mt-2 max-h-[22rem] space-y-2 overflow-y-auto pr-1">
                      {groupCatalog.map((item) => {
                        const currentSelection = selectedGroupState.stats.get(item.group);
                        const groupSelected = currentSelection?.groupSelected || false;
                        const tagSelectedCount = currentSelection?.selectedTags.size || 0;
                        return (
                          <div
                            key={item.group}
                            className="rounded-lg border border-slate-200/80 bg-slate-50/70 p-2 dark:border-neutral-800 dark:bg-[var(--surface-2)]"
                          >
                            <button
                              type="button"
                              className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-2 text-left text-sm font-medium transition-colors ${
                                groupSelected
                                  ? "bg-primary text-primary-foreground"
                                  : "text-slate-700 hover:bg-white dark:text-neutral-200 dark:hover:bg-[var(--surface-3)]"
                              }`}
                              disabled={tagSelectedCount > 0 || editorInputDisabled}
                              onClick={() => handleToggleGroupSelection(item.group)}
                            >
                              <span className="flex items-center gap-2">
                                <FolderTree className="h-4 w-4" />
                                <span>{item.group}</span>
                              </span>
                              <span className="flex items-center gap-2">
                                {tagSelectedCount > 0 ? (
                                  <span
                                    className={`rounded-full px-2 py-1 text-[11px] data-text ${
                                      groupSelected
                                        ? "bg-primary-foreground/15 text-primary-foreground"
                                        : "bg-slate-200 text-slate-600 dark:bg-neutral-800 dark:text-neutral-300"
                                    }`}
                                  >
                                    {`${tagSelectedCount} 个标签`}
                                  </span>
                                ) : null}
                                {groupSelected ? <Check className="h-4 w-4" /> : null}
                              </span>
                            </button>
                            {item.tags.length > 0 ? (
                              <div className="ml-4 mt-2 space-y-1 border-l border-slate-200 pl-2 dark:border-neutral-800">
                                {item.tags.map((tag) => {
                                  const value = `${item.group}:${tag}`;
                                  const tagSelected =
                                    currentSelection?.selectedTags.has(tag) || false;
                                  return (
                                    <button
                                      key={value}
                                      type="button"
                                      className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-2 text-left text-sm transition-colors ${
                                        tagSelected
                                          ? "bg-primary text-primary-foreground"
                                          : "text-slate-600 hover:bg-white dark:text-neutral-300 dark:hover:bg-[var(--surface-3)]"
                                      }`}
                                      disabled={groupSelected || editorInputDisabled}
                                      onClick={() => handleToggleGroupSelection(value)}
                                    >
                                      <span className="truncate">{tag}</span>
                                      {tagSelected ? <Check className="h-4 w-4" /> : null}
                                    </button>
                                  );
                                })}
                              </div>
                            ) : (
                              <div className="ml-4 mt-2 border-l border-dashed border-slate-200 pl-2 text-xs text-slate-500 dark:border-neutral-800 dark:text-neutral-400">
                                暂无标签
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}

              {selectedGroupState.items.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {selectedGroupState.items.map((item) => (
                    <button
                      key={item.value}
                      type="button"
                      className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 transition-colors hover:bg-white dark:border-neutral-800 dark:bg-[var(--surface-2)] dark:text-neutral-200 dark:hover:bg-neutral-800"
                      disabled={editorInputDisabled}
                      onClick={() => handleRemoveGroupSelection(item.value)}
                    >
                      <span>{item.label}</span>
                      <X className="h-3 w-3" />
                    </button>
                  ))}
                </div>
              ) : null}
            </section>
          </>
        ) : null}
      </AdminDrawer>

      {/* A-01 步骤 3：共享规则抽屉。新增时预设 scope={mode:"include",
          nodes:[本节点]}；「完成」只写回规则草稿（D-08），随「保存配置」提交；
          「仅此节点」规则在抽屉内也提供删除。 */}
      {nodeRuleForm ? (
        <AlertRuleDrawer
          open
          rule={nodeRuleForm}
          isNew={!(nodeRules ?? []).some((item) => item.id === nodeRuleForm.id)}
          nodes={nodes}
          groupTree={settings?.group_tree || []}
          channels={settings?.notify_channels || []}
          probes={testCatalog}
          onDone={handleNodeRuleDone}
          lockedNodeId={editingNodeId}
          onDelete={
            nodeRuleForm.metric !== OFFLINE_ALERT_RULE_ID && editingNodeId && isNodeOnlyRule(nodeRuleForm, editingNodeId)
              ? () => removeNodeRuleDraft(nodeRuleForm)
              : undefined
          }
          onClose={closeNodeRuleDrawer}
        />
      ) : null}
    </div>
  );
}
