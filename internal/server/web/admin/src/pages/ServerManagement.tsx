import { useEffect, useMemo, useRef, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import {
  Check,
  ChevronsUpDown,
  FolderTree,
  Loader2,
  RefreshCw,
  Rocket,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
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
import { DEFAULT_TCP_INTERVAL, MAX_TCP_INTERVAL, type AgentUpdateInfo,
  NodeDeleteResponse,
  NodeProfilePayload,
  NodeView,
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
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDangerBadgeClass,
  adminDangerOutlineButtonClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminInputClass,
  adminOutlineButtonClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminSuccessBadgeClass,
  adminWarningBadgeClass,
} from "@/lib/admin-ui";

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
    return DEFAULT_TCP_INTERVAL;
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
  if (!isTCPTest(item)) {
    return "0";
  }
  const rawInterval = Math.trunc(Number(intervalSec) || 0);
  return String(
    Number.isFinite(rawInterval) && rawInterval > 0
      ? Math.min(rawInterval, MAX_TCP_INTERVAL)
      : defaultInterval(item),
  );
}

function parseTestSelectionInterval(item: TestCatalogItem, rawValue: string) {
  if (!isTCPTest(item)) {
    return 0;
  }
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

function buildPayload(form: FormState, catalog: TestCatalogItem[]): NodeProfilePayload {
  const expireAt = parseDateTimeLocalValue(form.expireAt);
  if (form.expireAt && !expireAt) {
    throw new Error("到期时间格式无效，请重新选择");
  }

  const autoRenew = expireAt > 0 && form.renewPlan !== "none";
  const renewIntervalSec = autoRenew ? planToSeconds(form.renewPlan) : 0;
  const normalizedSpeed = Number.parseInt(form.netSpeedMbps, 10);
  const selections: TestSelection[] = buildTestDraftEntries(catalog, form.testSelections)
    .filter((entry) => entry.active && entry.itemId)
    .map(({ item, itemId, intervalValue }) => ({
      test_id: itemId,
      interval_sec: parseTestSelectionInterval(item, intervalValue),
    }));

  const region = normalizeRegionInput(form.region);
  if (form.region.trim() && !region) {
    throw new Error("地区代码无效：请输入两位字母代码（如 SG / JP / HK）。");
  }

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
    test_selections: selections,
  };

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

function renderStatusBadge(status: string) {
  if (status === "online") {
    return <Badge className={adminSuccessBadgeClass}>在线</Badge>;
  }
  return (
    <Badge variant="secondary" className={adminDangerBadgeClass}>
      离线
    </Badge>
  );
}

const nodeTableColumns: ReadonlyArray<AdminDataTableColumn<NodeListEntry>> = [
  {
    key: "name",
    label: "名称",
    align: "left",
    width: "1%",
    render: (entry) => (
      <span className="inline-flex min-w-0 max-w-[300px] items-center gap-2">
        <span className="truncate text-sm font-medium text-slate-900 dark:text-neutral-50">
          {entry.nodeName}
        </span>
        {renderStatusBadge(entry.node.status)}
        {entry.node.alert_enabled === false ? (
          <Badge variant="outline" className={adminWarningBadgeClass}>
            告警已关闭
          </Badge>
        ) : null}
      </span>
    ),
  },
  {
    key: "ipv4",
    label: "IPv4",
    width: "1%",
    mono: true,
    render: (entry) => {
      const value = String(entry.node.stats.public_ipv4 || "").trim();
      return value ? (
        <span className="data-text text-sm">{value}</span>
      ) : (
        <span className="text-sm text-[var(--label-3)]">--</span>
      );
    },
  },
  {
    key: "ipv6",
    label: "IPv6",
    width: "360px",
    mono: true,
    render: (entry) => {
      const value = String(entry.node.stats.public_ipv6 || "").trim();
      return value ? (
        <span className="data-text text-sm">{value}</span>
      ) : (
        <span className="text-sm text-[var(--label-3)]">--</span>
      );
    },
  },
  {
    key: "os",
    label: "系统",
    render: (entry) => `${entry.node.stats.os} ／ ${entry.node.stats.arch}`,
  },
  {
    key: "agent",
    label: "Agent",
    width: "1%",
    mono: true,
    render: (entry) => formatVersionLabel(entry.node.stats.agent_version),
  },
  {
    key: "renew",
    label: "续期",
    width: "1%",
    mono: true,
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
      level: tag ? "二级标签" : "一级分组",
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

export default function ServerManagement({
  settings,
  nodes,
  loading = false,
  onDirtyChange,
  onCheckAgentUpdate,
  onRefresh,
  onSaveNode,
  onDeleteNode,
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
  const formInitializationKeyRef = useRef("");
  const formBaselineSignatureRef = useRef("");
  const formSourceSignatureRef = useRef("");
  const agentUpdateRequestSeqRef = useRef(0);
  const lastOpenedNodeCardRef = useRef("");
  const restoreFocusTimerRef = useRef<number | null>(null);
  const runAction = useAsyncAction();

  const testCatalog = settings?.test_catalog || [];
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
  const isEditingDraftDirty = Boolean(
    form && formBaselineSignatureRef.current && currentFormSignature !== formBaselineSignatureRef.current,
  );
  const editorBusy = saving || deleting || refreshing || refreshingAgentUpdate || updatingAgent;
  const editorInputDisabled = editorBusy || sourceConflict;

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
  }, [currentFormSignature, deleting, editingNode, editingNodeId, isEditingDraftDirty, saving, testCatalog, testCatalogSignature]);

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
    void runAction({
      action: () => onSaveNode(resolveNodeId(editingNode), buildPayload(form, testCatalog)),
      fallbackError: "保存节点配置失败",
      successToast: "节点配置已保存并下发",
      onSuccess: () => closeEditor(true),
      setBusy: setSaving,
    });
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
        actionsClassName="flex flex-col gap-2 sm:flex-row sm:items-center"
        actions={
          <>
            <div className="relative min-w-[320px]">
              <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500 dark:text-neutral-400" />
              <Input
                aria-label="搜索节点"
                type="search"
                className={`rounded-full pl-11 ${adminInputClass}`}
                name="node-search"
                autoComplete="off"
                placeholder="例如：搜索节点名、Node ID、主机名、地区…"
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
            {/* 平台切换与日志筛选同款：内容宽、方角、选中墨色（用户第 20 轮：不要胶囊主按钮那么大）。 */}
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                className={
                  installPlatform === "unix"
                    ? "h-9 min-w-0 px-3 text-xs font-medium bg-slate-900 text-white hover:bg-slate-800 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white"
                    : `${adminActionButtonClass} h-9 min-w-0 rounded-lg px-3 text-xs font-medium`
                }
                onClick={() => setInstallPlatform("unix")}
              >
                Linux/macOS
              </Button>
              <Button
                type="button"
                variant="outline"
                className={
                  installPlatform === "windows"
                    ? "h-9 min-w-0 px-3 text-xs font-medium bg-slate-900 text-white hover:bg-slate-800 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white"
                    : `${adminActionButtonClass} h-9 min-w-0 rounded-lg px-3 text-xs font-medium`
                }
                onClick={() => setInstallPlatform("windows")}
              >
                Windows
              </Button>
            </div>
            <code
              id={installPlatform === "windows" ? agentInstallWindowsId : agentInstallLinuxId}
              className={`${adminCodeBlockPanelClass} block w-full cursor-pointer select-text whitespace-pre-wrap break-all focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]`}
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
          <p className="text-[13px] text-slate-500 dark:text-neutral-400">
            请先在基础设置的 Agent 配置中填写 Agent 对接地址。
          </p>
        )}
      </AdminPanel>

      <AdminPanel title="节点列表">
        <AdminDataTable
          ariaLabel="节点列表"
          columns={nodeTableColumns}
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
        onOpenChange={(open) => {
          if (!open) {
            closeEditor();
          }
        }}
        title={editingNode ? resolveNodeName(editingNode) : "节点配置编辑"}
        description={editingNode ? resolveNodeIdentitySummary(editingNode) : undefined}
        footer={
          editingNode && form ? (
            <div className="flex items-center justify-between gap-2">
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
              <div className="flex gap-2">
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
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
                Agent 更新
              </h3>
              {editingNode.agent_update_supported ? (
                <>
                  <AdminKVField label="当前版本">
                    <span className="data-text text-sm font-medium text-slate-800 dark:text-neutral-200">
                      {formatVersionLabel(editingAgentVersion)}
                    </span>
                  </AdminKVField>
                  <AdminKVField label="最新版本">
                    <span
                      className={cn(
                        "text-sm font-medium text-slate-800 dark:text-neutral-200",
                        agentLatestVersionIsValue && "data-text",
                      )}
                    >
                      {agentLatestVersionLabel}
                    </span>
                  </AdminKVField>
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
                <p className="text-xs leading-relaxed text-slate-500 dark:text-neutral-400">
                  {agentUpdateDisabledReason || "当前 Agent 已禁用远程更新"}
                </p>
              )}
            </section>

            <section>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
                显示与标注
              </h3>
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
            </section>

            <section>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
                探测下发策略
              </h3>
              <p className="text-xs text-slate-500 dark:text-neutral-400">
                {`已选 ${testDraftState.summary.selected} 个探测节点。${
                  testDraftState.summary.tcpCustom > 0
                    ? ` 其中 ${testDraftState.summary.tcpCustom} 个 TCP 节点使用了自定义间隔。`
                    : ""
                }`}
              </p>
              {testCatalog.length === 0 ? (
                <p className="text-sm text-[var(--label-3)]">请先在“探测设置”页配置探测节点。</p>
              ) : (
                <div>
                  {testDraftState.items.map((entry) => {
                    const { item, itemId, active, isTCP, intervalValue, defaultIntervalSec } =
                      entry;
                    const host = item.host || "--";
                    const endpoint = item.port ? `${host}:${item.port}` : host;
                    return (
                      <label
                        key={item.id || endpoint}
                        className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-[var(--separator)] py-2.5 last:border-b-0"
                      >
                        <input
                          type="checkbox"
                          className="h-4 w-4 rounded border-slate-300 text-primary focus:ring-[var(--primary-ring)] dark:border-neutral-700 dark:bg-[var(--surface-2)]"
                          checked={active}
                          disabled={!itemId || editorInputDisabled}
                          onChange={() => handleToggleTest(entry)}
                        />
                        <span className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2">
                          <span className="text-sm font-medium text-slate-900 dark:text-neutral-50">
                            {item.name || host || "未命名探测节点"}
                          </span>
                          <span className="data-text truncate text-xs text-[var(--label-3)]">
                            {endpoint}
                          </span>
                        </span>
                        <span className="text-xs text-[var(--label-3)]">{isTCP ? "TCP" : "ICMP"}</span>
                        {isTCP ? (
                          <span className="flex items-center gap-1.5">
                            <Input
                              name={itemId ? `probe-interval-${itemId}` : "probe-interval"}
                              className="h-9 w-20 rounded-lg border-slate-300 bg-white text-sm dark:border-neutral-700 dark:bg-[var(--surface-2)]"
                              type="number"
                              min={0}
                              max={MAX_TCP_INTERVAL}
                              autoComplete="off"
                              disabled={!active || !itemId || editorInputDisabled}
                              value={intervalValue}
                              onChange={(event) =>
                                handleTestIntervalChange(itemId, event.target.value)
                              }
                              placeholder={String(defaultIntervalSec)}
                            />
                            <span className="text-xs text-[var(--label-3)]">秒</span>
                          </span>
                        ) : null}
                      </label>
                    );
                  })}
                </div>
              )}
            </section>

            <section>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
                生命周期与告警
              </h3>
              <AdminKVField label="到期时间" htmlFor="node-expire-at">
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
              </AdminKVField>
              <AdminKVField label="自动续费方案" htmlFor="node-renew-plan">
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
                    <SelectValue placeholder="选择续费方案…" />
                  </SelectTrigger>
                  <SelectContent className={adminSelectContentClass}>
                    <SelectItem value="none">不自动续费</SelectItem>
                    <SelectItem value="month">按月续费（30 天）</SelectItem>
                    <SelectItem value="quarter">按季度续费（90 天）</SelectItem>
                    <SelectItem value="half">按半年续费（180 天）</SelectItem>
                    <SelectItem value="year">按年续费（365 天）</SelectItem>
                  </SelectContent>
                </Select>
              </AdminKVField>
              <AdminKVField label="离线告警">
                <div className="inline-flex items-center gap-1 rounded-full border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] p-1">
                  <button
                    type="button"
                    disabled={editorInputDisabled}
                    onClick={() => updateFormField("alertEnabled", true)}
                    className={`rounded-full px-3.5 py-1 text-xs font-medium transition-[background-color,color] ${
                      form.alertEnabled
                        ? "bg-slate-900 text-white dark:bg-[var(--surface-3)] dark:text-[var(--label-1)]"
                        : "text-slate-500 hover:text-slate-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                    }`}
                  >
                    开启
                  </button>
                  <button
                    type="button"
                    disabled={editorInputDisabled}
                    onClick={() => updateFormField("alertEnabled", false)}
                    className={`rounded-full px-3.5 py-1 text-xs font-medium transition-[background-color,color] ${
                      !form.alertEnabled
                        ? "bg-slate-900 text-white dark:bg-[var(--surface-3)] dark:text-[var(--label-1)]"
                        : "text-slate-500 hover:text-slate-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                    }`}
                  >
                    关闭
                  </button>
                </div>
              </AdminKVField>
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
            </section>

            <section>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
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
                        className="h-9 w-full justify-between rounded-xl border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-3 text-left text-sm font-medium text-slate-700 shadow-none hover:bg-[var(--cm-control-hover)] dark:text-neutral-200"
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
                    className="w-[min(26rem,calc(100vw-3rem))] rounded-[1.3rem] border border-slate-200/90 bg-white/98 p-2 shadow-[var(--cm-elev-2)] dark:border-neutral-800 dark:bg-[var(--surface-3)]"
                    sideOffset={10}
                  >
                    <div className="border-b border-slate-200/80 px-2 pb-2 text-xs leading-5 text-slate-500 dark:border-neutral-800 dark:text-neutral-400">
                      点击一级分组或其下方标签即可选择；同一一级分组下会在分组与标签之间互斥。
                    </div>
                    <div className="mt-2 max-h-[22rem] space-y-2 overflow-y-auto pr-1">
                      {groupCatalog.map((item) => {
                        const currentSelection = selectedGroupState.stats.get(item.group);
                        const groupSelected = currentSelection?.groupSelected || false;
                        const tagSelectedCount = currentSelection?.selectedTags.size || 0;
                        return (
                          <div
                            key={item.group}
                            className="rounded-[1.1rem] border border-slate-200/80 bg-slate-50/70 p-2 dark:border-neutral-800 dark:bg-[var(--surface-2)]"
                          >
                            <button
                              type="button"
                              className={`flex w-full items-center justify-between gap-2 rounded-[0.95rem] px-2 py-2 text-left text-sm font-medium transition-colors ${
                                groupSelected
                                  ? "bg-primary text-primary-foreground"
                                  : "text-slate-700 hover:bg-white dark:text-neutral-200 dark:hover:bg-neutral-950"
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
                                      className={`flex w-full items-center justify-between gap-2 rounded-[0.9rem] px-2 py-2 text-left text-sm transition-colors ${
                                        tagSelected
                                          ? "bg-primary text-primary-foreground"
                                          : "text-slate-600 hover:bg-white dark:text-neutral-300 dark:hover:bg-neutral-950"
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
                                暂无二级标签
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
    </div>
  );
}
