import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronsUpDown,
  Edit2,
  FolderTree,
  Loader2,
  RefreshCw,
  Search,
  Server,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import type {
  AgentUpdateInfo,
  NetworkTestConfig,
  NodeProfilePayload,
  NodeView,
  SettingsView,
  TestCatalogItem,
  TestSelection,
} from "@/lib/admin-types";
import {
  flattenGroupTree,
  formatDateTime,
  formatMbps,
  formatRelativeTime,
  formatVersionLabel,
  getErrorMessage,
  normalizeSelectionValues,
  resolveNodeSelectionValues,
  resolveNodeIdentitySummary,
  parseSelectionValue,
  resolveNodeId,
  resolveNodeName,
  resolveProbeLabel,
  upsertSelectionValue,
} from "@/lib/admin-format";
import {
  buildAgentInstallCommand,
  buildAgentWindowsInstallCommand,
} from "@/lib/agent-install";
import {
  adminActionButtonClass,
  adminAccentBadgeClass,
  adminCodeBlockPanelClass,
  adminDetailCardClass,
  adminDetailGroupClass,
  adminDetailHeaderClass,
  adminDetailHintPanelClass,
  adminDetailWarningPanelClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDangerBadgeClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminEmptyStateClass,
  adminInlineEmptyStateClass,
  adminInputClass,
  adminOutlineButtonClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminNeutralBadgeClass,
  adminPreviewPanelClass,
  adminSectionHeaderClass,
  adminSectionIntroPanelClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminSuccessBadgeClass,
  adminStatCardClass,
  adminStatCardHeaderClass,
  adminStatEyebrowClass,
  adminStatIconChipClass,
  adminStatIconChipClassByTone,
  adminStatSurfaceClassByTone,
  adminStatValueToneClassByTone,
  adminSurfaceCardClass,
  adminWarningBadgeClass,
  adminWorkspaceActionChipClass,
  adminWorkspaceHeaderClass,
  adminWorkspaceItemClass,
  adminWorkspaceListClass,
  adminWorkspaceMetaCardClass,
  adminWorkspaceMetaGridClass,
  adminWorkspaceMetaLabelClass,
} from "@/lib/admin-ui";

const DEFAULT_TCP_INTERVAL = 5;

const statCardLabelClass = adminStatEyebrowClass;

const sectionCardClass = `overflow-hidden ${adminSurfaceCardClass}`;

const sectionHeaderClass = adminSectionHeaderClass;

const formInputClass = adminInputClass;

const outlineActionClass = `${adminOutlineButtonClass} h-11 px-5`;

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
  expireAt: string;
  renewPlan: RenewPlan;
  groups: string[];
  testSelections: SelectionDraft;
};

type BuildPayloadOptions = {
  clearLegacyTests?: boolean;
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
  onCheckAgentUpdate: (nodeID: string) => Promise<AgentUpdateInfo>;
  onRefresh: () => Promise<void>;
  onSaveNode: (nodeID: string, payload: NodeProfilePayload) => Promise<void>;
  onDeleteNode: (nodeID: string) => Promise<void>;
  onTriggerAgentUpdate: (nodeID: string) => Promise<{ status: string; target_version?: string }>;
}

function toDateTimeLocalValue(value?: number) {
  if (!value) return "";
  const date = new Date(value * 1000);
  const pad = (num: number) => String(num).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

function parseDateTimeLocalValue(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const timestamp = new Date(trimmed).getTime();
  if (Number.isNaN(timestamp)) {
    return 0;
  }
  return Math.floor(timestamp / 1000);
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

function renewPlanLabel(plan: RenewPlan) {
  switch (plan) {
    case "month":
      return "按月续费";
    case "quarter":
      return "按季度续费";
    case "half":
      return "按半年续费";
    case "year":
      return "按年续费";
    default:
      return "不自动续费";
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

function testKey(test?: Partial<NetworkTestConfig | TestCatalogItem>) {
  const type = String(test?.type || "icmp").trim().toLowerCase();
  const host = String(test?.host || "").trim().toLowerCase();
  const port = Number(test?.port || 0);
  return `${type}|${host}|${port}`;
}

function defaultInterval(item?: TestCatalogItem) {
  const raw = Number(item?.interval_sec || 0);
  if (!Number.isFinite(raw) || raw <= 0) {
    return DEFAULT_TCP_INTERVAL;
  }
  return Math.min(Math.trunc(raw), 3600);
}

function isTCPTest(test?: Partial<NetworkTestConfig | TestCatalogItem>) {
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
      ? Math.min(rawInterval, 3600)
      : defaultInterval(item),
  );
}

function parseTestSelectionInterval(item: TestCatalogItem, rawValue: string) {
  if (!isTCPTest(item)) {
    return 0;
  }
  const parsedInterval = Number.parseInt(rawValue, 10);
  return Number.isFinite(parsedInterval) && parsedInterval >= 0
    ? Math.min(parsedInterval, 3600)
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

  if (!Array.isArray(node.tests) || node.tests.length === 0) {
    return selections;
  }

  const byKey = new Map<string, TestCatalogItem>();
  catalog.forEach((item) => {
    byKey.set(testKey(item), item);
  });

  node.tests.forEach((test) => {
    const matched = byKey.get(testKey(test));
    if (!matched?.id) {
      return;
    }
    selections[matched.id] = buildTestSelectionValue(matched, test.interval_sec);
  });

  return selections;
}

function buildFormState(node: NodeView, catalog: TestCatalogItem[]): FormState {
  return {
    alias: node.alias || node.stats.node_alias || "",
    region: node.region || "",
    diskType: node.disk_type || "",
    netSpeedMbps: node.net_speed_mbps ? String(node.net_speed_mbps) : "",
    alertEnabled: node.alert_enabled !== false,
    expireAt: toDateTimeLocalValue(node.expire_at),
    renewPlan: resolveRenewPlan(node.auto_renew, node.renew_interval_sec),
    groups: resolveNodeSelectionValues(node),
    testSelections: buildInitialSelections(node, catalog),
  };
}

function buildPayload(
  form: FormState,
  catalog: TestCatalogItem[],
  options: BuildPayloadOptions = {},
): NodeProfilePayload {
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

  const payload: NodeProfilePayload = {
    alias: form.alias.trim(),
    alert_enabled: form.alertEnabled,
    auto_renew: autoRenew,
    disk_type: form.diskType.trim(),
    groups: normalizeSelectionValues(form.groups),
    net_speed_mbps:
      Number.isFinite(normalizedSpeed) && normalizedSpeed >= 0 ? normalizedSpeed : 0,
    region: form.region.trim().toUpperCase(),
    test_selections: selections,
  };

  if (options.clearLegacyTests) {
    payload.tests = [];
  }

  if (expireAt > 0) {
    payload.expire_at = expireAt;
    if (renewIntervalSec > 0) {
      payload.renew_interval_sec = renewIntervalSec;
    }
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
  const [refreshingAgentUpdate, setRefreshingAgentUpdate] = useState(false);
  const [agentUpdateInfo, setAgentUpdateInfo] = useState<AgentUpdateInfo | null>(null);
  const [updatingAgent, setUpdatingAgent] = useState(false);
  const [installPlatform, setInstallPlatform] = useState<"unix" | "windows">("unix");
  const formInitializationKeyRef = useRef("");
  const lastOpenedNodeCardRef = useRef("");
  const lastScrollYRef = useRef(0);

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
    let alertDisabled = 0;

    nodes.forEach((node) => {
      if (node.status === "online") {
        online += 1;
      }
      if (node.alert_enabled === false) {
        alertDisabled += 1;
      }

      const nodeId = resolveNodeId(node);
      const nodeName = resolveNodeName(node);
      const nodeGroups = resolveNodeSelectionValues(node);
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
        alertDisabled,
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

  const metricCards = [
    {
      label: "节点总数",
      value: metrics.total,
      icon: Server,
      tone: "neutral",
    },
    {
      label: "在线节点",
      value: metrics.online,
      icon: Activity,
      tone: "success",
    },
    {
      label: "已关闭告警",
      value: metrics.alertDisabled,
      icon: AlertTriangle,
      tone: "warning",
    },
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

  useEffect(() => {
    if (!editingNode) {
      setForm(null);
      setAgentUpdateInfo(null);
      formInitializationKeyRef.current = "";
      return;
    }
    const nextKey = `${editingNodeId}::${testCatalogSignature}`;
    if (formInitializationKeyRef.current === nextKey) {
      return;
    }
    setForm(buildFormState(editingNode, testCatalog));
    formInitializationKeyRef.current = nextKey;
  }, [editingNode, editingNodeId, testCatalog, testCatalogSignature]);

  const patchForm = (updater: (current: FormState) => FormState) => {
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
  const usingLegacyTestsFallback = Boolean(
    editingNode &&
      (!Array.isArray(editingNode.test_selections) || editingNode.test_selections.length === 0) &&
      Array.isArray(editingNode.tests) &&
      editingNode.tests.length > 0,
  );
  const hasExpireAt = Boolean(form?.expireAt.trim());
  const renewActive = Boolean(hasExpireAt && form?.renewPlan !== "none");
  const alertStatusLabel = form?.alertEnabled ? "已启用离线告警" : "已关闭离线告警";
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

  const handleOpen = (node: NodeView) => {
    const nodeID = resolveNodeId(node);
    lastOpenedNodeCardRef.current = nodeID;
    lastScrollYRef.current = window.scrollY;
    setEditingNodeId(nodeID);
  };

  const closeEditor = () => {
    const restoreNodeID = lastOpenedNodeCardRef.current;
    setEditingNodeId("");
    if (!restoreNodeID) {
      return;
    }
    window.requestAnimationFrame(() => {
      window.scrollTo({ top: lastScrollYRef.current, behavior: "auto" });
      const selector = `[data-node-card-id="${escapeSelectorValue(restoreNodeID)}"]`;
      const target = document.querySelector<HTMLElement>(selector);
      target?.focus({ preventScroll: true });
    });
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await onRefresh();
      toast.success("节点列表已刷新");
    } catch (error) {
      toast.error(getErrorMessage(error, "刷新节点列表失败"));
    } finally {
      setRefreshing(false);
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
    if (!itemId) {
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

  const handleSave = async () => {
    if (!editingNode || !form) {
      return;
    }
    setSaving(true);
    try {
      const payload = buildPayload(form, testCatalog, {
        clearLegacyTests: usingLegacyTestsFallback,
      });
      await onSaveNode(resolveNodeId(editingNode), payload);
      toast.success("节点配置已保存并下发");
      closeEditor();
    } catch (error) {
      toast.error(getErrorMessage(error, "保存节点配置失败"));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!editingNode) {
      return;
    }
    setDeleting(true);
    try {
      await onDeleteNode(resolveNodeId(editingNode));
      toast.success("节点已删除");
      setDeleteDialogOpen(false);
      closeEditor();
    } catch (error) {
      toast.error(getErrorMessage(error, "删除节点失败"));
    } finally {
      setDeleting(false);
    }
  };

  const copyInstallCommand = async (value: string) => {
    if (!value) {
      return;
    }
    try {
      await copyTextToClipboard(value);
      toast.success("命令已复制");
    } catch {
      toast.error("复制失败，请手动选择命令后复制");
    }
  };

  const handleCheckAgentUpdate = async () => {
    if (!editingNode) {
      return;
    }
    setRefreshingAgentUpdate(true);
    try {
      const info = await onCheckAgentUpdate(resolveNodeId(editingNode));
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
      setRefreshingAgentUpdate(false);
    }
  };

  const handleAgentUpdate = async () => {
    if (!editingNode) {
      return;
    }
    setUpdatingAgent(true);
    try {
      const result = await onTriggerAgentUpdate(resolveNodeId(editingNode));
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
      setUpdatingAgent(false);
    }
  };

  return (
    <div className={adminPageShellClass}>
      <section className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>节点管理</h1>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative min-w-[320px]">
            <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
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
            disabled={refreshing || loading}
          >
            {refreshing || loading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            刷新节点
          </Button>
        </div>
      </section>

      <Card className={sectionCardClass}>
        <CardHeader className={sectionHeaderClass}>
          <CardTitle className="flex items-center gap-3 text-slate-900 dark:text-slate-50">
            <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-100 text-emerald-700 dark:bg-emerald-900 dark:text-emerald-100">
              <Terminal className="h-5 w-5" />
            </span>
            <span>Agent 快速接入</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 p-5">
          {installReady ? (
            <div className="grid gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className={`${
                    installPlatform === "unix" ? adminPrimaryButtonClass : adminActionButtonClass
                  } h-11 min-w-[148px] px-5`}
                  onClick={() => setInstallPlatform("unix")}
                >
                  Linux / macOS
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className={`${
                    installPlatform === "windows" ? adminPrimaryButtonClass : adminActionButtonClass
                  } h-11 min-w-[148px] px-5`}
                  onClick={() => setInstallPlatform("windows")}
                >
                  Windows
                </Button>
              </div>

              <div className="grid gap-2">
                <button
                  aria-label={`复制${installPlatform === "windows" ? " Windows " : " Linux / macOS "}Agent 接入命令`}
                  id={installPlatform === "windows" ? agentInstallWindowsId : agentInstallLinuxId}
                  type="button"
                  className={`${adminCodeBlockPanelClass} w-full select-text whitespace-pre-wrap break-all text-left transition-colors hover:border-sky-200 hover:bg-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400 dark:hover:border-sky-800 dark:hover:bg-slate-900`}
                  onClick={() => copyInstallCommand(activeInstallCommand)}
                  title="单击复制完整命令，拖拽可自由选择局部内容"
                >
                  <code className="block w-full select-text whitespace-pre-wrap break-all text-left font-inherit">
                    {activeInstallCommand}
                  </code>
                </button>
              </div>
            </div>
          ) : (
            <div className={adminSectionIntroPanelClass}>
              请先在基础设置的 Agent 配置中填写对接地址与 Agent Token。
            </div>
          )}
        </CardContent>
      </Card>

      <section className="grid auto-rows-fr gap-4 md:grid-cols-3">
        {metricCards.map((item) => {
          const Icon = item.icon;
          return (
            <Card key={item.label} className={`${adminStatCardClass} ${adminStatSurfaceClassByTone[item.tone]}`}>
              <CardHeader className={adminStatCardHeaderClass}>
                <div>
                  <CardDescription className={statCardLabelClass}>
                    {item.label}
                  </CardDescription>
                  <CardTitle className={`mt-3 text-3xl font-black tracking-tighter ${adminStatValueToneClassByTone[item.tone]}`}>
                    {item.value}
                  </CardTitle>
                </div>
                <div className={`${adminStatIconChipClass} ${adminStatIconChipClassByTone[item.tone]}`}>
                  <Icon className="h-5 w-5" />
                </div>
              </CardHeader>
            </Card>
          );
        })}
      </section>

      <Card className={sectionCardClass}>
        <CardHeader className={sectionHeaderClass}>
          <CardTitle className="flex items-center gap-3 text-slate-900 dark:text-slate-50">
            <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-sky-100 text-sky-700 dark:bg-sky-900 dark:text-sky-100">
              <Server className="h-5 w-5" />
            </span>
            <span>服务器管理</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 p-5">
          <div className={adminWorkspaceListClass}>
            {filteredNodes.length === 0 ? (
              <div className={`${adminEmptyStateClass} text-sm text-slate-500 dark:text-slate-400`}>
                {nodes.length === 0 ? "当前还没有节点接入。" : "没有匹配的节点，请调整搜索条件。"}
              </div>
            ) : (
              filteredNodes.map((entry) => {
                const { node, nodeGroups, nodeId, nodeName } = entry;
                const renewSummary =
                  node.auto_renew && node.renew_interval_sec
                    ? ` ／ ${renewPlanLabel(resolveRenewPlan(node.auto_renew, node.renew_interval_sec))}`
                    : "";

                return (
                  <button
                    key={nodeId}
                    data-node-card-id={nodeId}
                    type="button"
                    onClick={() => handleOpen(node)}
                    className={adminWorkspaceItemClass}
                    style={{ contentVisibility: "auto", containIntrinsicSize: "296px" }}
                  >
                    <div className={adminWorkspaceHeaderClass}>
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-base font-semibold text-slate-900 dark:text-slate-50">{nodeName}</span>
                          {renderStatusBadge(node.status)}
                          {node.alert_enabled === false ? (
                            <Badge variant="outline" className={adminWarningBadgeClass}>
                              告警已关闭
                            </Badge>
                          ) : null}
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-400">
                          Node ID：{nodeId} ／ 主机名：{node.stats.hostname || "--"} ／ Agent：{node.stats.agent_version || "--"}
                        </div>
                      </div>
                      <div className={adminWorkspaceActionChipClass}>
                        <Edit2 className="h-4 w-4" />
                        编辑配置
                      </div>
                    </div>

                    <div className={adminWorkspaceMetaGridClass}>
                      <div className={adminWorkspaceMetaCardClass}>
                        <div className={adminWorkspaceMetaLabelClass}>最近状态</div>
                        <div className="mt-1 font-medium">{formatRelativeTime(node.last_seen)}</div>
                        <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                          {node.status === "online" ? "当前在线，可直接下发配置" : "当前离线，配置会在恢复后生效"}
                        </div>
                      </div>
                      <div className={adminWorkspaceMetaCardClass}>
                        <div className={adminWorkspaceMetaLabelClass}>资源快照</div>
                        <div className="mt-1 font-medium">
                          CPU {Math.round(node.stats.cpu.usage_percent || 0)}% ／ 内存{" "}
                          {Math.round(node.stats.memory.used_percent || 0)}%
                        </div>
                        <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                          带宽：{formatMbps(node.net_speed_mbps)}
                        </div>
                      </div>
                      <div className={adminWorkspaceMetaCardClass}>
                        <div className={adminWorkspaceMetaLabelClass}>运行环境</div>
                        <div className="mt-1 font-medium">
                          {node.stats.os} ／ {node.stats.arch}
                        </div>
                        <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                          地区：{(node.region || "--").toUpperCase()}
                        </div>
                      </div>
                      <div className={adminWorkspaceMetaCardClass}>
                        <div className={adminWorkspaceMetaLabelClass}>归属与续费</div>
                        <div className="mt-1 line-clamp-2 font-medium">
                          {nodeGroups.length > 0 ? nodeGroups.join("，") : "未分组"}
                        </div>
                        <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                          {node.expire_at ? formatDateTime(node.expire_at) : "未设置到期时间"}
                          {renewSummary}
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>

      <Dialog open={Boolean(editingNode && form)} onOpenChange={(open) => !open && closeEditor()}>
        <DialogContent
          className={`flex max-h-[min(92vh,960px)] w-[min(100vw-2rem,70rem)] max-w-none flex-col gap-0 overflow-hidden p-0 sm:max-w-[min(100vw-2rem,70rem)] ${adminDialogContentClass}`}
        >
          <DialogHeader className={adminDialogHeaderClass}>
            <div className="space-y-2">
              <DialogTitle className="text-xl font-semibold text-slate-900 dark:text-slate-50">
                节点配置编辑
              </DialogTitle>
              <DialogDescription className="text-sm text-slate-500 dark:text-slate-400">
                {editingNode
                  ? `${resolveNodeName(editingNode)} ／ ${resolveNodeIdentitySummary(editingNode)}`
                  : "选择节点后编辑"}
              </DialogDescription>
            </div>
          </DialogHeader>

          {editingNode && form ? (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="flex-1 overflow-y-auto px-6 py-6">
                <div className="space-y-6">
                  <div className={`grid gap-3 md:grid-cols-3 ${adminSectionIntroPanelClass}`}>
                    <div className={adminWorkspaceMetaCardClass}>
                      <div className={adminWorkspaceMetaLabelClass}>编辑目标</div>
                      <div className="mt-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {resolveNodeName(editingNode)}
                      </div>
                    </div>
                    <div className={adminWorkspaceMetaCardClass}>
                      <div className={adminWorkspaceMetaLabelClass}>资源快照</div>
                      <div className="mt-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                        CPU {Math.round(editingNode.stats.cpu.usage_percent || 0)}% ／ 内存{" "}
                        {Math.round(editingNode.stats.memory.used_percent || 0)}%
                      </div>
                    </div>
                    <div className={adminWorkspaceMetaCardClass}>
                      <div className={adminWorkspaceMetaLabelClass}>运行环境</div>
                      <div className="mt-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                        {editingNode.stats.os} ／ {editingNode.stats.arch}
                      </div>
                    </div>
                  </div>
                  <Card className={adminDetailCardClass}>
                    <CardHeader className={adminDetailHeaderClass}>
                      <CardTitle className="flex items-center gap-2 text-base text-slate-900 dark:text-slate-50">
                        <RefreshCw className="h-4 w-4 text-sky-500 dark:text-sky-300" />
                        Agent 更新
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5 p-6">
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className={adminPreviewPanelClass}>
                          <p className={statCardLabelClass}>当前版本</p>
                          <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                            {formatVersionLabel(editingAgentVersion)}
                          </p>
                        </div>
                        <div className={adminPreviewPanelClass}>
                          <p className={statCardLabelClass}>最新版本</p>
                          <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                            {agentLatestVersionLabel}
                          </p>
                        </div>
                      </div>
                      {editingNode.agent_update_supported ? (
                        <div className="flex flex-wrap items-center gap-3">
                          <Button
                            type="button"
                            variant="outline"
                            className={`${adminActionButtonClass} h-11 px-5`}
                            onClick={handleCheckAgentUpdate}
                            disabled={Boolean(agentUpdateDisabledReason) || refreshingAgentUpdate || updatingAgent}
                            title={agentUpdateDisabledReason || undefined}
                          >
                            {refreshingAgentUpdate ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                            检查更新
                          </Button>
                          <Button
                            type="button"
                            className={`${adminPrimaryButtonClass} h-11 px-5`}
                            onClick={handleAgentUpdate}
                            disabled={Boolean(agentUpdateActionDisabledReason) || refreshingAgentUpdate || updatingAgent}
                            title={agentUpdateActionDisabledReason || undefined}
                          >
                            {updatingAgent ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                            {updatingAgent ? "更新中" : "立即更新"}
                          </Button>
                        </div>
                      ) : (
                        <div className={adminDetailHintPanelClass}>
                          {agentUpdateDisabledReason || "当前 Agent 已禁用远程更新"}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                  <Card className={adminDetailCardClass}>
                    <CardHeader className={adminDetailHeaderClass}>
                      <CardTitle className="flex items-center gap-2 text-base text-slate-900 dark:text-slate-50">
                        <Server className="h-4 w-4 text-sky-500 dark:text-sky-300" />
                        节点资料
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5 p-6">
                      <div className={adminDetailGroupClass}>
                        <div className="space-y-1">
                          <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">识别信息</h4>
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="grid gap-2">
                            <Label htmlFor="node-alias">显示名称</Label>
                            <Input
                              id="node-alias"
                              name="node-alias"
                              autoComplete="off"
                              className={formInputClass}
                              value={form.alias}
                              onChange={(event) => updateFormField("alias", event.target.value)}
                              placeholder={editingNode.stats.node_name || editingNode.stats.hostname}
                            />
                          </div>
                          <div className="grid gap-2">
                            <Label htmlFor="node-region">地区代码</Label>
                            <Input
                              id="node-region"
                              name="node-region"
                              autoComplete="off"
                              className={formInputClass}
                              value={form.region}
                              onChange={(event) =>
                                updateFormField("region", event.target.value.toUpperCase())
                              }
                              placeholder="例如：US"
                            />
                          </div>
                        </div>
                        <div className="grid gap-3 md:grid-cols-2">
                          <div className={adminWorkspaceMetaCardClass}>
                            <div className={adminWorkspaceMetaLabelClass}>当前主机名</div>
                            <div className="mt-1 font-medium">{editingNode.stats.hostname || "--"}</div>
                          </div>
                          <div className={adminWorkspaceMetaCardClass}>
                            <div className={adminWorkspaceMetaLabelClass}>Node ID</div>
                            <div className="mt-1 font-medium">{resolveNodeId(editingNode)}</div>
                          </div>
                        </div>
                      </div>

                      <div className={adminDetailGroupClass}>
                        <div className="space-y-1">
                          <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">资源标注</h4>
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="grid gap-2">
                            <Label htmlFor="node-disk-type">磁盘类型</Label>
                            <Input
                              id="node-disk-type"
                              name="node-disk-type"
                              autoComplete="off"
                              className={formInputClass}
                              value={form.diskType}
                              onChange={(event) => updateFormField("diskType", event.target.value)}
                              placeholder="NVMe / SSD / HDD"
                            />
                          </div>
                          <div className="grid gap-2">
                            <Label htmlFor="node-net-speed">带宽（Mbps）</Label>
                            <Input
                              id="node-net-speed"
                              name="node-net-speed"
                              className={formInputClass}
                              type="number"
                              min={0}
                              autoComplete="off"
                              value={form.netSpeedMbps}
                              onChange={(event) =>
                                updateFormField("netSpeedMbps", event.target.value)
                              }
                              placeholder="1000"
                            />
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className={adminDetailCardClass}>
                    <CardHeader className={adminDetailHeaderClass}>
                      <CardTitle className="flex items-center gap-2 text-base text-slate-900 dark:text-slate-50">
                        <Activity className="h-4 w-4 text-emerald-500 dark:text-emerald-300" />
                        探测下发策略
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5 p-6">
                      <div className={adminDetailHintPanelClass}>
                        已选 {testDraftState.summary.selected} 个探测节点。
                        {testDraftState.summary.tcpCustom > 0
                          ? ` 其中 ${testDraftState.summary.tcpCustom} 个 TCP 节点使用了自定义间隔。`
                          : ""}
                      </div>

                      {testCatalog.length === 0 ? (
                        <div className={adminInlineEmptyStateClass}>
                          请先在“探测设置”页配置探测节点。
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {testDraftState.items.map((entry) => {
                            const { item, itemId, active, isTCP, intervalValue, defaultIntervalSec } =
                              entry;
                            return (
                              <div
                                key={item.id || resolveProbeLabel(item)}
                                className={`rounded-[1.25rem] border px-4 py-4 transition-colors ${
                                  active
                                    ? "border-sky-200 bg-sky-50/70 dark:border-sky-800 dark:bg-sky-950/30"
                                    : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950"
                                }`}
                              >
                                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                                  <label className="flex flex-1 items-start gap-3">
                                    <input
                                      type="checkbox"
                                      className="mt-1 h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500 dark:border-slate-700 dark:bg-slate-950"
                                      checked={active}
                                      disabled={!itemId}
                                      onChange={() => handleToggleTest(entry)}
                                    />
                                    <div className="min-w-0 space-y-1">
                                      <div className="flex flex-wrap items-center gap-2">
                                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                                          {item.name || item.host || "未命名探测节点"}
                                        </span>
                                        <span
                                          className={
                                            isTCP ? adminAccentBadgeClass : adminNeutralBadgeClass
                                          }
                                        >
                                          {isTCP ? "TCP" : "ICMP"}
                                        </span>
                                      </div>
                                      <div className="text-xs text-slate-500 dark:text-slate-400">
                                        {resolveProbeLabel(item)}
                                      </div>
                                    </div>
                                  </label>

                                  <div className="flex items-center gap-3 lg:pl-6">
                                    {isTCP ? (
                                      <>
                                        <span className="text-xs font-medium uppercase tracking-[0.18em] text-slate-400 dark:text-slate-500">
                                          Interval
                                        </span>
                                        <Input
                                          name={itemId ? `probe-interval-${itemId}` : "probe-interval"}
                                          className="h-10 w-[148px] rounded-xl border-slate-300 bg-white text-sm dark:border-slate-700 dark:bg-slate-950"
                                          type="number"
                                          min={0}
                                          max={3600}
                                          autoComplete="off"
                                          disabled={!active || !itemId}
                                          value={intervalValue}
                                          onChange={(event) =>
                                            handleTestIntervalChange(itemId, event.target.value)
                                          }
                                          placeholder={`默认 ${defaultIntervalSec} 秒`}
                                        />
                                      </>
                                    ) : (
                                      <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400">
                                        固定执行
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {usingLegacyTestsFallback ? (
                        <div className={adminDetailHintPanelClass}>
                          当前节点沿用了旧版探测字段，本页已自动回填到新的探测选择器中。
                        </div>
                      ) : null}
                    </CardContent>
                  </Card>

                  <Card className={adminDetailCardClass}>
                    <CardHeader className={adminDetailHeaderClass}>
                      <CardTitle className="flex items-center gap-2 text-base text-slate-900 dark:text-slate-50">
                        <AlertTriangle className="h-4 w-4 text-amber-500 dark:text-amber-300" />
                        生命周期与告警
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5 p-6">
                      <div className={adminDetailGroupClass}>
                        <div className="space-y-1">
                          <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">到期与续费</h4>
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="grid gap-2">
                            <Label htmlFor="node-expire-at">到期时间</Label>
                            <Input
                              id="node-expire-at"
                              name="node-expire-at"
                              className={formInputClass}
                              type="datetime-local"
                              autoComplete="off"
                              value={form.expireAt}
                              onChange={(event) => updateFormField("expireAt", event.target.value)}
                            />
                          </div>
                          <div className="grid gap-2">
                            <Label htmlFor="node-renew-plan">自动续费方案</Label>
                            <Select
                              value={form.renewPlan}
                              onValueChange={(value) => {
                                if (value === null) {
                                  return;
                                }
                                updateFormField("renewPlan", value as RenewPlan);
                              }}
                              disabled={!hasExpireAt}
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
                          </div>
                        </div>
                      </div>

                      <div className={adminDetailGroupClass}>
                        <div className="flex items-center justify-between gap-4">
                          <div className="space-y-1">
                            <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">离线告警</h4>
                            <div className="flex items-center gap-2">
                              <span className={`h-2 w-2 rounded-full ${form.alertEnabled ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]" : "bg-slate-300"}`} />
                              <span className="text-sm font-medium text-slate-600 dark:text-slate-400">{alertStatusLabel}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 bg-white/50 dark:bg-slate-950/50 p-1.5 rounded-full border border-slate-200 dark:border-slate-800">
                            <button
                              type="button"
                              onClick={() => updateFormField("alertEnabled", true)}
                              className={`px-4 py-1.5 rounded-full text-xs font-bold transition-[background-color,color,box-shadow] ${form.alertEnabled ? "bg-slate-900 text-white shadow-lg dark:bg-white dark:text-slate-900" : "text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"}`}
                            >
                              开启
                            </button>
                            <button
                              type="button"
                              onClick={() => updateFormField("alertEnabled", false)}
                              className={`px-4 py-1.5 rounded-full text-xs font-bold transition-[background-color,color,box-shadow] ${!form.alertEnabled ? "bg-slate-900 text-white shadow-lg dark:bg-white dark:text-slate-900" : "text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"}`}
                            >
                              关闭
                            </button>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className={adminDetailCardClass}>
                    <CardHeader className={adminDetailHeaderClass}>
                      <CardTitle className="flex items-center gap-2 text-base text-slate-900 dark:text-slate-50">
                        <FolderTree className="h-4 w-4 text-indigo-500 dark:text-indigo-300" />
                        分组与标签
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4 p-6">
                      {groupCatalog.length === 0 ? (
                        <div className={adminInlineEmptyStateClass}>
                          当前还没有分组树，请先在“分组管理”页维护结构。
                        </div>
                      ) : (
                        <div className="grid gap-2">
                          <DropdownMenu>
                            <DropdownMenuTrigger
                              render={(
                                <Button
                                  id="node-group-selection-trigger"
                                  type="button"
                                  variant="outline"
                                  className="h-11 w-full justify-between rounded-[1.1rem] border-slate-200 bg-white px-4 text-left text-sm font-medium text-slate-700 shadow-none hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200 dark:hover:bg-slate-900"
                                >
                                  <span
                                    className={`truncate ${
                                      selectedGroupCount === 0
                                        ? "text-slate-400 dark:text-slate-500"
                                        : "text-slate-700 dark:text-slate-200"
                                    }`}
                                  >
                                    {selectedGroupState.label}
                                  </span>
                                  <ChevronsUpDown className="ml-3 h-4 w-4 shrink-0 text-slate-400" />
                                </Button>
                              )}
                            />
                            <DropdownMenuContent
                              align="start"
                              className="w-[min(26rem,calc(100vw-3rem))] rounded-[1.3rem] border border-slate-200/90 bg-white/98 p-2 shadow-[0_24px_56px_-36px_rgba(15,23,42,0.32)] dark:border-slate-800 dark:bg-slate-950/98"
                              sideOffset={10}
                            >
                              <div className="border-b border-slate-200/80 px-2 pb-2 text-xs leading-5 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                                点击一级分组或其下方标签即可选择；同一一级分组下会在分组与标签之间互斥。
                              </div>
                              <div className="mt-2 max-h-[22rem] space-y-2 overflow-y-auto pr-1">
                                {groupCatalog.map((item) => {
                                  const currentSelection = selectedGroupState.stats.get(item.group);
                                  const groupSelected = currentSelection?.groupSelected || false;
                                  const tagSelectedCount =
                                    currentSelection?.selectedTags.size || 0;
                                  return (
                                    <div
                                      key={item.group}
                                      className="rounded-[1.1rem] border border-slate-200/80 bg-slate-50/70 p-2 dark:border-slate-800 dark:bg-slate-900/70"
                                    >
                                      <button
                                        type="button"
                                        className={`flex w-full items-center justify-between gap-3 rounded-[0.95rem] px-3 py-2 text-left text-sm font-medium transition ${
                                          groupSelected
                                            ? "bg-sky-600 text-white"
                                            : "text-slate-700 hover:bg-white dark:text-slate-200 dark:hover:bg-slate-950"
                                        }`}
                                        disabled={tagSelectedCount > 0}
                                        onClick={() => handleToggleGroupSelection(item.group)}
                                      >
                                        <span className="flex items-center gap-2">
                                          <FolderTree className="h-4 w-4" />
                                          <span>{item.group}</span>
                                        </span>
                                        <span className="flex items-center gap-2">
                                          {tagSelectedCount > 0 ? (
                                            <span
                                              className={`rounded-full px-2 py-0.5 text-[11px] ${
                                                groupSelected
                                                  ? "bg-white/20 text-white"
                                                  : "bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                                              }`}
                                            >
                                              {tagSelectedCount} 个标签
                                            </span>
                                          ) : null}
                                          {groupSelected ? <Check className="h-4 w-4" /> : null}
                                        </span>
                                      </button>
                                      {item.tags.length > 0 ? (
                                        <div className="ml-5 mt-2 space-y-1 border-l border-slate-200 pl-3 dark:border-slate-800">
                                          {item.tags.map((tag) => {
                                            const value = `${item.group}:${tag}`;
                                            const tagSelected =
                                              currentSelection?.selectedTags.has(tag) || false;
                                            return (
                                              <button
                                                key={value}
                                                type="button"
                                                className={`flex w-full items-center justify-between gap-3 rounded-[0.9rem] px-3 py-2 text-left text-sm transition ${
                                                  tagSelected
                                                    ? "bg-indigo-600 text-white"
                                                    : "text-slate-600 hover:bg-white dark:text-slate-300 dark:hover:bg-slate-950"
                                                }`}
                                                disabled={groupSelected}
                                                onClick={() => handleToggleGroupSelection(value)}
                                              >
                                                <span className="truncate">{tag}</span>
                                                {tagSelected ? <Check className="h-4 w-4" /> : null}
                                              </button>
                                            );
                                          })}
                                        </div>
                                      ) : (
                                        <div className="ml-5 mt-2 border-l border-dashed border-slate-200 pl-3 text-xs text-slate-400 dark:border-slate-800 dark:text-slate-500">
                                          暂无二级标签
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      )}

                      {selectedGroupState.items.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {selectedGroupState.items.map((item) => (
                            <button
                              key={item.value}
                              type="button"
                              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm font-medium text-slate-700 transition hover:border-slate-300 hover:bg-white dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200 dark:hover:border-slate-700"
                              onClick={() => handleRemoveGroupSelection(item.value)}
                            >
                              <span>{item.label}</span>
                              <span className="rounded-full bg-slate-200 px-2 py-0.5 text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                                {item.level}
                              </span>
                              <X className="h-3.5 w-3.5" />
                            </button>
                          ))}
                        </div>
                      ) : null}

                    </CardContent>
                  </Card>

              </div>
              </div>

              <Separator className="bg-slate-200 dark:bg-slate-800" />

              <DialogFooter className={`${adminDialogFooterClass} flex-col-reverse gap-3 sm:flex-row sm:justify-between items-center px-8 py-6`}>
                <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
                  <AlertDialogTrigger
                    render={(
                      <Button
                        type="button"
                        variant="destructive"
                        className={`${adminDialogDangerActionClass} h-12 min-w-[140px] px-6 font-bold`}
                        disabled={saving || deleting}
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
                        {editingNode ? `确认删除节点“${resolveNodeName(editingNode)}”？` : "确认删除节点？"}
                      </AlertDialogTitle>
                    </AlertDialogHeader>
                    <AlertDialogFooter className={adminDialogFooterClass}>
                      <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                      <AlertDialogAction
                        className={adminDialogDangerActionClass}
                        onClick={handleDelete}
                      >
                        {deleting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                        确认删除
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
                <div className="flex gap-3 w-full sm:w-auto">
                  <Button
                    type="button"
                    variant="outline"
                    className={`${adminOutlineButtonClass} h-12 flex-1 sm:flex-none min-w-[100px] px-8 font-bold`}
                    onClick={closeEditor}
                    disabled={saving || deleting}
                  >
                    取消
                  </Button>
                  <Button
                    type="button"
                    className={`${adminPrimaryButtonClass} h-12 flex-1 sm:flex-none min-w-[140px] px-8 font-bold`}
                    onClick={handleSave}
                    disabled={saving || deleting}
                  >
                    {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                    保存配置
                  </Button>
                </div>
              </DialogFooter>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
