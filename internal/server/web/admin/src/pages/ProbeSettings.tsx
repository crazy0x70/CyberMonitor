import { useEffect, useMemo, useRef, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminEmptyState } from "@/components/admin-empty-state";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminSaveBar } from "@/components/admin-save-bar";
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
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Radio, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { fetchNodes, fetchSettings } from "@/lib/admin-api";
import { flattenGroupTree, resolveNodeId, resolveNodeName } from "@/lib/admin-format";
import { RuleMultiSelect } from "@/components/alert-rule-drawer";
import {
  DEFAULT_TCP_INTERVAL,
  MAX_TCP_INTERVAL,
  type AlertScope,
  type GroupNode,
  type NodeView,
  type SettingsView,
  type TestCatalogItem,
} from "@/lib/admin-types";
import {
  adminActionButtonClass,
  adminDialogCancelClass,
  adminDangerOutlineButtonClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminDirtyBadgeClass,
  adminFieldErrorClass,
  adminHelpTextClass,
  adminInputClass,
  adminNeutralBadgeClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminOutlineButtonClass,
  adminSegmentedItemActiveClass,
  adminSegmentedItemClass,
  adminSegmentedItemInactiveClass,
  adminSegmentedTrackClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

const MAX_TCP_PORT = 65535;

type ProbeType = "icmp" | "tcp";

// O-01：探测目标的下发范围模式（存储形态为 AlertScope——none ⇔ 无 scope，
// groups / nodes 均映射为 mode=include）。
type ProbeScopeMode = "none" | "all" | "groups" | "nodes";

type ProbeFormState = {
  id?: string;
  name: string;
  type: ProbeType;
  host: string;
  port: string;
  intervalSec: string;
  scopeMode: ProbeScopeMode;
  scopeNodes: string[];
  scopeGroups: string[];
  scopeExclude: string[];
};

type ProbeField = "name" | "host" | "port" | "intervalSec" | "scope";

type ProbeValidationResult =
  | {
      item: TestCatalogItem;
    }
  | {
      field: ProbeField;
      error: string;
    };

const probeFieldIDMap: Record<ProbeField, string> = {
  name: "probe-name",
  host: "probe-host",
  port: "probe-port",
  intervalSec: "probe-interval",
  scope: "probe-scope",
};

// O-01：清洗 scope 内的字符串列表（去空格、去空项；顺序保留，与服务端
// normalizeUniqueStrings 的顺序语义一致）。
function cleanScopeList(values?: string[]): string[] {
  return (values || []).map((value) => String(value || "").trim()).filter(Boolean);
}

// O-01：scope 的规范化形态（与服务端 normalizeTestCatalog + normalizeAlertScope
// 后的落盘形态对齐：mode 为 all / include，空列表删除）。
function normalizeProbeScope(scope?: AlertScope): AlertScope | undefined {
  const mode = String(scope?.mode || "").trim();
  if (!scope || (mode !== "all" && mode !== "include")) {
    return undefined;
  }
  const exclude = cleanScopeList(scope.exclude);
  if (mode === "all") {
    return exclude.length > 0 ? { mode: "all", exclude } : { mode: "all" };
  }
  const nodes = cleanScopeList(scope.nodes);
  const groups = cleanScopeList(scope.groups);
  const next: AlertScope = { mode: "include" };
  if (nodes.length > 0) next.nodes = nodes;
  if (groups.length > 0) next.groups = groups;
  if (exclude.length > 0) next.exclude = exclude;
  return next;
}

// O-01：从存储形态推导抽屉的模式（groups 非空优先显示「指定分组」）。
function probeScopeModeOf(scope?: AlertScope): ProbeScopeMode {
  const mode = String(scope?.mode || "").trim();
  if (mode === "all") {
    return "all";
  }
  if (mode === "include") {
    return cleanScopeList(scope?.groups).length > 0 ? "groups" : "nodes";
  }
  return "none";
}

// O-01：抽屉草稿 → 存储形态。none → undefined（不下发）；exclude 在 all 与
// include 两种模式下都原样携带（D-05 语义，避免重存丢失）。
function buildProbeScope(mode: ProbeScopeMode, nodes: string[], groups: string[], exclude: string[]): AlertScope | undefined {
  if (mode === "none") {
    return undefined;
  }
  if (mode === "all") {
    const cleanedExclude = cleanScopeList(exclude);
    return cleanedExclude.length > 0 ? { mode: "all", exclude: cleanedExclude } : { mode: "all" };
  }
  const next: AlertScope = { mode: "include" };
  const cleanedNodes = cleanScopeList(nodes);
  const cleanedGroups = cleanScopeList(groups);
  if (mode === "groups" && cleanedGroups.length > 0) {
    next.groups = cleanedGroups;
  }
  if (mode === "nodes" && cleanedNodes.length > 0) {
    next.nodes = cleanedNodes;
  }
  const cleanedExclude = cleanScopeList(exclude);
  if (cleanedExclude.length > 0) {
    next.exclude = cleanedExclude;
  }
  return next;
}

type ProbeDraft = { uid: string; item: TestCatalogItem };

export interface ProbeSettingsProps {
  testCatalog: TestCatalogItem[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (catalog: TestCatalogItem[]) => Promise<SettingsView>;
}

function resolveProbeType(item?: Partial<TestCatalogItem>): ProbeType {
  const rawType = String(item?.type || "").trim().toLowerCase();
  if (rawType === "tcp") return "tcp";
  if (rawType === "icmp") return "icmp";
  return Number(item?.port || 0) > 0 ? "tcp" : "icmp";
}

function normalizeInterval(value?: number) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return 0;
  }
  return Math.min(Math.trunc(num), MAX_TCP_INTERVAL);
}

function normalizeCatalogItem(item: TestCatalogItem): TestCatalogItem {
  const type = resolveProbeType(item);
  const normalizedBase: TestCatalogItem = {
    id: item.id,
    name: String(item.name || "").trim(),
    type,
    host: String(item.host || "").trim(),
    // F2：icmp 也带 interval_sec（0 表示持续），不再只对 tcp 保留。
    interval_sec: normalizeInterval(item.interval_sec),
  };
  // O-01：scope 参与规范化（与服务端 normalizeTestCatalog 的落盘口径对齐）。
  const scope = normalizeProbeScope(item.scope);
  if (scope) {
    normalizedBase.scope = scope;
  }

  if (type === "icmp") {
    return normalizedBase;
  }

  return {
    ...normalizedBase,
    port: Math.max(0, Math.trunc(Number(item.port) || 0)),
  };
}

function normalizeCatalog(items: TestCatalogItem[]) {
  return (items || []).map(normalizeCatalogItem);
}

function serializeCatalog(items: TestCatalogItem[]) {
  return JSON.stringify(
    normalizeCatalog(items).map((item) => {
      const type = resolveProbeType(item);
      // O-01：scope 入签名（与保存载荷同源——A-03：改范围必须让保存条出现）。
      const scope = normalizeProbeScope(item.scope);
      return {
        id: item.id || "",
        name: item.name,
        type,
        host: item.host,
        port: type === "tcp" ? Number(item.port) || 0 : 0,
        interval_sec: normalizeInterval(item.interval_sec),
        scope: scope
          ? {
              mode: scope.mode,
              nodes: scope.nodes || [],
              groups: scope.groups || [],
              exclude: scope.exclude || [],
            }
          : null,
      };
    }),
  );
}

function toFormState(item?: TestCatalogItem): ProbeFormState {
  const type = resolveProbeType(item);
  return {
    id: item?.id,
    name: item?.name || "",
    type,
    host: item?.host || "",
    port: type === "tcp" && Number(item?.port) > 0 ? String(item?.port) : "",
    intervalSec: normalizeInterval(item?.interval_sec) > 0
      ? String(normalizeInterval(item?.interval_sec))
      : "",
    // O-01：下发范围草稿（exclude 两种模式都保留，重存不丢失——D-05）。
    scopeMode: probeScopeModeOf(item?.scope),
    scopeNodes: cleanScopeList(item?.scope?.nodes),
    scopeGroups: cleanScopeList(item?.scope?.groups),
    scopeExclude: cleanScopeList(item?.scope?.exclude),
  };
}

const STRICT_IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV4_LITERAL_PART_RE = /^(0x[0-9a-f]+|\d+)$/;
const IPV6_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;

function isAmbiguousIPv4LiteralHost(value: string) {
  const trimmed = value.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();
  if (!trimmed || trimmed.includes(":")) {
    return false;
  }
  const parts = trimmed.split(".");
  if (parts.length > 4) {
    return false;
  }
  if (!parts.every((part) => IPV4_LITERAL_PART_RE.test(part))) {
    return false;
  }
  if (parts.length !== 4) {
    return true;
  }
  return parts.some((part) => {
    if (part.startsWith("0x")) {
      return true;
    }
    if (part.length > 1 && part.startsWith("0")) {
      return true;
    }
    return Number(part) > 255 || String(Number(part)) !== part;
  });
}

function isValidIPv6(value: string) {
  if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(":")) {
    return false;
  }

  if (value.includes(":::")) {
    return false;
  }
  let rest = value;
  const v4Tail = value.match(/^(.*:)(\d{1,3}(\.\d{1,3}){3})$/);
  if (v4Tail) {
    if (!STRICT_IPV4_RE.test(v4Tail[2])) {
      return false;
    }
    rest = v4Tail[1];
  }
  const doubleColonCount = rest.split("::").length - 1;
  if (doubleColonCount > 1) {
    return false;
  }

  if (doubleColonCount === 0 && (value.startsWith(":") || value.endsWith(":"))) {
    return false;
  }
  const groups = rest.split(/::?/).filter((group) => group !== "");
  if (!groups.every((group) => IPV6_GROUP_RE.test(group))) {
    return false;
  }

  if (doubleColonCount === 0) {
    return groups.length === (v4Tail ? 6 : 8);
  }
  return groups.length <= (v4Tail ? 5 : 7);
}

function isValidHost(value: string) {
  if (!value || value.includes("://") || value.includes("/") || value.includes(" ")) {
    return false;
  }
  if (isAmbiguousIPv4LiteralHost(value)) {
    return false;
  }
  if (STRICT_IPV4_RE.test(value)) {
    return true;
  }
  if (isValidIPv6(value)) {
    return true;
  }
  if (value.length > 253) return false;
  return value.split(".").every((label) => {
    if (!label || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    return /^[a-zA-Z0-9-]+$/.test(label);
  });
}

function validateProbeForm(formState: ProbeFormState): ProbeValidationResult {
  const name = formState.name.trim();
  const host = formState.host.trim();

  if (!name) {
    return { field: "name", error: "探测节点名称不能为空。" };
  }
  if (/[<>"'`]/.test(name)) {
    return { field: "name", error: "探测节点名称包含非法字符。" };
  }
  if (!host) {
    return { field: "host", error: "探测节点地址不能为空。" };
  }
  if (/[<>"'`]/.test(host) || !isValidHost(host)) {
    return { field: "host", error: "探测节点地址格式不正确。" };
  }

  // F2：ICMP 与 TCP 都可配置间隔，校验逻辑共用；0 = ICMP 持续 / TCP 5 秒。
  const intervalRaw = formState.intervalSec.trim();
  const intervalValue = intervalRaw === "" ? 0 : Number.parseInt(intervalRaw, 10);
  if (
    intervalRaw !== "" &&
    (!Number.isFinite(intervalValue) || intervalValue < 0 || intervalValue > MAX_TCP_INTERVAL)
  ) {
    return {
      field: "intervalSec",
      error: `探测间隔需为 0 - ${MAX_TCP_INTERVAL} 秒。`,
    };
  }

  // O-01：指定分组 / 指定节点时至少选择一项（与规则抽屉「指定范围时至少选择
  // 一个节点或分组。」同语义）。
  if (
    (formState.scopeMode === "groups" && cleanScopeList(formState.scopeGroups).length === 0) ||
    (formState.scopeMode === "nodes" && cleanScopeList(formState.scopeNodes).length === 0)
  ) {
    return { field: "scope", error: "指定范围时至少选择一个节点或分组。" };
  }
  const scope = buildProbeScope(
    formState.scopeMode,
    formState.scopeNodes,
    formState.scopeGroups,
    formState.scopeExclude,
  );

  if (formState.type === "icmp") {
    const item: TestCatalogItem = {
      id: formState.id,
      name,
      type: "icmp",
      host,
      interval_sec: intervalValue > 0 ? intervalValue : 0,
    };
    if (scope) {
      item.scope = scope;
    }
    return { item };
  }

  const port = Number.parseInt(formState.port, 10);
  if (!Number.isFinite(port) || port < 1 || port > MAX_TCP_PORT) {
    return { field: "port", error: `TCP 端口需为 1 - ${MAX_TCP_PORT}。` };
  }

  const item: TestCatalogItem = {
    id: formState.id,
    name,
    type: "tcp",
    host,
    port,
    interval_sec: intervalValue > 0 ? intervalValue : 0,
  };
  if (scope) {
    item.scope = scope;
  }
  return { item };
}

function formatProbeTarget(item: TestCatalogItem) {
  const type = resolveProbeType(item);
  if (type === "tcp" && Number(item.port) > 0) {
    return `${item.host}:${item.port}`;
  }
  return item.host;
}

function formatProbeInterval(item: TestCatalogItem) {
  const interval = normalizeInterval(item.interval_sec);
  if (interval > 0) {
    return `${interval} 秒`;
  }
  // F2：ICMP 0 = 持续；TCP 0 = 5 秒。
  return resolveProbeType(item) === "tcp" ? `${DEFAULT_TCP_INTERVAL} 秒` : "持续";
}

// O-01：「下发」列文案——不下发 → 「—」；全部节点 → 「全部节点」；
// 分组 / 节点 → 「N 个分组」/「N 个节点」（groups 非空优先，与抽屉模式推导一致）。
function formatProbeDelivery(item: TestCatalogItem) {
  const scope = item.scope;
  const mode = String(scope?.mode || "").trim();
  if (mode === "all") {
    return "全部节点";
  }
  if (mode === "include") {
    const groups = cleanScopeList(scope?.groups);
    if (groups.length > 0) {
      return `${groups.length} 个分组`;
    }
    const nodes = cleanScopeList(scope?.nodes);
    if (nodes.length > 0) {
      return `${nodes.length} 个节点`;
    }
  }
  return "—";
}

// 探测目标账本列：地址等宽、间隔数字右对齐；无逐条启停数据，删除
// 动作收进抽屉底栏（与 ServerManagement 的删除位一致）。
const probeTableColumns: ReadonlyArray<AdminDataTableColumn<ProbeDraft>> = [
  {
    key: "name",
    label: "名称",
    render: (draft) => (
      <span className="text-sm font-medium text-[var(--label-1)]">
        {draft.item.name || "未命名探测节点"}
      </span>
    ),
  },
  {
    key: "target",
    label: "目标地址",
    mono: true,
    render: (draft) => (
      <span className="text-[13px] text-[var(--label-1)]">
        {formatProbeTarget(draft.item)}
      </span>
    ),
  },
  {
    key: "type",
    label: "协议",
    render: (draft) => (
      <Badge variant="secondary" className={`${adminNeutralBadgeClass} tracking-wide`}>
        {resolveProbeType(draft.item).toUpperCase()}
      </Badge>
    ),
  },
  {
    key: "delivery",
    label: "下发",
    render: (draft) => (
      <span className="text-[13px] text-[var(--label-2)]">
        {formatProbeDelivery(draft.item)}
      </span>
    ),
  },
  {
    key: "interval",
    label: "间隔",
    width: "20%",
    render: (draft) => (
      <span className="tabular-nums text-[var(--label-2)]">{formatProbeInterval(draft.item)}</span>
    ),
  },
];

export default function ProbeSettings({
  testCatalog,
  onDirtyChange,
  saving = false,
  onSave,
}: ProbeSettingsProps) {
  const normalizedCatalog = useMemo(() => normalizeCatalog(testCatalog), [testCatalog]);
  const normalizedCatalogSignature = useMemo(
    () => serializeCatalog(normalizedCatalog),
    [normalizedCatalog],
  );

  const uidSeqRef = useRef(0);
  const nextProbeUid = () => `probe-draft-${++uidSeqRef.current}`;
  const attachUid = (item: TestCatalogItem): ProbeDraft => ({ uid: nextProbeUid(), item });
  const [drafts, setDrafts] = useState<ProbeDraft[]>(() => normalizedCatalog.map(attachUid));
  const [isSaving, setIsSaving] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [editingUid, setEditingUid] = useState<string | null>(null);
  const [pendingDeleteUid, setPendingDeleteUid] = useState<string | null>(null);
  const [formState, setFormState] = useState<ProbeFormState>(() => toFormState());
  const [formError, setFormError] = useState<{ field: ProbeField; message: string } | null>(null);
  const currentDraftSignature = useMemo(
    () => serializeCatalog(drafts.map((draft) => draft.item)),
    [drafts],
  );
  const isBusy = isSaving || saving;

  const [sourceSignature, absorbSourceSignature, discardDraft] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: normalizedCatalogSignature,
    isBusy,
    resetDraft: () => setDrafts(normalizedCatalog.map(attachUid)),
    warningText: "服务端探测配置已更新，当前未保存修改已保留。",
  });
  // A-03：isDirty 由「草稿签名 ≠ 已吸收的服务端签名」派生——改回原值后保存条自动消失。
  const isDirty = sourceSignature !== currentDraftSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  // 全量替换保存语义下的并发闸门（对齐 ServerManagement 的
  // sourceConflict 模式）：草稿 dirty 期间服务端目录更新过，直接保存会
  // 用旧基线覆盖他人改动——禁保存，要求放弃本地修改或自行调和。
  const lastSeenCatalogSignatureRef = useRef(normalizedCatalogSignature);
  const [sourceConflict, setSourceConflict] = useState(false);
  useEffect(() => {
    if (lastSeenCatalogSignatureRef.current === normalizedCatalogSignature) {
      return;
    }
    lastSeenCatalogSignatureRef.current = normalizedCatalogSignature;
    if (isDirty) {
      setSourceConflict(true);
    }
  }, [isDirty, normalizedCatalogSignature]);

  const discardLocalChanges = () => {
    setDrafts(normalizedCatalog.map(attachUid));
    setSourceConflict(false);
    toast.info("已放弃本地修改，已重置为服务端当前配置。");
  };

  // A-03 / D-07 保存条「放弃修改」：回到服务端当前配置；丢弃后草稿与服务端一致，
  // 冲突闸门（sourceConflict）一并解除，避免「保存已被阻止」徽标残留。
  const discardDraftChanges = () => {
    discardDraft();
    setSourceConflict(false);
  };

  const openDrawer = (draft?: ProbeDraft) => {
    if (isBusy) {
      return;
    }
    setEditingUid(draft ? draft.uid : null);
    setFormState(toFormState(draft?.item));
    setFormError(null);
    setIsDrawerOpen(true);
  };

  // O-01：「下发范围」的节点 / 分组数据。页面未从 App 接收 nodes / groupTree
  //（App.tsx 不在本阶段白名单），抽屉打开时经现有 admin API 自取一份最新值；
  // 拉取失败不阻塞其他字段编辑（多选器显示空态，重开抽屉重试）。
  const [scopeData, setScopeData] = useState<{ nodes: NodeView[]; groupTree: GroupNode[] } | null>(null);
  const [scopeDataLoading, setScopeDataLoading] = useState(false);
  useEffect(() => {
    if (!isDrawerOpen) {
      return;
    }
    let cancelled = false;
    setScopeDataLoading(true);
    void (async () => {
      try {
        const [nodesSnapshot, settingsView] = await Promise.all([fetchNodes(), fetchSettings()]);
        if (!cancelled) {
          setScopeData({
            nodes: nodesSnapshot?.nodes || [],
            groupTree: settingsView?.group_tree || [],
          });
        }
      } catch {
        if (!cancelled) {
          setScopeData(null);
        }
      } finally {
        if (!cancelled) {
          setScopeDataLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isDrawerOpen]);

  const scopeNodeOptions = (scopeData?.nodes || [])
    .map((node) => {
      const id = resolveNodeId(node);
      return { value: id, label: resolveNodeName(node) || id };
    })
    .filter((option) => option.value);
  const scopeGroupOptions = flattenGroupTree(scopeData?.groupTree || []).flatMap((entry) => [
    { value: entry.group, label: entry.group },
    ...entry.tags.map((tag) => ({
      value: `${entry.group}:${tag}`,
      label: `${entry.group} / ${tag}`,
      indent: true,
    })),
  ]);

  const updateScopeListField = (field: "scopeNodes" | "scopeGroups" | "scopeExclude", value: string, checked: boolean) => {
    if (isBusy) {
      return;
    }
    setFormState((current) => ({
      ...current,
      [field]: checked
        ? [...current[field], value]
        : current[field].filter((item) => item !== value),
    }));
    setFormError((current) => (current?.field === "scope" ? null : current));
  };

  const closeDrawer = () => {
    setFormError(null);
    setIsDrawerOpen(false);
    setEditingUid(null);
  };

  // O-01：scope 模式的编辑不走 updateFormField（Select / 多选器有各自的 handler），
  // 泛型收窄到 ProbeFormState 实际持有的字段键。
  const updateFormField = <TField extends Exclude<ProbeField, "scope">>(
    field: TField,
    value: ProbeFormState[TField],
  ) => {
    if (isBusy) {
      return;
    }
    setFormState((current) => ({ ...current, [field]: value }) as ProbeFormState);
    setFormError((current) => (current?.field === field ? null : current));
  };

  const clearPendingDelete = () => {
    setPendingDeleteUid(null);
  };

  const focusProbeField = (field: ProbeField) => {
    const element = document.getElementById(probeFieldIDMap[field]);
    if (element instanceof HTMLElement) {
      element.focus();
    }
  };

  const handleDrawerSave = () => {
    if (isBusy) {
      return;
    }
    const result = validateProbeForm(formState);
    if (!("item" in result)) {
      setFormError({ field: result.field, message: result.error });
      focusProbeField(result.field);
      return;
    }

    if (editingUid !== null && !drafts.some((draft) => draft.uid === editingUid)) {
      // 抽屉打开期间草稿被服务端更新重置：uid 失效，明确提示而非静默错写。
      toast.warning("该条目已被服务端更新重置，请关闭抽屉后重新编辑。");
      return;
    }
    setDrafts((current) => {
      if (editingUid === null) {
        return [...current, { uid: nextProbeUid(), item: result.item }];
      }
      return current.map((draft) =>
        draft.uid === editingUid ? { ...draft, item: result.item } : draft
      );
    });
    closeDrawer();
    toast.success(editingUid === null ? "探测节点已添加" : "探测节点已更新");
  };

  const handleDelete = (uid: string) => {
    if (isBusy) {
      return;
    }
    if (!drafts.some((draft) => draft.uid === uid)) {
      // 确认框打开期间草稿被服务端重置：不置脏、不撒"已移除"的谎。
      toast.warning("该条目已被服务端更新重置。");
      clearPendingDelete();
      return;
    }
    setDrafts((current) => current.filter((draft) => draft.uid !== uid));
    clearPendingDelete();
    toast.success("探测节点已移除");
  };

  const runAction = useAsyncAction();

  const handleSave = () => {
    if (isBusy) {
      return;
    }
    if (sourceConflict) {
      toast.warning("服务端探测配置已更新，请放弃本地修改后重试，以免覆盖他人改动。");
      return;
    }
    const payload = normalizeCatalog(drafts.map((draft) => draft.item));
    void runAction({
      action: () => onSave(payload),
      fallbackError: "保存探测节点配置失败",
      successToast: "探测节点配置已保存",
      onSuccess: (savedSettings) => {
        const canonicalCatalog = normalizeCatalog(savedSettings.test_catalog || payload);
        setDrafts(canonicalCatalog.map(attachUid));
        absorbSourceSignature(serializeCatalog(canonicalCatalog));
        setSourceConflict(false);
      },
      setBusy: setIsSaving,
    });
  };

  const editingDraft = editingUid ? drafts.find((draft) => draft.uid === editingUid) || null : null;

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="探测设置"
        actions={
          <>
            {sourceConflict ? (
              <>
                <span className={adminDirtyBadgeClass}>服务端配置已更新，保存已被阻止</span>
                {/* 0.1.2 裁定：「放弃本地修改」保持页头原位、原逻辑，不搬进浮动保存条。 */}
                <Button
                  variant="outline"
                  className={`${adminActionButtonClass} h-9 flex-1 px-4 font-medium sm:flex-none`}
                  onClick={discardLocalChanges}
                  disabled={isBusy}
                >
                  放弃本地修改
                </Button>
              </>
            ) : null}
            {/* A-12 / 0.1.2：保存入口与「有未保存的修改」徽标移入浮动保存条，页头只留「新增探测节点」。 */}
            <Button
              variant="outline"
              className={`${adminActionButtonClass} h-9 min-w-[140px] flex-1 gap-1.5 px-4 font-medium sm:flex-none`}
              onClick={() => openDrawer()}
              disabled={isBusy}
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              新增探测节点
            </Button>
          </>
        }
      />

      <AdminPanel
        title="目标列表"
        icon={<Radio className="h-4 w-4 text-[var(--label-3)]" />}
      >
        <AdminDataTable
          ariaLabel="探测目标"
          columns={probeTableColumns}
          rows={drafts}
          rowKey={(draft) => draft.uid}
          onRowClick={(draft) => openDrawer(draft)}
          emptyLabel={
            // E-11 / A-16 / 0.1.2：空态用 AdminEmptyState，主按钮复用页头「新增探测节点」
            // 同一个 onClick（openDrawer()），不新增逻辑。
            <AdminEmptyState
              icon={<Radio aria-hidden="true" />}
              title="暂无探测节点"
              description="添加探测目标后，展示页节点详情中将显示到各目标的延迟图表。"
              action={
                <Button
                  className={adminPrimaryButtonClass}
                  onClick={() => openDrawer()}
                  disabled={isBusy}
                >
                  <Plus className="h-4 w-4" aria-hidden="true" />
                  新增探测节点
                </Button>
              }
            />
          }
        />
      </AdminPanel>

      {isDirty ? (
        // A-12：保存入口移入浮动保存条；handleSave 的冲突闸门与禁用条件
        // （!isDirty 由渲染条件覆盖）复用原有逻辑，只改呈现位置。
        // A-03：左侧「放弃修改」带二次确认（D-07），确认后回到服务端当前配置。
        <AdminSaveBar
          saving={isSaving || saving}
          disabled={isBusy || sourceConflict}
          onSave={handleSave}
          onDiscard={discardDraftChanges}
        />
      ) : null}

      <AdminDrawer
        open={isDrawerOpen}
        onOpenChange={(open) => {
          if (!open) {
            closeDrawer();
          }
        }}
        title={editingUid === null ? "新增探测节点" : "编辑探测节点"}
        description={
          editingDraft
            ? `${resolveProbeType(editingDraft.item).toUpperCase()} · ${formatProbeTarget(
                editingDraft.item,
              )}`
            : "配置探测目标的基础信息与协议参数。"
        }
        footer={
          <div className="flex flex-wrap items-center justify-between gap-2">
            {editingUid !== null ? (
              <AlertDialog
                open={pendingDeleteUid !== null}
                onOpenChange={(open) => {
                  if (!open) {
                    clearPendingDelete();
                  } else if (editingUid !== null) {
                    // 受控打开：Trigger 只会回调 onOpenChange(true)，必须在这里落入
                    // pendingDeleteUid，否则确认框永远打不开（迁移回归）。
                    setPendingDeleteUid(editingUid);
                  }
                }}
              >
                <AlertDialogTrigger
                  render={(
                    <Button
                      type="button"
                      variant="destructive"
                      className={cn(adminDangerOutlineButtonClass, "min-w-[92px] gap-1.5 px-4")}
                      disabled={isBusy}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                      删除
                    </Button>
                  )}
                />
                <AlertDialogContent className={adminDialogContentClass}>
                  <AlertDialogHeader className={adminDialogHeaderClass}>
                    <AlertDialogTitle>确认删除探测节点？</AlertDialogTitle>
                  </AlertDialogHeader>
                  <AlertDialogFooter className={adminDialogFooterClass}>
                    <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                    <AlertDialogAction
                      className={adminDialogDangerActionClass}
                      disabled={isBusy}
                      onClick={() => {
                        if (pendingDeleteUid !== null) {
                          handleDelete(pendingDeleteUid);
                        }
                        clearPendingDelete();
                        closeDrawer();
                      }}
                    >
                      确认删除
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            ) : (
              <span />
            )}
            <div className="ml-auto flex gap-2">
              <Button
                type="button"
                variant="outline"
                className={cn(adminOutlineButtonClass, "min-w-[84px] px-4")}
                onClick={closeDrawer}
                disabled={isBusy}
              >
                取消
              </Button>
              <Button
                type="button"
                className={cn(adminPrimaryButtonClass, "min-w-[110px] px-4")}
                onClick={handleDrawerSave}
                disabled={isBusy}
              >
                {editingUid === null ? "新增探测节点" : "保存探测节点"}
              </Button>
            </div>
          </div>
        }
      >
        <section>
          <h3 className="text-sm font-semibold text-[var(--label-1)]">基础信息</h3>
          <AdminKVField label="名称" htmlFor="probe-name">
            <div className="space-y-1.5">
              <Input
                id="probe-name"
                name="probe-name"
                autoComplete="off"
                className={`${adminInputClass} w-full`}
                aria-invalid={formError?.field === "name"}
                aria-describedby={formError?.field === "name" ? "probe-name-error" : undefined}
                value={formState.name}
                disabled={isBusy}
                onChange={(event) => updateFormField("name", event.target.value)}
                placeholder="例如：主站 TCP 443…"
              />
              {formError?.field === "name" ? (
                <p id="probe-name-error" className={adminFieldErrorClass} aria-live="polite">
                  {formError.message}
                </p>
              ) : null}
            </div>
          </AdminKVField>
          <AdminKVField label="类型">
            <div className={adminSegmentedTrackClass}>
              {(["icmp", "tcp"] as const).map((type) => {
                const active = formState.type === type;
                return (
                  <Button
                    key={type}
                    type="button"
                    variant={null}
                    aria-pressed={active}
                    className={cn(
                      adminSegmentedItemClass,
                      "outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] disabled:opacity-50",
                      active
                        ? adminSegmentedItemActiveClass
                        : adminSegmentedItemInactiveClass,
                    )}
                    onClick={() => {
                      if (isBusy) {
                        return;
                      }
                      setFormState((current) => ({
                        ...current,
                        type,
                        port: type === "tcp" ? current.port : "",
                      }));
                    }}
                    disabled={isBusy}
                  >
                    {type.toUpperCase()}
                  </Button>
                );
              })}
            </div>
          </AdminKVField>
        </section>

        <section>
          <h3 className="text-sm font-semibold text-[var(--label-1)]">目标地址</h3>
          <AdminKVField label="地址" htmlFor="probe-host">
            <div className="space-y-1.5">
              <Input
                id="probe-host"
                name="probe-host"
                autoComplete="off"
                spellCheck={false}
                className={`${adminInputClass} data-text w-full`}
                aria-invalid={formError?.field === "host"}
                aria-describedby={formError?.field === "host" ? "probe-host-error" : undefined}
                value={formState.host}
                disabled={isBusy}
                onChange={(event) => updateFormField("host", event.target.value)}
                placeholder="例如：1.1.1.1 / example.com…"
              />
              {formError?.field === "host" ? (
                <p id="probe-host-error" className={adminFieldErrorClass} aria-live="polite">
                  {formError.message}
                </p>
              ) : null}
            </div>
          </AdminKVField>
        </section>

        <section>
          <h3 className="text-sm font-semibold text-[var(--label-1)]">
            {formState.type === "tcp" ? "TCP 参数" : "ICMP 参数"}
          </h3>
          {formState.type === "tcp" ? (
            <AdminKVField label="端口" htmlFor="probe-port">
              <div className="space-y-1.5">
                <Input
                  id="probe-port"
                  name="probe-port"
                  type="number"
                  min={1}
                  max={MAX_TCP_PORT}
                  autoComplete="off"
                  inputMode="numeric"
                  className={`${adminInputClass} data-text w-full`}
                  aria-invalid={formError?.field === "port"}
                  aria-describedby={formError?.field === "port" ? "probe-port-error" : undefined}
                  value={formState.port}
                  disabled={isBusy}
                  onChange={(event) => updateFormField("port", event.target.value)}
                  placeholder="例如：443…"
                />
                {formError?.field === "port" ? (
                  <p id="probe-port-error" className={adminFieldErrorClass} aria-live="polite">
                    {formError.message}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
          ) : null}
          <AdminKVField label="探测间隔（秒）" htmlFor="probe-interval">
            <div className="space-y-1.5">
              <Input
                id="probe-interval"
                name="probe-interval"
                type="number"
                min={0}
                max={MAX_TCP_INTERVAL}
                autoComplete="off"
                inputMode="numeric"
                className={`${adminInputClass} tabular-nums w-full`}
                aria-invalid={formError?.field === "intervalSec"}
                aria-describedby={
                  formError?.field === "intervalSec" ? "probe-interval-error" : undefined
                }
                value={formState.intervalSec}
                disabled={isBusy}
                onChange={(event) => updateFormField("intervalSec", event.target.value)}
                placeholder={formState.type === "icmp" ? "持续" : String(DEFAULT_TCP_INTERVAL)}
              />
              <p className={adminHelpTextClass}>
                {formState.type === "icmp"
                  ? "留空或填 0 为持续探测。"
                  : `留空或填 0 为每 ${DEFAULT_TCP_INTERVAL} 秒。`}
              </p>
              {formError?.field === "intervalSec" ? (
                <p id="probe-interval-error" className={adminFieldErrorClass} aria-live="polite">
                  {formError.message}
                </p>
              ) : null}
            </div>
          </AdminKVField>
        </section>

        {/* O-01：下发范围（复用共享规则抽屉的范围选择组件 RuleMultiSelect）。 */}
        <section>
          <h3 className="text-sm font-semibold text-[var(--label-1)]">下发范围</h3>
          <AdminKVField label="范围" htmlFor="probe-scope">
            <div className="space-y-1.5">
              <Select
                value={formState.scopeMode}
                onValueChange={(next) => {
                  if (isBusy || !next) {
                    return;
                  }
                  const mode: ProbeScopeMode =
                    next === "all" || next === "groups" || next === "nodes" ? next : "none";
                  setFormState((current) => ({ ...current, scopeMode: mode }));
                  setFormError((current) => (current?.field === "scope" ? null : current));
                }}
              >
                <SelectTrigger
                  id="probe-scope"
                  size="sm"
                  disabled={isBusy}
                  className={`${adminSelectTriggerClass} w-full`}
                  aria-invalid={formError?.field === "scope"}
                  aria-describedby={formError?.field === "scope" ? "probe-scope-error" : undefined}
                >
                  <SelectValue>
                    {formState.scopeMode === "all"
                      ? "全部节点"
                      : formState.scopeMode === "groups"
                        ? "指定分组"
                        : formState.scopeMode === "nodes"
                          ? "指定节点"
                          : "不下发"}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent className={adminSelectContentClass}>
                  <SelectItem value="none">不下发</SelectItem>
                  <SelectItem value="all">全部节点</SelectItem>
                  <SelectItem value="groups">指定分组</SelectItem>
                  <SelectItem value="nodes">指定节点</SelectItem>
                </SelectContent>
              </Select>
              {scopeDataLoading ? (
                <p className={adminHelpTextClass}>正在加载数据…</p>
              ) : null}
              {formError?.field === "scope" ? (
                <p id="probe-scope-error" className={adminFieldErrorClass} aria-live="polite">
                  {formError.message}
                </p>
              ) : null}
            </div>
          </AdminKVField>
          {formState.scopeMode === "groups" ? (
            <AdminKVField label="指定分组" htmlFor="probe-scope-groups">
              <RuleMultiSelect
                id="probe-scope-groups"
                summary={`已选 ${formState.scopeGroups.length} 项`}
                emptyText={scopeGroupOptions.length === 0 ? "暂无分组" : "未选择"}
                options={scopeGroupOptions}
                selected={formState.scopeGroups}
                disabled={isBusy || scopeDataLoading}
                onToggle={(value, checked) => updateScopeListField("scopeGroups", value, checked)}
              />
            </AdminKVField>
          ) : null}
          {formState.scopeMode === "nodes" ? (
            <AdminKVField label="指定节点" htmlFor="probe-scope-nodes">
              <RuleMultiSelect
                id="probe-scope-nodes"
                summary={`已选 ${formState.scopeNodes.length} 个节点`}
                emptyText={scopeNodeOptions.length === 0 ? "暂无节点" : "未选择"}
                options={scopeNodeOptions}
                selected={formState.scopeNodes}
                disabled={isBusy || scopeDataLoading}
                onToggle={(value, checked) => updateScopeListField("scopeNodes", value, checked)}
              />
            </AdminKVField>
          ) : null}
          {formState.scopeMode === "all" ? (
            <AdminKVField label="排除节点" htmlFor="probe-scope-exclude">
              <RuleMultiSelect
                id="probe-scope-exclude"
                summary={`已选 ${formState.scopeExclude.length} 个节点`}
                emptyText={scopeNodeOptions.length === 0 ? "暂无节点" : "未选择"}
                options={scopeNodeOptions}
                selected={formState.scopeExclude}
                disabled={isBusy || scopeDataLoading}
                onToggle={(value, checked) => updateScopeListField("scopeExclude", value, checked)}
              />
            </AdminKVField>
          ) : null}
        </section>
      </AdminDrawer>
    </div>
  );
}
