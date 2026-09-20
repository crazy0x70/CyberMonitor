import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Edit2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { DEFAULT_TCP_INTERVAL, MAX_TCP_INTERVAL, type SettingsView, type TestCatalogItem } from "@/lib/admin-types";
import { getErrorMessage } from "@/lib/admin-format";
import {
  adminActionButtonClass,
  adminAccentBadgeClass,
  adminDialogCancelClass,
  adminDangerIconButtonClass,
  adminDialogContentClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminEmptyStateClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminNeutralBadgeClass,
  adminOutlineButtonClass,
  adminWorkspaceHeaderClass,
  adminWorkspaceItemClass,
  adminWorkspaceListClass,
  adminWorkspaceMetaCardClass,
  adminWorkspaceMetaGridClass,
  adminWorkspaceMetaLabelClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

const MAX_TCP_PORT = 65535;

type ProbeType = "icmp" | "tcp";

type ProbeFormState = {
  id?: string;
  name: string;
  type: ProbeType;
  host: string;
  port: string;
  intervalSec: string;
};

type ProbeField = "name" | "host" | "port" | "intervalSec";

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
};

// 草稿条目的本地行身份：弹窗打开期间若服务端目录更新触发草稿重置，
// 下标会指向错位条目，稳定 uid 保证编辑/删除永远命中原行。计数器放
// 组件 useRef（随实例存活）：模块级计数器在 HMR 重求值后会归零并与
// 保留的 hooks 状态撞号。
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
  };

  if (type === "icmp") {
    return normalizedBase;
  }

  return {
    ...normalizedBase,
    port: Math.max(0, Math.trunc(Number(item.port) || 0)),
    interval_sec: normalizeInterval(item.interval_sec),
  };
}

function normalizeCatalog(items: TestCatalogItem[]) {
  return (items || []).map(normalizeCatalogItem);
}

function serializeCatalog(items: TestCatalogItem[]) {
  return JSON.stringify(
    normalizeCatalog(items).map((item) => {
      const type = resolveProbeType(item);
      return {
        id: item.id || "",
        name: item.name,
        type,
        host: item.host,
        port: type === "tcp" ? Number(item.port) || 0 : 0,
        interval_sec: type === "tcp" ? normalizeInterval(item.interval_sec) : 0,
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
    intervalSec:
      type === "tcp" && normalizeInterval(item?.interval_sec) > 0
        ? String(normalizeInterval(item?.interval_sec))
        : "",
  };
}

// 与后端 persist.go isValidTestHost 对称：歧义 IPv4 字面量（缩写段/
// 前导零/hex 段）与非法 IP 一律弹窗字段级拒绝，避免拖到整页保存被
// 后端整体 400 且不定位条目。
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
  // ::: （三连冒号）对 net.ParseIP 非法，但省略号计数会漏掉它。
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
  // 孤立前导/尾随单冒号（":1:2:..."）非合法 IPv6，filter 空段后组数
  // 会碰巧凑满，需显式拒绝（:: 场景 doubleColonCount>=1 不受影响）。
  if (doubleColonCount === 0 && (value.startsWith(":") || value.endsWith(":"))) {
    return false;
  }
  const groups = rest.split(/::?/).filter((group) => group !== "");
  if (!groups.every((group) => IPV6_GROUP_RE.test(group))) {
    return false;
  }
  // net.ParseIP 对齐：无 :: 必须满组（8 组；v4 尾段占 2 组故 6 组 hex），
  // 有 :: 可省 1..7 组（v4 尾段时 hex 上限 5）。
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

  if (formState.type === "icmp") {
    return {
      item: {
        id: formState.id,
        name,
        type: "icmp",
        host,
      } satisfies TestCatalogItem,
    };
  }

  const port = Number.parseInt(formState.port, 10);
  if (!Number.isFinite(port) || port < 1 || port > MAX_TCP_PORT) {
    return { field: "port", error: `TCP 端口需为 1 - ${MAX_TCP_PORT}。` };
  }

  const intervalRaw = formState.intervalSec.trim();
  const intervalValue = intervalRaw === "" ? 0 : Number.parseInt(intervalRaw, 10);
  if (
    intervalRaw !== "" &&
    (!Number.isFinite(intervalValue) || intervalValue < 0 || intervalValue > MAX_TCP_INTERVAL)
  ) {
    return {
      field: "intervalSec",
      error: `TCP 默认间隔需为 0 - ${MAX_TCP_INTERVAL} 秒，留空或 0 表示默认 ${DEFAULT_TCP_INTERVAL} 秒。`,
    };
  }

  return {
    item: {
      id: formState.id,
      name,
      type: "tcp",
      host,
      port,
      interval_sec: intervalValue > 0 ? intervalValue : 0,
    } satisfies TestCatalogItem,
  };
}

function formatProbeTarget(item: TestCatalogItem) {
  const type = resolveProbeType(item);
  if (type === "tcp" && Number(item.port) > 0) {
    return `${item.host}:${item.port}`;
  }
  return item.host;
}

function formatProbeInterval(item: TestCatalogItem) {
  if (resolveProbeType(item) !== "tcp") {
    return "固定";
  }
  const interval = normalizeInterval(item.interval_sec);
  return interval > 0 ? `${interval} 秒` : `默认 ${DEFAULT_TCP_INTERVAL} 秒`;
}

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
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingUid, setEditingUid] = useState<string | null>(null);
  const [pendingDeleteUid, setPendingDeleteUid] = useState<string | null>(null);
  const [formState, setFormState] = useState<ProbeFormState>(() => toFormState());
  const [formError, setFormError] = useState<{ field: ProbeField; message: string } | null>(null);
  const draftSignature = useMemo(
    () => serializeCatalog(drafts.map((draft) => draft.item)),
    [drafts],
  );
  const isBusy = isSaving || saving;

  const [, absorbSourceSignature] = useDraftReconcile({
    draftSignature,
    nextSourceSignature: normalizedCatalogSignature,
    isBusy,
    resetDraft: () => setDrafts(normalizedCatalog.map(attachUid)),
    warningText: "服务端探测配置已更新，当前未保存修改已保留。",
    onCleaned: () => setIsDirty(false),
  });
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
    setIsDirty(false);
    setSourceConflict(false);
    toast.info("已放弃本地修改，已重置为服务端当前配置。");
  };

  const openDialog = (draft?: ProbeDraft) => {
    if (isBusy) {
      return;
    }
    setEditingUid(draft ? draft.uid : null);
    setFormState(toFormState(draft?.item));
    setFormError(null);
    setIsDialogOpen(true);
  };

  const closeDialog = () => {
    setFormError(null);
    setIsDialogOpen(false);
  };

  const openCreateDialog = () => {
    openDialog();
  };

  const openEditDialog = (draft: ProbeDraft) => {
    openDialog(draft);
  };

  const updateFormField = <TField extends ProbeField>(
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

  const handleDialogSave = () => {
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
      // 弹窗打开期间草稿被服务端更新重置：uid 失效，明确提示而非静默错写。
      toast.warning("该条目已被服务端更新重置，请关闭弹窗后重新编辑。");
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
    setIsDirty(true);
    closeDialog();
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
    setIsDirty(true);
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
        setIsDirty(false);
        setSourceConflict(false);
      },
      setBusy: setIsSaving,
    });
  };

  

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div className="space-y-2">
          <h1 className={adminPageTitleClass}>探测设置</h1>
        </div>
        <div className={cn(adminPageActionsClass, "flex-col gap-2 sm:flex-row sm:items-center")}>
          {sourceConflict ? (
            <>
              <span className={adminDirtyBadgeClass}>服务端配置已更新，保存已被阻止</span>
              <Button
                variant="outline"
                className={`${adminActionButtonClass} h-11 px-5 font-bold`}
                onClick={discardLocalChanges}
                disabled={isBusy}
              >
                放弃本地修改
              </Button>
            </>
          ) : null}
          {isDirty && !sourceConflict ? (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          ) : null}
          <Button
            variant="outline"
            className={`${adminActionButtonClass} h-11 min-w-[140px] px-5 font-bold`}
            onClick={openCreateDialog}
            disabled={isBusy}
          >
            <Plus className="mr-2 h-4 w-4" />
            新增探测节点
          </Button>
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            onClick={handleSave}
            disabled={!isDirty || isBusy || sourceConflict}
          >
            {isBusy ? "保存中…" : "保存更改"}
          </Button>
        </div>
      </div>

      <div className={adminWorkspaceListClass}>
        {drafts.length === 0 ? (
          <div className={cn(adminEmptyStateClass, "space-y-4")}>
            <p className="text-lg font-semibold text-slate-900 dark:text-slate-100">暂无探测节点</p>
            <Button className={adminPrimaryButtonClass} onClick={openCreateDialog}>
              <Plus className="mr-2 h-4 w-4" />
              新增探测节点
            </Button>
          </div>
        ) : null}

        {drafts.map((draft) => {
          const item = draft.item;
          const type = resolveProbeType(item);
          return (
            <div
              key={draft.uid}
              className={adminWorkspaceItemClass}
            >
              <div className={adminWorkspaceHeaderClass}>
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-base font-semibold text-slate-900 dark:text-slate-50">
                      {item.name || "未命名探测节点"}
                    </span>
                    <Badge
                      variant="secondary"
                      className={
                        type === "icmp"
                          ? adminNeutralBadgeClass
                          : adminAccentBadgeClass
                      }
                    >
                      {type.toUpperCase()}
                    </Badge>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="icon"
                    className={cn(adminActionButtonClass, "h-9 w-9 px-0")}
                    aria-label={`编辑探测节点 ${item.name || formatProbeTarget(item)}`}
                    disabled={isBusy}
                    onClick={() => openEditDialog(draft)}
                  >
                    <Edit2 className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className={adminDangerIconButtonClass}
                    aria-label={`删除探测节点 ${item.name || formatProbeTarget(item)}`}
                    disabled={isBusy}
                    onClick={() => setPendingDeleteUid(draft.uid)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className={cn(adminWorkspaceMetaGridClass, "md:grid-cols-3 xl:grid-cols-3")}>
                <div className={adminWorkspaceMetaCardClass}>
                  <div className={adminWorkspaceMetaLabelClass}>目标</div>
                  <div className="mt-1 font-mono text-sm text-slate-700 dark:text-slate-200">
                    {formatProbeTarget(item)}
                  </div>
                </div>
                <div className={adminWorkspaceMetaCardClass}>
                  <div className={adminWorkspaceMetaLabelClass}>协议</div>
                  <div className="mt-1 font-medium">{type.toUpperCase()}</div>
                </div>
                <div className={adminWorkspaceMetaCardClass}>
                  <div className={adminWorkspaceMetaLabelClass}>间隔</div>
                  <div className="mt-1 font-medium">{formatProbeInterval(item)}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <Dialog
        open={isDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            closeDialog();
          }
        }}
      >
        <DialogContent className={`sm:max-w-[620px] ${adminDialogContentClass}`}>
          <DialogHeader className={adminDialogHeaderClass}>
            <DialogTitle className="dark:text-slate-50">
              {editingUid === null ? "新增探测节点" : "编辑探测节点"}
            </DialogTitle>
          </DialogHeader>

          <div className="grid gap-4 px-6 py-6">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="probe-name">名称</Label>
                <Input
                  id="probe-name"
                  name="probe-name"
                  autoComplete="off"
                  className={adminInputClass}
                  aria-invalid={formError?.field === "name"}
                  aria-describedby={formError?.field === "name" ? "probe-name-error" : undefined}
                  value={formState.name}
                  disabled={isBusy}
                  onChange={(event) => updateFormField("name", event.target.value)}
                  placeholder="例如：主站 TCP 443…"
                />
                {formError?.field === "name" ? (
                  <p id="probe-name-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                    {formError.message}
                  </p>
                ) : null}
              </div>

              <div className="grid gap-2">
                <Label>类型</Label>
                <div className="grid grid-cols-2 gap-3 rounded-[1.25rem] border border-slate-200 bg-slate-50 p-2 dark:border-slate-800 dark:bg-slate-950">
                  {(["icmp", "tcp"] as const).map((type) => {
                    const active = formState.type === type;
                    return (
                      <Button
                        key={type}
                        type="button"
                        variant="outline"
                        className={
                          active
                            ? `${adminPrimaryButtonClass} h-11 w-full min-w-0 px-4`
                            : `${adminActionButtonClass} h-11 w-full min-w-0 px-4`
                        }
                        onClick={() => {
                          if (isBusy) {
                            return;
                          }
                          setFormState((current) => ({
                            ...current,
                            type,
                            port: type === "tcp" ? current.port : "",
                            intervalSec: type === "tcp" ? current.intervalSec : "",
                          }));
                        }}
                        disabled={isBusy}
                      >
                        {type.toUpperCase()}
                      </Button>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="probe-host">目标地址</Label>
              <Input
                id="probe-host"
                name="probe-host"
                autoComplete="off"
                spellCheck={false}
                className={adminInputClass}
                aria-invalid={formError?.field === "host"}
                aria-describedby={formError?.field === "host" ? "probe-host-error" : undefined}
                value={formState.host}
                disabled={isBusy}
                onChange={(event) => updateFormField("host", event.target.value)}
                placeholder="例如：1.1.1.1 / example.com…"
              />
              {formError?.field === "host" ? (
                <p id="probe-host-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                  {formError.message}
                </p>
              ) : null}
            </div>

            {formState.type === "tcp" ? (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="grid gap-2">
                  <Label htmlFor="probe-port">端口</Label>
                  <Input
                    id="probe-port"
                    name="probe-port"
                    type="number"
                    min={1}
                    max={MAX_TCP_PORT}
                    autoComplete="off"
                    inputMode="numeric"
                    className={adminInputClass}
                    aria-invalid={formError?.field === "port"}
                    aria-describedby={formError?.field === "port" ? "probe-port-error" : undefined}
                    value={formState.port}
                    disabled={isBusy}
                    onChange={(event) => updateFormField("port", event.target.value)}
                    placeholder="例如：443…"
                  />
                  {formError?.field === "port" ? (
                    <p id="probe-port-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                      {formError.message}
                    </p>
                  ) : null}
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="probe-interval">默认间隔（秒）</Label>
                  <Input
                    id="probe-interval"
                    name="probe-interval"
                    type="number"
                    min={0}
                    max={MAX_TCP_INTERVAL}
                    autoComplete="off"
                    inputMode="numeric"
                    className={adminInputClass}
                    aria-invalid={formError?.field === "intervalSec"}
                    aria-describedby={formError?.field === "intervalSec" ? "probe-interval-error" : undefined}
                    value={formState.intervalSec}
                    disabled={isBusy}
                    onChange={(event) => updateFormField("intervalSec", event.target.value)}
                    placeholder={`例如：${DEFAULT_TCP_INTERVAL}…`}
                  />
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {`留空或填写 0 时，将沿用默认间隔 ${DEFAULT_TCP_INTERVAL} 秒。`}
                  </p>
                  {formError?.field === "intervalSec" ? (
                    <p id="probe-interval-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                      {formError.message}
                    </p>
                  ) : null}
                </div>
              </div>
            ) : null}
          </div>

          <DialogFooter className={`${adminDialogFooterClass} px-8 py-6`}>
            <Button
              variant="outline"
              className={`${adminOutlineButtonClass} h-12 px-8 font-bold`}
              onClick={closeDialog}
              disabled={isBusy}
            >
              取消
            </Button>
            <Button
              className={`${adminPrimaryButtonClass} h-12 px-8 font-bold`}
              onClick={handleDialogSave}
              disabled={isBusy}
            >
              {editingUid === null ? "新增探测节点" : "保存探测节点"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={pendingDeleteUid !== null}
        onOpenChange={(open) => {
          if (!open) {
            clearPendingDelete();
          }
        }}
      >
        <AlertDialogContent className={adminDialogContentClass}>
          <AlertDialogHeader className={adminDialogHeaderClass}>
            <AlertDialogTitle>确认删除探测节点？</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter className={adminDialogFooterClass}>
            <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
            <AlertDialogAction
              className={adminPrimaryButtonClass}
              disabled={isBusy}
              onClick={() => {
                if (pendingDeleteUid !== null) {
                  handleDelete(pendingDeleteUid);
                }
                clearPendingDelete();
              }}
            >
              确认删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
