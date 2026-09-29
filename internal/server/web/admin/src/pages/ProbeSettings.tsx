import { useEffect, useMemo, useRef, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Radio, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { DEFAULT_TCP_INTERVAL, MAX_TCP_INTERVAL, type SettingsView, type TestCatalogItem } from "@/lib/admin-types";
import {
  adminActionButtonClass,
  adminDialogCancelClass,
  adminDangerOutlineButtonClass,
  adminDialogContentClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminPageActionsClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminOutlineButtonClass,
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

// 探测目标账本列：地址等宽、间隔数字右对齐；无逐条启停数据，删除
// 动作收进抽屉底栏（与 ServerManagement 的删除位一致）。
const probeTableColumns: ReadonlyArray<AdminDataTableColumn<ProbeDraft>> = [
  {
    key: "name",
    label: "名称",
    render: (draft) => (
      <span className="text-sm font-medium text-slate-900 dark:text-neutral-50">
        {draft.item.name || "未命名探测节点"}
      </span>
    ),
  },
  {
    key: "target",
    label: "目标地址",
    mono: true,
    render: (draft) => (
      <span className="text-slate-700 dark:text-neutral-200">
        {formatProbeTarget(draft.item)}
      </span>
    ),
  },
  {
    key: "type",
    label: "协议",
    mono: true,
    render: (draft) => resolveProbeType(draft.item).toUpperCase(),
  },
  {
    key: "interval",
    label: "间隔",
    mono: true,
    width: "20%",
    render: (draft) => formatProbeInterval(draft.item),
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
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
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

  const openDrawer = (draft?: ProbeDraft) => {
    if (isBusy) {
      return;
    }
    setEditingUid(draft ? draft.uid : null);
    setFormState(toFormState(draft?.item));
    setFormError(null);
    setIsDrawerOpen(true);
  };

  const closeDrawer = () => {
    setFormError(null);
    setIsDrawerOpen(false);
    setEditingUid(null);
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
    setIsDirty(true);
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

  const editingDraft = editingUid ? drafts.find((draft) => draft.uid === editingUid) || null : null;

  const metricItems = [
    { label: "接入目标", value: drafts.length },
  ] as const;

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="探测设置"
        actionsClassName={cn(adminPageActionsClass, "flex-col gap-2 sm:flex-row sm:items-center")}
        actions={
          <>
            {sourceConflict ? (
              <>
                <span className={adminDirtyBadgeClass}>服务端配置已更新，保存已被阻止</span>
                <Button
                  variant="outline"
                  className={`${adminActionButtonClass} h-9 px-4 font-medium`}
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
              className={`${adminActionButtonClass} h-9 min-w-[140px] px-4 font-medium`}
              onClick={() => openDrawer()}
              disabled={isBusy}
            >
              <Plus className="mr-2 h-4 w-4" />
              新增探测节点
            </Button>
            <Button
              className={`${adminPrimaryButtonClass} h-9 px-4 font-medium`}
              onClick={handleSave}
              disabled={!isDirty || isBusy || sourceConflict}
            >
              {isBusy ? "保存中…" : "保存更改"}
            </Button>
          </>
        }
      />

      <AdminMetricStrip ariaLabel="探测统计" items={metricItems} />

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
          emptyLabel="暂无探测节点，点击右上角「新增探测节点」开始。"
        />
      </AdminPanel>

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
          <div className="flex items-center justify-between gap-2">
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
                      className={cn(adminDangerOutlineButtonClass, "h-9 min-w-[92px] px-4")}
                      disabled={isBusy}
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
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
                      className={adminPrimaryButtonClass}
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
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                className={cn(adminOutlineButtonClass, "h-9 min-w-[84px] px-4")}
                onClick={closeDrawer}
                disabled={isBusy}
              >
                取消
              </Button>
              <Button
                type="button"
                className={cn(adminPrimaryButtonClass, "h-9 min-w-[110px] px-4")}
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
          <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">基础信息</h3>
          <AdminKVField label="名称" htmlFor="probe-name">
            <div className="space-y-2">
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
          </AdminKVField>
          <AdminKVField label="类型">
            <div className="grid grid-cols-2 gap-2">
              {(["icmp", "tcp"] as const).map((type) => {
                const active = formState.type === type;
                return (
                  <Button
                    key={type}
                    type="button"
                    variant="outline"
                    className={
                      active
                        ? `${adminPrimaryButtonClass} h-9 w-full min-w-0 px-4`
                        : `${adminOutlineButtonClass} h-9 w-full min-w-0 px-4`
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
          </AdminKVField>
        </section>

        <section>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">目标地址</h3>
          <AdminKVField label="地址" htmlFor="probe-host">
            <div className="space-y-2">
              <Input
                id="probe-host"
                name="probe-host"
                autoComplete="off"
                spellCheck={false}
                className={`${adminInputClass} data-text`}
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
          </AdminKVField>
        </section>

        {formState.type === "tcp" ? (
          <section>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
              TCP 参数
            </h3>
            <AdminKVField label="端口" htmlFor="probe-port">
              <div className="space-y-2">
                <Input
                  id="probe-port"
                  name="probe-port"
                  type="number"
                  min={1}
                  max={MAX_TCP_PORT}
                  autoComplete="off"
                  inputMode="numeric"
                  className={`${adminInputClass} data-text`}
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
            </AdminKVField>
            <AdminKVField label="默认间隔（秒）" htmlFor="probe-interval">
              <div className="space-y-2">
                <Input
                  id="probe-interval"
                  name="probe-interval"
                  type="number"
                  min={0}
                  max={MAX_TCP_INTERVAL}
                  autoComplete="off"
                  inputMode="numeric"
                  className={`${adminInputClass} data-text`}
                  aria-invalid={formError?.field === "intervalSec"}
                  aria-describedby={
                    formError?.field === "intervalSec" ? "probe-interval-error" : undefined
                  }
                  value={formState.intervalSec}
                  disabled={isBusy}
                  onChange={(event) => updateFormField("intervalSec", event.target.value)}
                  placeholder={`例如：${DEFAULT_TCP_INTERVAL}…`}
                />
                <p className="text-xs text-slate-500 dark:text-neutral-400">
                  {`留空或填写 0 时，将沿用默认间隔 ${DEFAULT_TCP_INTERVAL} 秒。`}
                </p>
                {formError?.field === "intervalSec" ? (
                  <p id="probe-interval-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                    {formError.message}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
          </section>
        ) : null}
      </AdminDrawer>
    </div>
  );
}
