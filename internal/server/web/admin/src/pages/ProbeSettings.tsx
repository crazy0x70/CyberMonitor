import { useEffect, useMemo, useState } from "react";
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
import type { TestCatalogItem } from "@/lib/admin-types";
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

const DEFAULT_TCP_INTERVAL = 5;
const MAX_TCP_INTERVAL = 3600;
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

export interface ProbeSettingsProps {
  testCatalog: TestCatalogItem[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (catalog: TestCatalogItem[]) => Promise<unknown>;
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

function isValidHost(value: string) {
  if (!value || value.includes("://") || value.includes("/") || value.includes(" ")) {
    return false;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split(".").every((part) => {
      const num = Number(part);
      return num >= 0 && num <= 255;
    });
  }
  if (/^[0-9a-fA-F:]+$/.test(value) && value.includes(":")) {
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

  const [drafts, setDrafts] = useState<TestCatalogItem[]>(normalizedCatalog);
  const [sourceSignature, setSourceSignature] = useState(normalizedCatalogSignature);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [pendingDeleteIndex, setPendingDeleteIndex] = useState<number | null>(null);
  const [formState, setFormState] = useState<ProbeFormState>(() => toFormState());
  const [formError, setFormError] = useState<{ field: ProbeField; message: string } | null>(null);

  useEffect(() => {
    if (normalizedCatalogSignature === sourceSignature) {
      return;
    }
    setDrafts(normalizedCatalog);
    setSourceSignature(normalizedCatalogSignature);
    setIsDirty(false);
  }, [normalizedCatalog, normalizedCatalogSignature, sourceSignature]);

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

  const openCreateDialog = () => {
    setEditingIndex(null);
    setFormState(toFormState());
    setFormError(null);
    setIsDialogOpen(true);
  };

  const openEditDialog = (item: TestCatalogItem, index: number) => {
    setEditingIndex(index);
    setFormState(toFormState(item));
    setFormError(null);
    setIsDialogOpen(true);
  };

  const focusProbeField = (field: ProbeField) => {
    const element = document.getElementById(probeFieldIDMap[field]);
    if (element instanceof HTMLElement) {
      element.focus();
    }
  };

  const handleDialogSave = () => {
    const result = validateProbeForm(formState);
    if (!("item" in result)) {
      setFormError({ field: result.field, message: result.error });
      focusProbeField(result.field);
      return;
    }

    setDrafts((current) => {
      if (editingIndex === null) {
        return [...current, result.item];
      }
      return current.map((item, index) => (index === editingIndex ? result.item : item));
    });
    setIsDirty(true);
    setIsDialogOpen(false);
    setFormError(null);
    toast.success(editingIndex === null ? "探测节点已添加" : "探测节点已更新");
  };

  const handleDelete = (index: number) => {
    setDrafts((current) => current.filter((_, currentIndex) => currentIndex !== index));
    setIsDirty(true);
    toast.success("探测节点已移除");
  };

  const handleSave = async () => {
    const payload = normalizeCatalog(drafts);

    setIsSaving(true);
    try {
      await onSave(payload);
      setSourceSignature(serializeCatalog(payload));
      setIsDirty(false);
      toast.success("探测节点配置已保存");
    } catch (error) {
      toast.error(getErrorMessage(error, "保存探测节点配置失败"));
    } finally {
      setIsSaving(false);
    }
  };

  const submitting = isSaving || saving;

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div className="space-y-2">
          <h1 className={adminPageTitleClass}>探测设置</h1>
        </div>
        <div className={cn(adminPageActionsClass, "flex-col gap-2 sm:flex-row sm:items-center")}>
          {isDirty ? (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          ) : null}
          <Button
            variant="outline"
            className={`${adminActionButtonClass} h-11 min-w-[140px] px-5 font-bold`}
            onClick={openCreateDialog}
          >
            <Plus className="mr-2 h-4 w-4" />
            新增探测节点
          </Button>
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            onClick={handleSave}
            disabled={!isDirty || submitting}
          >
            {submitting ? "保存中…" : "保存更改"}
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

        {drafts.map((item, index) => {
          const type = resolveProbeType(item);
          return (
            <div
              key={item.id || `probe-${index}`}
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
                    onClick={() => openEditDialog(item, index)}
                  >
                    <Edit2 className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className={adminDangerIconButtonClass}
                    aria-label={`删除探测节点 ${item.name || formatProbeTarget(item)}`}
                    onClick={() => setPendingDeleteIndex(index)}
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
          setIsDialogOpen(open);
          if (!open) {
            setFormError(null);
          }
        }}
      >
        <DialogContent className={`sm:max-w-[620px] ${adminDialogContentClass}`}>
          <DialogHeader className={adminDialogHeaderClass}>
            <DialogTitle className="dark:text-slate-50">
              {editingIndex === null ? "新增探测节点" : "编辑探测节点"}
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
                  onChange={(event) => {
                    setFormState((current) => ({ ...current, name: event.target.value }));
                    if (formError?.field === "name") {
                      setFormError(null);
                    }
                  }}
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
                        onClick={() =>
                          setFormState((current) => ({
                            ...current,
                            type,
                            port: type === "tcp" ? current.port : "",
                            intervalSec: type === "tcp" ? current.intervalSec : "",
                          }))
                        }
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
                onChange={(event) => {
                  setFormState((current) => ({ ...current, host: event.target.value }));
                  if (formError?.field === "host") {
                    setFormError(null);
                  }
                }}
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
                    onChange={(event) => {
                      setFormState((current) => ({ ...current, port: event.target.value }));
                      if (formError?.field === "port") {
                        setFormError(null);
                      }
                    }}
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
                    onChange={(event) => {
                      setFormState((current) => ({ ...current, intervalSec: event.target.value }));
                      if (formError?.field === "intervalSec") {
                        setFormError(null);
                      }
                    }}
                    placeholder={`例如：${DEFAULT_TCP_INTERVAL}…`}
                  />
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    留空或填写 `0` 时，将沿用默认间隔 {DEFAULT_TCP_INTERVAL} 秒。
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
              onClick={() => setIsDialogOpen(false)}
            >
              取消
            </Button>
            <Button
              className={`${adminPrimaryButtonClass} h-12 px-8 font-bold`}
              onClick={handleDialogSave}
            >
              {editingIndex === null ? "新增探测节点" : "保存探测节点"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={pendingDeleteIndex !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPendingDeleteIndex(null);
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
              onClick={() => {
                if (pendingDeleteIndex !== null) {
                  handleDelete(pendingDeleteIndex);
                }
                setPendingDeleteIndex(null);
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
