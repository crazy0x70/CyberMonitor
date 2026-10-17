import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminKVField } from "@/components/admin-kv-field";
import {
  AdminGroupedCard,
  AdminGroupedFieldRow,
  AdminSectionPanel,
} from "@/components/admin-section-panel";
import { AdminSaveBar } from "@/components/admin-save-bar";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminEmptyState } from "@/components/admin-empty-state";
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
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Bot,
  CheckCircle2,
  HelpCircle,
  Layers3,
  Loader2,
  Plus,
  Trash2,
  XCircle,
} from "lucide-react";
import {
  draftSignature,
  useAsyncAction,
  useDirtyNotification,
  useDraftReconcile,
} from "@/lib/admin-hooks";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  adminActionButtonClass,
  adminCompactActionButtonClass,
  adminDangerOutlineButtonClass,
  adminInputClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminNarrowPageShellClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
  adminSuccessBadgeClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminTextareaClass,
  adminWarningBadgeClass,
} from "@/lib/admin-ui";
import type { AIProviderConfig, SettingsUpdate, SettingsView } from "@/lib/admin-types";

export interface AIProviderProps {
  settings: SettingsView | null;
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (payload: SettingsUpdate) => Promise<SettingsView>;
  onTestProvider: (provider: string, config: AIProviderConfig | null) => Promise<void>;
  onFetchModels: (provider: string, config: AIProviderConfig | null) => Promise<string[]>;
}

type ProviderStatus = "unconfigured" | "unverified" | "verified";

type ProviderDraft = {
  id: string;
  name: string;
  provider: "openai" | "openai_compatible";
  apiKey: string;
  baseURL: string;
  model: string;
  allowPrivateBaseURL: boolean;
  models: string[];
  status: ProviderStatus;
  keyConfigured: boolean;
};

function resolveStatus(config: AIProviderConfig | undefined) {

  if (!config?.api_key_set) return "unconfigured" as const;
  return "unverified" as const;
}

function providerLabel(provider: string, fallback = "") {
  if (provider === "openai") return "OpenAI";
  if (provider.startsWith("openai_compatible")) return fallback || "OpenAI 兼容";
  return provider;
}

function makeProviderDrafts(settings: SettingsView | null): ProviderDraft[] {
  const ai = settings?.ai_settings || {};
  const compatibles = Array.isArray(ai.openai_compatibles) ? ai.openai_compatibles : [];

  const drafts: ProviderDraft[] = [
    {
      id: "openai",
      name: "OpenAI",
      provider: "openai",
      apiKey: ai.openai?.api_key || "",
      baseURL: ai.openai?.base_url || "",
      model: ai.openai?.model || "",
      allowPrivateBaseURL: Boolean(ai.openai?.allow_private_base_url),
      models: [],
      status: resolveStatus(ai.openai),
      keyConfigured: Boolean(ai.openai?.api_key_set),
    },
  ];

  compatibles.forEach((item, index) => {
    drafts.push({
      id: item.id || `compatible-${index}`,
      name: item.name || `兼容服务商 ${index + 1}`,
      provider: "openai_compatible",
      apiKey: item.api_key || "",
      baseURL: item.base_url || "",
      model: item.model || "",
      allowPrivateBaseURL: Boolean(item.allow_private_base_url),
      models: [],
      status: resolveStatus(item),
      keyConfigured: Boolean(item.api_key_set),
    });
  });

  return drafts;
}

type ProviderFormState = {
  name: string;
  apiKey: string;
  baseURL: string;
  model: string;
  allowPrivateBaseURL: boolean;
};

function toConfig(item: ProviderDraft): AIProviderConfig {
  return {
    api_key: item.apiKey.trim(),
    base_url: item.baseURL.trim(),
    model: item.model.trim(),
    allow_private_base_url: item.allowPrivateBaseURL,
  };
}

function toTestConfig(item: ProviderDraft): AIProviderConfig | null {
  if (!item.apiKey.trim() && item.keyConfigured) {
    return null;
  }
  return toConfig(item);
}

function toProviderValue(item: ProviderDraft) {
  return item.provider === "openai_compatible" ? `openai_compatible:${item.id}` : item.provider;
}

function resolveProviderSelection(options: Array<{ value: string }>, currentValue: string) {
  if (options.some((item) => item.value === currentValue)) {
    return currentValue;
  }
  return options[0]?.value || "openai";
}

type AISettingsDraft = {
  providers: ProviderDraft[];
  commandProvider: string;
  prompt: string;
};

function makeAISettingsDraft(settings: SettingsView | null): AISettingsDraft {
  const providers = makeProviderDrafts(settings);
  const commandProvider = resolveProviderSelection(
    providers.map((item) => ({ value: toProviderValue(item) })),
    settings?.ai_settings?.command_provider || "openai",
  );
  return {
    providers,
    commandProvider,
    prompt: settings?.ai_settings?.prompt || "",
  };
}

function projectAISettingsDraft(draft: AISettingsDraft) {
  return {
    commandProvider: draft.commandProvider,
    prompt: draft.prompt,
    providers: draft.providers.map((item) => ({
      id: item.id,
      name: item.name,
      provider: item.provider,
      apiKey: item.apiKey,
      baseURL: item.baseURL,
      model: item.model,
      allowPrivateBaseURL: item.allowPrivateBaseURL,
    })),
  };
}

function renderStatusBadge(status: ProviderStatus) {
  switch (status) {
    case "verified":
      return (
        <Badge variant="secondary" className={adminSuccessBadgeClass}>
          <CheckCircle2 aria-hidden="true" className="h-3 w-3" /> 已验证可用
        </Badge>
      );
    case "unverified":
      return (
        <Badge variant="secondary" className={adminWarningBadgeClass}>
          <HelpCircle aria-hidden="true" className="h-3 w-3" /> 已配置未验证
        </Badge>
      );
    default:
      return (
        <Badge variant="secondary" className={adminNeutralBadgeClass}>
          <XCircle aria-hidden="true" className="h-3 w-3" /> 未配置
        </Badge>
      );
  }
}

// E-01 / A-07 第 1 条：页头图标方块（F6 后运维助手为无分区单页）。
// 第 4 节图标表：运维助手 → Bot · 靛。
const PAGE_ICON_META: { icon: ReactNode; background: string } = {
  icon: <Bot className="h-5 w-5" />,
  background: "bg-linear-to-br from-[#7f8cff] to-[#5b57f0]",
};

const providerTableColumns: ReadonlyArray<AdminDataTableColumn<ProviderDraft>> = [
  {
    key: "name",
    label: "名称",
    render: (item) => (
      <span className="text-sm font-medium text-[var(--label-1)]">{item.name}</span>
    ),
  },
  {
    key: "endpoint",
    label: "端点",
    mono: true,
    render: (item) => (
      <span
        className={cn(
          "block max-w-[18rem] truncate text-[var(--label-2)] lg:max-w-[28rem]",
          !item.baseURL && "font-sans text-[var(--label-3)]",
        )}
        title={item.baseURL || "未设置 Base URL"}
      >
        {item.baseURL || "未设置 Base URL"}
      </span>
    ),
  },
  {
    key: "model",
    label: "模型",
    mono: true,
    render: (item) => item.model || "--",
  },
  {
    key: "status",
    label: "状态",
    render: (item) => renderStatusBadge(item.status),
  },
];

export default function AIProvider({
  settings,
  onDirtyChange,
  saving: externalSaving = false,
  onSave,
  onTestProvider,
  onFetchModels,
}: AIProviderProps) {
  const [providers, setProviders] = useState<ProviderDraft[]>(() => makeAISettingsDraft(settings).providers);
  const [commandProvider, setCommandProvider] = useState(() => makeAISettingsDraft(settings).commandProvider);
  const [prompt, setPrompt] = useState(() => makeAISettingsDraft(settings).prompt);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [fetchingModelsId, setFetchingModelsId] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [providerForm, setProviderForm] = useState({
    name: "",
    apiKey: "",
    baseURL: "",
    model: "",
    allowPrivateBaseURL: false,
  });
  const isBusy = isSaving || externalSaving || testingId !== null || fetchingModelsId !== null;
  // settings 尚未加载成功时草稿为空，保存会整份覆盖 ai_settings；settings===null 一律禁止保存。
  const settingsLoaded = settings !== null;

  const currentDraftSignature = useMemo(
    () => draftSignature(projectAISettingsDraft({ providers, commandProvider, prompt })),
    [commandProvider, prompt, providers],
  );

  // A-03：接收 useDraftReconcile 第三个返回值 discard（保存条「放弃修改」），
  // 其余签名化脏检测逻辑不动。
  const [sourceSignature, absorbSourceSignature, discard] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: draftSignature(projectAISettingsDraft(makeAISettingsDraft(settings))),
    isBusy,
    resetDraft: () => {
      const draft = makeAISettingsDraft(settings);
      setProviders(draft.providers);
      setCommandProvider(draft.commandProvider);
      setPrompt(draft.prompt);
    },
    warningText: "服务端 AI 配置已更新，当前未保存修改已保留。",
  });

  const isDirty = currentDraftSignature !== sourceSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  const savedCompatibleIDs = useMemo(
    () => new Set((settings?.ai_settings?.openai_compatibles || []).map((item) => item.id)),
    [settings],
  );

  const toProviderRequestKey = (item: ProviderDraft) => {
    if (item.provider !== "openai_compatible") {
      return item.provider;
    }
    return savedCompatibleIDs.has(item.id) ? `openai_compatible:${item.id}` : "openai_compatible";
  };

  const endpointEditNeedsSave = (item: ProviderDraft) => {
    if (!item.keyConfigured || item.apiKey.trim()) {
      return false;
    }
    const source =
      item.provider === "openai"
        ? settings?.ai_settings?.openai
        : settings?.ai_settings?.openai_compatibles?.find((entry) => entry.id === item.id);
    if (!source) {
      return false;
    }
    return (
      item.baseURL.trim() !== (source.base_url || "").trim() ||
      item.model.trim() !== (source.model || "").trim()
    );
  };

  const providerOptions = useMemo(() => {
    return providers.map((item) => ({
      value: toProviderValue(item),
      label: providerLabel(item.provider, item.name),

      configured: Boolean(item.apiKey) || item.keyConfigured,
      status: item.status,
    }));
  }, [providers]);

  useEffect(() => {
    if (isBusy) {
      return;
    }
    const nextCommand = resolveProviderSelection(providerOptions, commandProvider);
    if (nextCommand !== commandProvider) {

      setCommandProvider(nextCommand);
    }
  }, [commandProvider, isBusy, providerOptions]);

  const setProviderDrafts = (updater: (current: ProviderDraft[]) => ProviderDraft[]) => {
    setProviders(updater);
  };

  const openProviderDialog = (item: ProviderDraft) => {
    if (isBusy) {
      return;
    }
    dialogSessionRef.current += 1;
    setEditingId(item.id);
    setVerifiedSnapshot(null);
    setVerifiedScope(null);
    setProviderForm({
      name: item.name,
      apiKey: item.apiKey,
      baseURL: item.baseURL,
      model: item.model,
      allowPrivateBaseURL: item.allowPrivateBaseURL,
    });
    setIsDialogOpen(true);
  };

  const closeProviderDialog = () => {
    dialogSessionRef.current += 1;
    setIsDialogOpen(false);
    setEditingId(null);
    setVerifiedSnapshot(null);
    setVerifiedScope(null);
  };

  const updateProviderFormField = (field: keyof ProviderFormState, value: string) => {
    if (isBusy) {
      return;
    }
    setProviderForm((current) => ({ ...current, [field]: value }));

    setVerifiedSnapshot(null);
    setVerifiedScope(null);
  };

  const updateProviderAllowPrivateForm = (value: boolean) => {
    if (isBusy) {
      return;
    }
    setProviderForm((current) => ({ ...current, allowPrivateBaseURL: value }));

    setVerifiedSnapshot(null);
    setVerifiedScope(null);
  };

  const applyProviderForm = () => {
    if (isBusy || editingId === null) {
      return;
    }
    updateProviderInput(editingId, "name", providerForm.name);
    updateProviderInput(editingId, "apiKey", providerForm.apiKey);
    updateProviderInput(editingId, "baseURL", providerForm.baseURL);
    updateProviderInput(editingId, "model", providerForm.model);
    updateProviderAllowPrivate(editingId, providerForm.allowPrivateBaseURL);
    if (verifiedSnapshot && verifiedScope === editingId) {
      const earned = { ...providerForm };
      const matchesSnapshot =
        earned.name === verifiedSnapshot.name &&
        earned.apiKey === verifiedSnapshot.apiKey &&
        earned.baseURL === verifiedSnapshot.baseURL &&
        earned.model === verifiedSnapshot.model &&
        earned.allowPrivateBaseURL === verifiedSnapshot.allowPrivateBaseURL;
      if (matchesSnapshot) {
        updateProviderDraft(editingId, (current) => ({ ...current, status: "verified" }));
      }
    }
    closeProviderDialog();
  };

  const updateProviderDraft = (
    id: string,
    updater: (current: ProviderDraft) => ProviderDraft,
  ) => {
    setProviderDrafts((current) => current.map((item) => (item.id === id ? updater(item) : item)));
  };

  const updateProviderInput = (
    id: string,
    field: "name" | "apiKey" | "baseURL" | "model",
    value: string,
  ) => {
    if (isBusy) {
      return;
    }
    updateProviderDraft(id, (current) => {
      if (field === "name") {
        return { ...current, name: value };
      }
      if (field === "apiKey") {
        return {
          ...current,
          apiKey: value,

          status: value ? "unverified" : current.keyConfigured ? current.status : "unconfigured",
        };
      }

      const configured = Boolean(current.apiKey.trim()) || current.keyConfigured;
      const next = {
        ...current,
        status: configured ? "unverified" : current.status,
      };
      return field === "baseURL"
        ? { ...next, baseURL: value }
        : { ...next, model: value };
    });
  };

  const updateProviderAllowPrivate = (id: string, value: boolean) => {
    if (isBusy) {
      return;
    }
    updateProviderDraft(id, (current) => ({ ...current, allowPrivateBaseURL: value }));
  };

  const addCompatible = () => {
    if (isBusy) {
      return;
    }
    const id = `compatible-${Date.now()}`;
    setProviderDrafts(
      (current) => [
        ...current,
        {
          id,
          name: "新兼容服务商",
          provider: "openai_compatible",
          apiKey: "",
          baseURL: "",
          model: "",
          allowPrivateBaseURL: false,
          models: [],
          keyConfigured: false,
          status: "unconfigured",
        },
      ]
    );
  };

  const removeCompatible = (id: string) => {
    if (isBusy) {
      return;
    }
    const removingSelectedProvider = commandProvider === `openai_compatible:${id}`;

    const nextDrafts = providers.filter((item) => item.id !== id);
    if (removingSelectedProvider) {
      setCommandProvider(
        resolveProviderSelection(nextDrafts.map((item) => ({ value: toProviderValue(item) })), ""),
      );
    }
    setProviderDrafts(() => nextDrafts);
  };

  const runAction = useAsyncAction();

  const [verifiedSnapshot, setVerifiedSnapshot] = useState<ProviderFormState | null>(null);
  const [verifiedScope, setVerifiedScope] = useState<string | null>(null);
  const dialogSessionRef = useRef(0);

  const handleTest = (item: ProviderDraft) => {
    if (isBusy) {
      return;
    }
    if (endpointEditNeedsSave(item)) {
      toast.warning("端点或模型有未保存修改，请先保存后再测试。");
      return;
    }
    const session = dialogSessionRef.current;
    void runAction({
      action: () => onTestProvider(toProviderRequestKey(item), toTestConfig(item)),
      fallbackError: "验证失败",
      successToast: `${item.name} 验证成功`,
      onSuccess: () => {
        if (session !== dialogSessionRef.current) {
          return;
        }
        setVerifiedSnapshot({
          name: item.name,
          apiKey: item.apiKey,
          baseURL: item.baseURL,
          model: item.model,
          allowPrivateBaseURL: item.allowPrivateBaseURL,
        });
        setVerifiedScope(item.id);
      },
      setBusy: (on) => setTestingId(on ? item.id : null),
    });
  };

  const handleFetchModels = (item: ProviderDraft) => {
    if (isBusy) {
      return;
    }
    if (endpointEditNeedsSave(item)) {
      toast.warning("端点或模型有未保存修改，请先保存后再获取模型。");
      return;
    }
    void runAction({
      action: () => onFetchModels(toProviderRequestKey(item), toTestConfig(item)),
      fallbackError: "获取模型列表失败",
      successToast: `${item.name} 模型列表已刷新`,
      onSuccess: (models) => {

        updateProviderDraft(item.id, (current) => ({ ...current, models }));
        const shouldFillModel = models.length > 0 && !item.model;
        if (shouldFillModel) {
          setProviderForm((current) => ({ ...current, model: models[0] }));
        }
      },
      setBusy: (on) => setFetchingModelsId(on ? item.id : null),
    });
  };

  const editingItem = providers.find((item) => item.id === editingId) ?? null;
  const formItem: ProviderDraft | null = editingItem
    ? { ...editingItem, name: providerForm.name, apiKey: providerForm.apiKey, baseURL: providerForm.baseURL, model: providerForm.model, allowPrivateBaseURL: providerForm.allowPrivateBaseURL }
    : null;

  // A-07：指令服务商下拉显式渲染当前选中项的中文标签（原 <SelectValue /> 不传
  // children 时 Base UI 直接渲染原始 value，如 openai / openai_compatible:…）。
  const selectedCommandProvider = providerOptions.find((item) => item.value === commandProvider);
  const selectedCommandProviderLabel = selectedCommandProvider
    ? `${selectedCommandProvider.label}${selectedCommandProvider.configured ? "" : "（未配置）"}`
    : "选择命令服务商…";

  const handleSave = () => {
    if (isBusy || !settingsLoaded) {
      return;
    }
    const openai = providers.find((item) => item.provider === "openai");
    const compatibles = providers.filter((item) => item.provider === "openai_compatible");
    void runAction({
      action: () =>
        onSave({
          ai_settings: {
            command_provider: commandProvider,
            prompt,
            openai: openai ? toConfig(openai) : {},
            openai_compatibles: compatibles.map((item) => ({
              id: item.id,
              name: item.name.trim(),
              ...toConfig(item),
            })),
          },
        }),
      fallbackError: "保存 AI 配置失败",
      successToast: "运维助手配置已保存",
      onSuccess: (savedSettings) => {
        const canonicalDraft = makeAISettingsDraft(savedSettings);
        setProviders(canonicalDraft.providers);
        setCommandProvider(canonicalDraft.commandProvider);
        setPrompt(canonicalDraft.prompt);
        absorbSourceSignature(draftSignature(projectAISettingsDraft(canonicalDraft)));
      },
      setBusy: setIsSaving,
    });
  };

  return (
    // E-03：设置页窄版外壳（页头、表单、表格同宽 880px）；A-12：保存入口移入浮动保存条，
    // isDirty 为假时页头不显示保存按钮（0.1.2）。F6：无分区单页，依次渲染
    // 「助手设置」「服务商」两张分组卡片，顶部不再放统计卡。
    <div className={adminNarrowPageShellClass}>
      <AdminPageHeader
        icon={PAGE_ICON_META.icon}
        iconClassName={PAGE_ICON_META.background}
        title="运维助手"
        description="通过 Telegram /ai 命令，用自然语言查询节点状态。"
      />

      <div className="space-y-8">
        <AdminSectionPanel label="助手设置">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="指令服务商" htmlFor="ai-command-provider">
              <Select
                value={commandProvider}
                disabled={isBusy}
                onValueChange={(value) => {
                  if (isBusy || value === null) {
                    return;
                  }
                  setCommandProvider(value);
                }}
              >
                <SelectTrigger
                  id="ai-command-provider"
                  size="sm"
                  className={`w-full sm:w-56 ${adminSelectTriggerClass}`}
                >
                  <SelectValue placeholder="选择命令服务商…">{selectedCommandProviderLabel}</SelectValue>
                </SelectTrigger>
                <SelectContent className={adminSelectContentClass}>
                  {providerOptions.map((item) => (
                    <SelectItem key={`command-${item.value}`} value={item.value}>
                      {item.label}{item.configured ? "" : "（未配置）"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="运维提示词" htmlFor="ai-prompt">
              <Textarea
                id="ai-prompt"
                className={`min-h-24 max-h-40 resize-y supports-[field-sizing:content]:resize-none ${adminTextareaClass}`}
                value={prompt}
                onChange={(event) => {
                  if (isBusy) {
                    return;
                  }
                  setPrompt(event.target.value);
                }}
                disabled={isBusy}
                placeholder="例如：请重点关注网络流量、下载量与离线情况…"
              />
            </AdminGroupedFieldRow>
          </AdminGroupedCard>
        </AdminSectionPanel>

        <AdminSectionPanel
          label="服务商"
          actions={
            <Button
              variant="outline"
              className={adminCompactActionButtonClass}
              onClick={addCompatible}
              disabled={isBusy}
            >
              <Plus className="h-3.5 w-3.5" />
              新增兼容服务商
            </Button>
          }
        >
          <AdminDataTable
            ariaLabel="服务商列表"
            columns={providerTableColumns}
            rows={providers}
            rowKey={(item) => item.id}
            onRowClick={(item) => openProviderDialog(item)}
            emptyLabel={
              // A-16 / 0.1.2：空态用 AdminEmptyState，按钮复用页头「新增兼容服务商」
              // 同一个 onClick（addCompatible），不新增逻辑。
              <AdminEmptyState
                icon={<Layers3 aria-hidden="true" />}
                title="还没有服务商"
                description="新增一个 OpenAI 兼容服务商后，可在对话指令中调用它分析节点状态。"
                action={
                  <Button className={adminPrimaryButtonClass} onClick={addCompatible} disabled={isBusy}>
                    <Plus className="h-4 w-4" />
                    新增兼容服务商
                  </Button>
                }
              />
            }
          />
        </AdminSectionPanel>
      </div>

      {isDirty ? (
        // A-12：保存入口移入浮动保存条；handleSave 与禁用条件复用原有逻辑，只改呈现位置。
        // A-03：左侧「放弃修改」带二次确认（D-07），确认后回到服务端当前配置。
        <AdminSaveBar
          saving={isSaving || externalSaving}
          disabled={isBusy || !settingsLoaded}
          onSave={handleSave}
          onDiscard={discard}
        />
      ) : null}

      <AdminDrawer
        open={isDialogOpen && editingItem !== null}
        onOpenChange={(open) => {
          if (!open) {
            closeProviderDialog();
          }
        }}
        title={
          editingItem ? (
            <span className="flex flex-wrap items-center gap-2">
              {providerForm.name || editingItem.name}
              {renderStatusBadge(
                verifiedSnapshot &&
                  providerForm.name === verifiedSnapshot.name &&
                  providerForm.apiKey === verifiedSnapshot.apiKey &&
                  providerForm.baseURL === verifiedSnapshot.baseURL &&
                  providerForm.model === verifiedSnapshot.model &&
                  providerForm.allowPrivateBaseURL === verifiedSnapshot.allowPrivateBaseURL
                  ? "verified"
                  : editingItem.status,
              )}
            </span>
          ) : (
            "编辑服务商"
          )
        }
        description={
          editingItem
            ? `服务商类型：${providerLabel(editingItem.provider, editingItem.name)}`
            : undefined
        }
        footer={
          editingItem ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              {editingItem.provider === "openai_compatible" ? (
                <Button
                  variant="outline"
                  className={`${adminDangerOutlineButtonClass} h-9 min-w-[92px] px-4`}
                  onClick={() => {
                    removeCompatible(editingItem.id);
                    closeProviderDialog();
                  }}
                  disabled={isBusy}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  删除
                </Button>
              ) : (
                <span />
              )}
              <div className="ml-auto flex gap-2">
                <Button
                  variant="outline"
                  className={`${adminOutlineButtonClass} h-9 min-w-[84px] px-4`}
                  onClick={closeProviderDialog}
                  disabled={isBusy}
                >
                  取消
                </Button>
                <Button
                  className={`${adminPrimaryButtonClass} h-9 min-w-[84px] px-4`}
                  onClick={applyProviderForm}
                  disabled={isBusy}
                >
                  完成
                </Button>
              </div>
            </div>
          ) : null
        }
      >
        {editingItem && formItem ? (
          <>
            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                基础信息
              </h3>
              <AdminKVField label="显示名称" htmlFor="provider-display-name">
                <Input
                  id="provider-display-name"
                  className={adminInputClass}
                  autoComplete="off"
                  value={providerForm.name}
                  disabled={isBusy}
                  onChange={(event) => updateProviderFormField("name", event.target.value)}
                />
              </AdminKVField>
              <AdminKVField label="API Key" htmlFor="provider-api-key">
                <Input
                  id="provider-api-key"
                  className={`${adminInputClass} data-text`}
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  value={providerForm.apiKey}
                  disabled={isBusy}
                  onChange={(event) => updateProviderFormField("apiKey", event.target.value)}
                  placeholder={editingItem.keyConfigured ? "已配置（留空保持不变）" : "sk-…"}
                />
              </AdminKVField>
            </section>

            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                接入参数
              </h3>
              <AdminKVField label="Base URL" htmlFor="provider-base-url">
                <Input
                  id="provider-base-url"
                  className={adminInputClass}
                  type="url"
                  autoComplete="off"
                  inputMode="url"
                  spellCheck={false}
                  value={providerForm.baseURL}
                  disabled={isBusy}
                  onChange={(event) => updateProviderFormField("baseURL", event.target.value)}
                />
              </AdminKVField>
              <AdminKVField label="内网地址" htmlFor="provider-allow-private">
                <div className="flex flex-col gap-1.5">
                  <div className="flex min-h-9 items-center gap-2.5">
                    <Switch
                      id="provider-allow-private"
                      checked={providerForm.allowPrivateBaseURL}
                      disabled={isBusy}
                      onCheckedChange={updateProviderAllowPrivateForm}
                    />
                    <span className="text-sm text-[var(--label-1)]">
                      允许访问内网 / 环回地址
                    </span>
                  </div>
                  <p className={`text-xs leading-relaxed ${adminMutedTextClass}`}>
                    默认禁止指向私网、环回、链路本地等地址，以防借 API Key 探测内网。自建内网 LLM
                    网关（如 10.x 上的 vLLM / ollama）需显式开启。
                  </p>
                </div>
              </AdminKVField>
              <AdminKVField label="模型" htmlFor="provider-model">
                <div className="space-y-1.5">
                  <Input
                    id="provider-model"
                    className={`${adminInputClass} data-text`}
                    list="provider-models"
                    autoComplete="off"
                    spellCheck={false}
                    value={providerForm.model}
                    disabled={isBusy}
                    onChange={(event) => updateProviderFormField("model", event.target.value)}
                  />
                  <datalist id="provider-models">
                    {editingItem.models.map((model) => (
                      <option key={model} value={model} />
                    ))}
                  </datalist>
                  <p className={`text-xs leading-relaxed ${adminMutedTextClass}`}>
                    {editingItem.models.length > 0
                      ? `已缓存 ${editingItem.models.length} 个模型候选`
                      : "尚未获取模型列表"}
                  </p>
                </div>
              </AdminKVField>
            </section>

            <section>
              <h3 className="text-sm font-semibold text-[var(--label-1)]">
                连接验证
              </h3>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  className={adminActionButtonClass}
                  onClick={() => handleFetchModels(formItem)}
                  disabled={isBusy}
                >
                  {fetchingModelsId === editingItem.id ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      获取中…
                    </>
                  ) : (
                    "获取模型列表"
                  )}
                </Button>
                <Button
                  variant="outline"
                  className={adminActionButtonClass}
                  onClick={() => handleTest(formItem)}
                  disabled={isBusy}
                >
                  {testingId === editingItem.id ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      验证中…
                    </>
                  ) : (
                    "测试连接"
                  )}
                </Button>
              </div>
              <p className={`text-xs leading-relaxed ${adminMutedTextClass}`}>
                验证与获取模型使用当前抽屉内的端点与密钥；端点改动需先完成并保存后再验证存储密钥。
              </p>
            </section>
          </>
        ) : null}
      </AdminDrawer>
    </div>
  );
}
