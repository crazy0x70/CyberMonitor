import { useEffect, useMemo, useRef, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
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
import {
  adminActionButtonClass,
  adminCompactActionButtonClass,
  adminDangerOutlineButtonClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminOutlineButtonClass,
  adminPageShellClass,
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
};

function toConfig(item: ProviderDraft): AIProviderConfig {
  return {
    api_key: item.apiKey.trim(),
    base_url: item.baseURL.trim(),
    model: item.model.trim(),
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
    })),
  };
}

function renderStatusBadge(status: ProviderStatus) {
  switch (status) {
    case "verified":
      return (
        <Badge variant="secondary" className={adminSuccessBadgeClass}>
          <CheckCircle2 className="mr-1 h-3 w-3" /> 已验证可用
        </Badge>
      );
    case "unverified":
      return (
        <Badge variant="secondary" className={adminWarningBadgeClass}>
          <HelpCircle className="mr-1 h-3 w-3" /> 已配置未验证
        </Badge>
      );
    default:
      return (
        <Badge variant="secondary" className={adminNeutralBadgeClass}>
          <XCircle className="mr-1 h-3 w-3" /> 未配置
        </Badge>
      );
  }
}

const providerTableColumns: ReadonlyArray<AdminDataTableColumn<ProviderDraft>> = [
  {
    key: "name",
    label: "名称",
    render: (item) => (
      <span className="text-sm font-medium text-slate-900 dark:text-neutral-50">{item.name}</span>
    ),
  },
  {
    key: "endpoint",
    label: "端点",
    mono: true,
    render: (item) => (
      <span
        className="block w-full truncate text-slate-600 dark:text-neutral-300"
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
  });
  const isBusy = isSaving || externalSaving || testingId !== null || fetchingModelsId !== null;

  const currentDraftSignature = useMemo(
    () => draftSignature(projectAISettingsDraft({ providers, commandProvider, prompt })),
    [commandProvider, prompt, providers],
  );

  const [sourceSignature, absorbSourceSignature] = useDraftReconcile({
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

  const applyProviderForm = () => {
    if (isBusy || editingId === null) {
      return;
    }
    updateProviderInput(editingId, "name", providerForm.name);
    updateProviderInput(editingId, "apiKey", providerForm.apiKey);
    updateProviderInput(editingId, "baseURL", providerForm.baseURL);
    updateProviderInput(editingId, "model", providerForm.model);
    if (verifiedSnapshot && verifiedScope === editingId) {
      const earned = { ...providerForm };
      const matchesSnapshot =
        earned.name === verifiedSnapshot.name &&
        earned.apiKey === verifiedSnapshot.apiKey &&
        earned.baseURL === verifiedSnapshot.baseURL &&
        earned.model === verifiedSnapshot.model;
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
    ? { ...editingItem, name: providerForm.name, apiKey: providerForm.apiKey, baseURL: providerForm.baseURL, model: providerForm.model }
    : null;

  const handleSave = () => {
    if (isBusy) {
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
      successToast: "AI 服务商配置已保存",
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

  const verifiedCount = providers.filter((item) => item.status === "verified").length;

  const metricItems = [
    { label: "服务商", value: providers.length },
    { label: "已验证可用", value: verifiedCount },
  ] as const;

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="AI 服务商"
        actions={
          <>
            {isDirty && (
              <span className={adminDirtyBadgeClass}>有未保存的修改</span>
            )}
            <Button
              className={`${adminPrimaryButtonClass} h-9 px-4 font-medium`}
              onClick={handleSave}
              disabled={!isDirty || isBusy}
            >
              {isSaving || externalSaving ? "保存中…" : "保存更改"}
            </Button>
          </>
        }
      />

      <AdminMetricStrip ariaLabel="AI 服务商统计" items={metricItems} />

      <AdminPanel
        title="全局策略"
        icon={<Bot className="h-4 w-4 text-[var(--label-3)]" />}
      >
        <div className="space-y-6">
          <AdminKVField label="指令服务商" htmlFor="ai-command-provider">
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
                className={`min-w-56 ${adminSelectTriggerClass}`}
              >
                <SelectValue placeholder="选择命令服务商…" />
              </SelectTrigger>
              <SelectContent className={adminSelectContentClass}>
                {providerOptions.map((item) => (
                  <SelectItem key={`command-${item.value}`} value={item.value}>
                    {item.label}{item.configured ? "" : "（未配置）"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </AdminKVField>
          <AdminKVField label="运维提示词" htmlFor="ai-prompt">
            <Textarea
              id="ai-prompt"
              className={`min-h-20 max-h-40 ${adminTextareaClass}`}
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
          </AdminKVField>
        </div>
      </AdminPanel>

      <AdminPanel
        title="服务商"
        icon={<Layers3 className="h-4 w-4 text-[var(--label-3)]" />}
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
          ariaLabel="AI 服务商列表"
          columns={providerTableColumns}
          rows={providers}
          rowKey={(item) => item.id}
          onRowClick={(item) => openProviderDialog(item)}
          emptyLabel="还没有服务商。"
        />
      </AdminPanel>

      <AdminDrawer
        open={isDialogOpen && editingItem !== null}
        onOpenChange={(open) => {
          if (!open) {
            closeProviderDialog();
          }
        }}
        title={
          editingItem ? (
            <span className="flex flex-wrap items-center gap-2.5">
              {providerForm.name || editingItem.name}
              {renderStatusBadge(
                verifiedSnapshot &&
                  providerForm.name === verifiedSnapshot.name &&
                  providerForm.apiKey === verifiedSnapshot.apiKey &&
                  providerForm.baseURL === verifiedSnapshot.baseURL &&
                  providerForm.model === verifiedSnapshot.model
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
            <div className="flex items-center justify-between gap-2">
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
              <div className="flex gap-2">
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
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
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
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
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
              <AdminKVField label="模型" htmlFor="provider-model">
                <div className="space-y-2">
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
                  <p className={`text-xs ${adminMutedTextClass}`}>
                    {editingItem.models.length > 0
                      ? `已缓存 ${editingItem.models.length} 个模型候选`
                      : "尚未获取模型列表"}
                  </p>
                </div>
              </AdminKVField>
            </section>

            <section>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
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
              <p className={`text-xs ${adminMutedTextClass}`}>
                验证与获取模型使用当前抽屉内的端点与密钥；端点改动需先完成并保存后再验证存储密钥。
              </p>
            </section>
          </>
        ) : null}
      </AdminDrawer>
    </div>
  );
}
