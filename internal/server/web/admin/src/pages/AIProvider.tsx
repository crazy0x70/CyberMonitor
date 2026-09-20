import { useEffect, useMemo, useState } from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { Textarea } from "@/components/ui/textarea";
import { Bot, CheckCircle2, FileText, HelpCircle, Layers3, Loader2, Plus, Trash2, XCircle } from "lucide-react";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { toast } from "sonner";
import {
  adminActionButtonClass,
  adminDangerOutlineButtonClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminInsetCardClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminSuccessBadgeClass,
  adminSectionHeaderClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminSurfaceCardClass,
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
  // api_key 已脱敏恒空，凭据事实看 api_key_set。
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

function toConfig(item: ProviderDraft): AIProviderConfig {
  return {
    api_key: item.apiKey.trim(),
    base_url: item.baseURL.trim(),
    model: item.model.trim(),
  };
}

// 验证/取模型路径：本会话未重输 key 时传 null，后端 override=nil 走
// 存储配置——占位符"已配置（留空保持不变）"的承诺在验证路径同样成立。
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

function aiSettingsDraftSignature(draft: AISettingsDraft) {
  return JSON.stringify({
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
  });
}

function aiSettingsSourceSignature(settings: SettingsView | null) {
  return aiSettingsDraftSignature(makeAISettingsDraft(settings));
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
  const isBusy = isSaving || externalSaving || testingId !== null || fetchingModelsId !== null;

  const currentDraftSignature = useMemo(
    () => aiSettingsDraftSignature({ providers, commandProvider, prompt }),
    [commandProvider, prompt, providers],
  );

  const [sourceSignature, absorbSourceSignature] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: aiSettingsSourceSignature(settings),
    isBusy,
    resetDraft: () => {
      const draft = makeAISettingsDraft(settings);
      setProviders(draft.providers);
      setCommandProvider(draft.commandProvider);
      setPrompt(draft.prompt);
    },
    warningText: "服务端 AI 配置已更新，当前未保存修改已保留。",
  });
  // dirty 从签名派生（对齐 hook 惯例）：手工撤销回原值时徽标同步熄灭，
  // 不会像本地布尔那样卡在"有未保存的修改"。
  const isDirty = currentDraftSignature !== sourceSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  const savedCompatibleIDs = useMemo(
    () => new Set((settings?.ai_settings?.openai_compatibles || []).map((item) => item.id)),
    [settings],
  );
  // 请求选择器：已保存的 compatible 必须带 id——config=null（存量 key）
  // 时后端按选择器取存储配置，裸 key 会命中列表第一个服务商。未保存的
  // 新增条目 id 不在存储中，走 override 全量替换，保留裸 key。
  const toProviderRequestKey = (item: ProviderDraft) => {
    if (item.provider !== "openai_compatible") {
      return item.provider;
    }
    return savedCompatibleIDs.has(item.id) ? `openai_compatible:${item.id}` : "openai_compatible";
  };

  // key 走存储配置（输入留空）但端点/模型已改动：测试的是存储旧值，
  // 结果会误导归因——要求先保存。
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
      // 脱敏视图下 apiKey 恒空：已配置与否要看 keyConfigured。
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
      // reconcile 类 effect 只修正选中项，不产生新的 dirty——
      // 否则服务端规范化 compatible id 后用户刚保存就被标记未保存。
      setCommandProvider(nextCommand);
    }
  }, [commandProvider, isBusy, providerOptions]);

  const setProviderDrafts = (updater: (current: ProviderDraft[]) => ProviderDraft[]) => {
    setProviders(updater);
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
          // 清空输入=保存时保留服务端现 key，状态跟随现状不降级。
          status: value ? "unverified" : current.keyConfigured ? current.status : "unconfigured",
        };
      }
      // 端点/模型变更即降级：已验证状态只对当时保存的端点成立；key 走
      // 存储（输入为空、keyConfigured=true）是脱敏视图下的主路径，同样
      // 必须降级——否则徽标对新端点虚报已验证。
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
    // setter updater 必须保持纯函数（StrictMode 下会执行两次）：
    // 先基于当前 state 计算新值，再分别调用两个 setter。
    const nextDrafts = providers.filter((item) => item.id !== id);
    if (removingSelectedProvider) {
      setCommandProvider(
        resolveProviderSelection(nextDrafts.map((item) => ({ value: toProviderValue(item) })), ""),
      );
    }
    setProviderDrafts(() => nextDrafts);
  };

  const runAction = useAsyncAction();

  const handleTest = (item: ProviderDraft) => {
    if (isBusy) {
      return;
    }
    if (endpointEditNeedsSave(item)) {
      toast.warning("端点或模型有未保存修改，请先保存后再测试。");
      return;
    }
    void runAction({
      action: () => onTestProvider(toProviderRequestKey(item), toTestConfig(item)),
      fallbackError: "验证失败",
      successToast: `${item.name} 验证成功`,
      onSuccess: () => updateProviderDraft(item.id, (current) => ({ ...current, status: "verified" })),
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
        const shouldFillModel = models.length > 0 && !item.model;
        updateProviderDraft(
          item.id,
          (current) => ({
            ...current,
            models,
            model: shouldFillModel ? models[0] : current.model,
          })
        );
      },
      setBusy: (on) => setFetchingModelsId(on ? item.id : null),
    });
  };

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
        absorbSourceSignature(aiSettingsDraftSignature(canonicalDraft));
      },
      setBusy: setIsSaving,
    });
  };

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>AI 服务商</h1>
        </div>
        <div className={adminPageActionsClass}>
          {isDirty && (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          )}
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            onClick={handleSave}
            disabled={!isDirty || isBusy}
          >
            {isSaving || externalSaving ? "保存中…" : "保存更改"}
          </Button>
        </div>
      </div>

      <Card className={adminSurfaceCardClass}>
        <CardHeader className={adminSectionHeaderClass}>
          <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight text-slate-900 dark:text-slate-100">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400">
              <Bot className="h-5 w-5" />
            </div>
            全局 AI 策略
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-6 pb-6">
          <div className="space-y-3">
            <Label htmlFor="ai-command-provider" className="text-xs font-black uppercase tracking-widest text-slate-400">Telegram AI 指令服务商</Label>
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
              <SelectTrigger id="ai-command-provider" className={`w-full ${adminSelectTriggerClass}`}>
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
          </div>
        </CardContent>
      </Card>

      <Card className={adminSurfaceCardClass}>
        <CardHeader className={adminSectionHeaderClass}>
          <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-500">
              <FileText className="h-5 w-5" />
            </div>
            AI 运维提示词
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-6 pb-6">
          <Label htmlFor="ai-prompt" className="mb-3 block text-xs font-black uppercase tracking-widest text-slate-400">提示词内容</Label>
          <Textarea
            id="ai-prompt"
            className={`min-h-[156px] ${adminTextareaClass}`}
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
        </CardContent>
      </Card>

      <Card className={adminSurfaceCardClass}>
        <CardHeader className={`${adminSectionHeaderClass} flex flex-row items-center justify-between gap-4`}>
          <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-500">
              <Layers3 className="h-5 w-5" />
            </div>
            服务商配置详情
          </CardTitle>
          <Button
            variant="outline"
            className={adminActionButtonClass}
            onClick={addCompatible}
            disabled={isBusy}
          >
            <Plus className="mr-2 h-4 w-4" />
            新增兼容服务商
          </Button>
        </CardHeader>
        <CardContent className="pt-6 pb-6">
          <Accordion multiple className="space-y-4">
            {providers.map((item) => (
              <AccordionItem
                key={item.id}
                value={item.id}
                className={`overflow-hidden px-4 ${adminInsetCardClass}`}
              >
                <AccordionTrigger className="py-4 hover:no-underline">
                  <div className="flex flex-1 items-center justify-between gap-4 pr-4">
                    <div className="text-left font-medium text-slate-900 dark:text-slate-100">{item.name}</div>
                    {renderStatusBadge(item.status)}
                  </div>
                </AccordionTrigger>
                <AccordionContent className="space-y-4 pb-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="grid gap-2">
                      <Label htmlFor={`${item.id}-display-name`}>显示名称</Label>
                      <Input
                        id={`${item.id}-display-name`}
                        className={adminInputClass}
                        autoComplete="off"
                        value={item.name}
                        disabled={isBusy}
                        onChange={(event) => updateProviderInput(item.id, "name", event.target.value)}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor={`${item.id}-api-key`}>API Key</Label>
                      <Input
                        id={`${item.id}-api-key`}
                        className={adminInputClass}
                        type="password"
                        autoComplete="new-password"
                        spellCheck={false}
                        value={item.apiKey}
                        disabled={isBusy}
                        onChange={(event) => updateProviderInput(item.id, "apiKey", event.target.value)}
                        placeholder={item.keyConfigured ? "已配置（留空保持不变）" : "sk-…"}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor={`${item.id}-base-url`}>Base URL</Label>
                      <Input
                        id={`${item.id}-base-url`}
                        className={adminInputClass}
                        type="url"
                        autoComplete="off"
                        inputMode="url"
                        spellCheck={false}
                        value={item.baseURL}
                        disabled={isBusy}
                        onChange={(event) => updateProviderInput(item.id, "baseURL", event.target.value)}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor={`${item.id}-model`}>模型</Label>
                      <Input
                        id={`${item.id}-model`}
                        className={adminInputClass}
                        list={`models-${item.id}`}
                        autoComplete="off"
                        spellCheck={false}
                        value={item.model}
                        disabled={isBusy}
                        onChange={(event) => updateProviderInput(item.id, "model", event.target.value)}
                      />
                      <datalist id={`models-${item.id}`}>
                        {item.models.map((model) => (
                          <option key={model} value={model} />
                        ))}
                      </datalist>
                    </div>
                  </div>

                  <Separator />

                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className={`text-sm ${adminMutedTextClass}`}>
                      {item.models.length > 0 ? `已缓存 ${item.models.length} 个模型候选` : "尚未获取模型列表"}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="outline"
                        className={adminActionButtonClass}
                        onClick={() => handleFetchModels(item)}
                        disabled={isBusy}
                      >
                        {fetchingModelsId === item.id ? (
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
                        onClick={() => handleTest(item)}
                        disabled={isBusy}
                      >
                        {testingId === item.id ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            验证中…
                          </>
                        ) : (
                          "测试连接"
                        )}
                      </Button>
                      {item.provider === "openai_compatible" ? (
                        <Button
                          variant="outline"
                          className={`${adminDangerOutlineButtonClass} h-11 min-w-[132px] px-5`}
                          onClick={() => removeCompatible(item.id)}
                          disabled={isBusy}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          删除
                        </Button>
                      ) : null}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>
    </div>
  );
}
