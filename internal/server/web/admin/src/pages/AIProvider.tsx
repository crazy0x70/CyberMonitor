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
import type { AIProviderConfig, SettingsView } from "@/lib/admin-types";

export interface AIProviderProps {
  settings: SettingsView | null;
  onDirtyChange?: (dirty: boolean) => void;
  onSave: (payload: Record<string, unknown>) => Promise<void>;
  onTestProvider: (provider: string, config: AIProviderConfig) => Promise<void>;
  onFetchModels: (provider: string, config: AIProviderConfig) => Promise<string[]>;
}

type ProviderStatus = "unconfigured" | "unverified" | "verified";

type ProviderDraft = {
  id: string;
  name: string;
  provider: "openai" | "gemini" | "volcengine" | "openai_compatible";
  apiKey: string;
  baseURL: string;
  model: string;
  models: string[];
  status: ProviderStatus;
};

function resolveStatus(config: AIProviderConfig | undefined) {
  if (!config?.api_key) return "unconfigured" as const;
  return "unverified" as const;
}

function providerLabel(provider: string, fallback = "") {
  if (provider === "openai") return "OpenAI";
  if (provider === "gemini") return "Gemini";
  if (provider === "volcengine") return "Volcengine";
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
    },
    {
      id: "gemini",
      name: "Gemini",
      provider: "gemini",
      apiKey: ai.gemini?.api_key || "",
      baseURL: ai.gemini?.base_url || "",
      model: ai.gemini?.model || "",
      models: [],
      status: resolveStatus(ai.gemini),
    },
    {
      id: "volcengine",
      name: "Volcengine",
      provider: "volcengine",
      apiKey: ai.volcengine?.api_key || "",
      baseURL: ai.volcengine?.base_url || "",
      model: ai.volcengine?.model || "",
      models: [],
      status: resolveStatus(ai.volcengine),
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

function toProviderValue(item: ProviderDraft) {
  return item.provider === "openai_compatible" ? `openai_compatible:${item.id}` : item.provider;
}

function toProviderRequestKey(item: ProviderDraft) {
  return item.provider === "openai_compatible" ? "openai_compatible" : item.provider;
}

function resolveProviderSelection(options: Array<{ value: string }>, currentValue: string) {
  if (options.some((item) => item.value === currentValue)) {
    return currentValue;
  }
  return options[0]?.value || "openai";
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
  onSave,
  onTestProvider,
  onFetchModels,
}: AIProviderProps) {
  const [providers, setProviders] = useState<ProviderDraft[]>(() => makeProviderDrafts(settings));
  const [commandProvider, setCommandProvider] = useState("openai");
  const [prompt, setPrompt] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [fetchingModelsId, setFetchingModelsId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setProviders(makeProviderDrafts(settings));
    setCommandProvider(
      settings?.ai_settings?.command_provider || settings?.ai_settings?.default_provider || "openai",
    );
    setPrompt(settings?.ai_settings?.prompt || "");
    setIsDirty(false);
  }, [settings]);

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

  const providerOptions = useMemo(() => {
    return providers.map((item) => ({
      value: toProviderValue(item),
      label: providerLabel(item.provider, item.name),
      configured: Boolean(item.apiKey),
      status: item.status,
    }));
  }, [providers]);

  useEffect(() => {
    const nextCommand = resolveProviderSelection(providerOptions, commandProvider);
    if (nextCommand !== commandProvider) {
      setCommandProvider(nextCommand);
    }
  }, [commandProvider, providerOptions]);

  const updateProvider = (id: string, updater: (current: ProviderDraft) => ProviderDraft) => {
    setProviders((current) =>
      current.map((item) => (item.id === id ? updater(item) : item)),
    );
    setIsDirty(true);
  };

  const addCompatible = () => {
    const id = `compatible-${Date.now()}`;
    setProviders((current) => [
      ...current,
      {
        id,
        name: "新兼容服务商",
        provider: "openai_compatible",
        apiKey: "",
        baseURL: "",
        model: "",
        models: [],
        status: "unconfigured",
      },
    ]);
    setIsDirty(true);
  };

  const removeCompatible = (id: string) => {
    setProviders((current) => current.filter((item) => item.id !== id));
    setIsDirty(true);
  };

  const handleTest = async (item: ProviderDraft) => {
    setTestingId(item.id);
    try {
      await onTestProvider(toProviderRequestKey(item), toConfig(item));
      setProviders((current) =>
        current.map((entry) => (entry.id === item.id ? { ...entry, status: "verified" } : entry)),
      );
      toast.success(`${item.name} 验证成功`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "验证失败");
    } finally {
      setTestingId(null);
    }
  };

  const handleFetchModels = async (item: ProviderDraft) => {
    setFetchingModelsId(item.id);
    try {
      const models = await onFetchModels(toProviderRequestKey(item), toConfig(item));
      setProviders((current) =>
        current.map((entry) => (entry.id === item.id ? { ...entry, models } : entry)),
      );
      if (models.length > 0 && !item.model) {
        updateProvider(item.id, (current) => ({ ...current, model: models[0] }));
      }
      toast.success(`${item.name} 模型列表已刷新`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "获取模型列表失败");
    } finally {
      setFetchingModelsId(null);
    }
  };

  const handleSave = async () => {
    const openai = providers.find((item) => item.provider === "openai");
    const gemini = providers.find((item) => item.provider === "gemini");
    const volcengine = providers.find((item) => item.provider === "volcengine");
    const compatibles = providers.filter((item) => item.provider === "openai_compatible");

    setSaving(true);
    try {
      await onSave({
        ai_settings: {
          default_provider: commandProvider,
          command_provider: commandProvider,
          prompt,
          openai: openai ? toConfig(openai) : {},
          gemini: gemini ? toConfig(gemini) : {},
          volcengine: volcengine ? toConfig(volcengine) : {},
          openai_compatibles: compatibles.map((item) => ({
            id: item.id,
            name: item.name.trim(),
            ...toConfig(item),
          })),
        },
      });
      toast.success("AI 服务商配置已保存");
      setIsDirty(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存 AI 配置失败");
    } finally {
      setSaving(false);
    }
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
            disabled={!isDirty || saving}
          >
            {saving ? "保存中…" : "保存更改"}
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
              onValueChange={(value) => {
                if (value === null) {
                  return;
                }
                setCommandProvider(value);
                setIsDirty(true);
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
              setPrompt(event.target.value);
              setIsDirty(true);
            }}
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
                        onChange={(event) =>
                          updateProvider(item.id, (current) => ({
                            ...current,
                            name: event.target.value,
                          }))
                        }
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
                        onChange={(event) =>
                          updateProvider(item.id, (current) => ({
                            ...current,
                            apiKey: event.target.value,
                            status: event.target.value ? "unverified" : "unconfigured",
                          }))
                        }
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
                        onChange={(event) =>
                          updateProvider(item.id, (current) => ({
                            ...current,
                            baseURL: event.target.value,
                            status: current.apiKey ? "unverified" : current.status,
                          }))
                        }
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
                        onChange={(event) =>
                          updateProvider(item.id, (current) => ({
                            ...current,
                            model: event.target.value,
                            status: current.apiKey ? "unverified" : current.status,
                          }))
                        }
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
                        disabled={fetchingModelsId !== null}
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
                        disabled={testingId !== null}
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
