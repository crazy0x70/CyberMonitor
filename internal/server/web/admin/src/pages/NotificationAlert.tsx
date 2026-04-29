import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertTriangle, Bell, Clock3, Send, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { getErrorMessage, parseTelegramUserIds } from "@/lib/admin-format";
import {
  adminActionButtonClass,
  adminDetailGroupClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminOverviewCardClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPanelFooterClass,
  adminPanelHeaderClass,
  adminPrimaryButtonClass,
  adminStatCardClass,
  adminStatCardHeaderClass,
  adminStatEyebrowClass,
  adminStatIconChipClass,
  adminStatIconChipClassByTone,
  adminStatSurfaceClassByTone,
  adminStatValueToneClassByTone,
  adminSurfaceCardClass,
} from "@/lib/admin-ui";
import type { AlertTestPayload, NodeView, SettingsView } from "@/lib/admin-types";

const panelCardClass = `flex h-full flex-col overflow-hidden ${adminSurfaceCardClass}`;

const panelHeaderClass = adminPanelHeaderClass;

const panelFooterClass = `justify-end ${adminPanelFooterClass}`;

type AlertField = "offlineMinutes" | "telegramToken" | "telegramUserIds" | "webhook";

const alertFieldIDMap: Record<AlertField, string> = {
  offlineMinutes: "offline-minutes",
  telegramToken: "telegram-token",
  telegramUserIds: "telegram-user-ids",
  webhook: "feishu-webhook",
};

export interface NotificationAlertProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (payload: Record<string, unknown>) => Promise<void>;
  onTest: (payload: AlertTestPayload) => Promise<void>;
}

function isValidHTTPURL(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export default function NotificationAlert({
  settings,
  nodes,
  onDirtyChange,
  saving = false,
  onSave,
  onTest,
}: NotificationAlertProps) {
  const [webhook, setWebhook] = useState("");
  const [telegramToken, setTelegramToken] = useState("");
  const [telegramUserIds, setTelegramUserIds] = useState("");
  const [offlineMinutes, setOfflineMinutes] = useState("5");
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [testingChannel, setTestingChannel] = useState<"telegram" | "feishu" | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<AlertField, string>>>({});

  useEffect(() => {
    const userIds = Array.isArray(settings?.alert_telegram_user_ids)
      ? settings?.alert_telegram_user_ids
      : typeof settings?.alert_telegram_user_id === "number" && settings.alert_telegram_user_id > 0
        ? [settings.alert_telegram_user_id]
        : [];

    setWebhook(settings?.alert_webhook || "");
    setTelegramToken(settings?.alert_telegram_token || "");
    setTelegramUserIds(userIds.length > 0 ? userIds.join(",") : "");
    setOfflineMinutes(
      settings?.alert_offline_sec && settings.alert_offline_sec > 0
        ? String(Math.round(settings.alert_offline_sec / 60))
        : "5",
    );
    setIsDirty(false);
    setFieldErrors({});
  }, [settings]);

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

  const counts = useMemo(() => {
    const total = nodes.length;
    const enabled = nodes.filter((node) => node.alert_enabled !== false).length;
    const disabled = total - enabled;
    return { total, enabled, disabled };
  }, [nodes]);

  const focusAlertField = (field: AlertField) => {
    const element = document.getElementById(alertFieldIDMap[field]);
    if (element instanceof HTMLElement) {
      element.focus();
    }
  };

  const createFieldChangeHandler =
    (field: AlertField, setter: (value: string) => void) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      setter(event.target.value);
      setFieldErrors((current) =>
        current[field] ? { ...current, [field]: undefined } : current,
      );
      setIsDirty(true);
    };

  const validateAlertForm = ({
    requireTelegram = false,
    requireWebhook = false,
  }: {
    requireTelegram?: boolean;
    requireWebhook?: boolean;
  }) => {
    const nextErrors: Partial<Record<AlertField, string>> = {};
    const normalizedWebhook = webhook.trim();
    const normalizedToken = telegramToken.trim();
    const normalizedUserIds = telegramUserIds.trim();
    const ids = parseTelegramUserIds(telegramUserIds);
    const minutes = Number.parseInt(offlineMinutes, 10);

    if (!Number.isFinite(minutes) || minutes < 1) {
      nextErrors.offlineMinutes = "请输入大于或等于 1 的离线阈值。";
    }

    if (normalizedWebhook) {
      if (!isValidHTTPURL(normalizedWebhook)) {
        nextErrors.webhook = "Webhook 地址需为有效的 http 或 https 地址。";
      }
    } else if (requireWebhook) {
      nextErrors.webhook = "测试飞书告警前，请先填写 Webhook 地址。";
    }

    if (requireTelegram || normalizedToken || normalizedUserIds) {
      if (!normalizedToken) {
        nextErrors.telegramToken = "请输入 Telegram Bot Token。";
      }
      if (!normalizedUserIds) {
        nextErrors.telegramUserIds = "请输入至少一个 Telegram 用户 ID。";
      } else if (ids.length === 0) {
        nextErrors.telegramUserIds = "用户 ID 必须为正整数，多个 ID 请用逗号分隔。";
      }
    }

    const firstField = (Object.keys(alertFieldIDMap) as AlertField[]).find((field) => nextErrors[field]);
    return {
      errors: nextErrors,
      firstField,
      ids,
      normalizedToken,
      normalizedWebhook,
      normalizedMinutes: Number.isFinite(minutes) && minutes > 0 ? minutes : 5,
    };
  };

  const applyValidationResult = (validation: ReturnType<typeof validateAlertForm>) => {
    setFieldErrors(validation.errors);
    if (validation.firstField) {
      focusAlertField(validation.firstField);
      return false;
    }
    return true;
  };

  const buildSavePayload = (validation: ReturnType<typeof validateAlertForm>) => ({
    alert_webhook: validation.normalizedWebhook,
    alert_telegram_token: validation.normalizedToken,
    alert_telegram_user_ids: validation.ids,
    alert_offline_sec: validation.normalizedMinutes * 60,
  });

  const buildTestPayload = (
    channel: "telegram" | "feishu",
    validation: ReturnType<typeof validateAlertForm>,
  ): AlertTestPayload =>
    channel === "telegram"
      ? {
          telegram_token: validation.normalizedToken,
          telegram_user_ids: validation.ids,
        }
      : {
          webhook: validation.normalizedWebhook,
        };

  const handleSave = async () => {
    const validation = validateAlertForm({});
    if (!applyValidationResult(validation)) {
      return;
    }

    setIsSaving(true);
    try {
      await onSave(buildSavePayload(validation));
      toast.success("告警配置已保存");
      setIsDirty(false);
      setFieldErrors({});
    } catch (error) {
      toast.error(getErrorMessage(error, "保存告警配置失败"));
    } finally {
      setIsSaving(false);
    }
  };

  const handleTest = async (channel: "telegram" | "feishu") => {
    const validation = validateAlertForm({
      requireTelegram: channel === "telegram",
      requireWebhook: channel === "feishu",
    });
    if (!applyValidationResult(validation)) {
      return;
    }

    setTestingChannel(channel);
    try {
      await onTest(buildTestPayload(channel, validation));
      toast.success("测试消息已发送");
    } catch (error) {
      toast.error(getErrorMessage(error, "测试发送失败"));
    } finally {
      setTestingChannel(null);
    }
  };

  const statCards = [
    {
      label: "节点总数",
      value: counts.total,
      tone: "neutral",
      icon: Bell,
    },
    {
      label: "已启用告警",
      value: counts.enabled,
      tone: "success",
      icon: ShieldAlert,
    },
    {
      label: "已关闭告警",
      value: counts.disabled,
      tone: "warning",
      icon: AlertTriangle,
    },
    {
      label: "离线阈值",
      value: `${offlineMinutes || "5"} 分钟`,
      tone: "info",
      icon: Clock3,
    },
  ] as const;

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>通知告警</h1>
        </div>
        <div className={adminPageActionsClass}>
          {isDirty && (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          )}
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            onClick={handleSave}
            disabled={!isDirty || isSaving || saving}
          >
            {isSaving || saving ? "保存中…" : "保存更改"}
          </Button>
        </div>
      </div>

      <div className="grid auto-rows-fr gap-4 md:grid-cols-2 xl:grid-cols-4">
        {statCards.map((item) => {
          const Icon = item.icon;
          return (
            <Card
              key={item.label}
              className={`${adminOverviewCardClass} ${adminStatCardClass} ${adminStatSurfaceClassByTone[item.tone]}`}
            >
              <CardHeader className={adminStatCardHeaderClass}>
                <div>
                  <CardDescription className={adminStatEyebrowClass}>
                    {item.label}
                  </CardDescription>
                  <CardTitle className={`text-3xl font-black tracking-tighter ${adminStatValueToneClassByTone[item.tone]}`}>
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
      </div>

      <div className="grid gap-6">
        <Card className={panelCardClass}>
          <CardHeader className={panelHeaderClass}>
            <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-amber-500/10 text-amber-500">
                <AlertTriangle className="h-5 w-5" />
              </div>
              全局告警策略
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-6 pb-6">
            <div className={adminDetailGroupClass}>
              <div className="grid gap-2">
                <Label htmlFor="offline-minutes" className="text-xs font-black uppercase tracking-widest text-slate-400">离线阈值（分钟）</Label>
                <Input
                  id="offline-minutes"
                  type="number"
                  name="offline-minutes"
                  min={1}
                  autoComplete="off"
                  inputMode="numeric"
                  className={adminInputClass}
                  aria-invalid={Boolean(fieldErrors.offlineMinutes)}
                  aria-describedby={fieldErrors.offlineMinutes ? "offline-minutes-error" : undefined}
                  value={offlineMinutes}
                  onChange={createFieldChangeHandler("offlineMinutes", setOfflineMinutes)}
                />
                {fieldErrors.offlineMinutes ? (
                  <p id="offline-minutes-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                    {fieldErrors.offlineMinutes}
                  </p>
                ) : null}
                <p className="text-[11px] font-medium text-slate-400 mt-1">当节点超过此时间未上报心跳时，将触发离线通知。</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className={panelCardClass}>
          <CardHeader className={panelHeaderClass}>
            <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-500">
                <Bell className="h-5 w-5" />
              </div>
              Telegram 告警
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-6 pb-6 space-y-4">
            <div className={adminDetailGroupClass}>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="grid gap-2">
                  <Label htmlFor="telegram-token" className="text-xs font-black uppercase tracking-widest text-slate-400">Bot Token</Label>
                  <Input
                    id="telegram-token"
                    type="password"
                    name="telegram-token"
                    autoComplete="off"
                    spellCheck={false}
                    className={adminInputClass}
                    aria-invalid={Boolean(fieldErrors.telegramToken)}
                    aria-describedby={fieldErrors.telegramToken ? "telegram-token-error" : undefined}
                    value={telegramToken}
                    onChange={createFieldChangeHandler("telegramToken", setTelegramToken)}
                    placeholder="例如：123456789:ABC…"
                  />
                  {fieldErrors.telegramToken ? (
                    <p id="telegram-token-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                      {fieldErrors.telegramToken}
                    </p>
                  ) : null}
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="telegram-user-ids" className="text-xs font-black uppercase tracking-widest text-slate-400">用户 ID</Label>
                  <Input
                    id="telegram-user-ids"
                    name="telegram-user-ids"
                    autoComplete="off"
                    inputMode="numeric"
                    spellCheck={false}
                    className={adminInputClass}
                    aria-invalid={Boolean(fieldErrors.telegramUserIds)}
                    aria-describedby={fieldErrors.telegramUserIds ? "telegram-user-ids-error" : undefined}
                    value={telegramUserIds}
                    onChange={createFieldChangeHandler("telegramUserIds", setTelegramUserIds)}
                    placeholder="例如：123456789,987654321…"
                  />
                  <p className="text-[11px] font-medium text-slate-400">
                    多个用户 ID 请使用逗号分隔。
                  </p>
                  {fieldErrors.telegramUserIds ? (
                    <p id="telegram-user-ids-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                      {fieldErrors.telegramUserIds}
                    </p>
                  ) : null}
                </div>
              </div>
            </div>
          </CardContent>
          <CardFooter className={`${panelFooterClass} px-6 pb-6`}>
            <Button
              variant="outline"
              className={cn(adminActionButtonClass, "h-11 shadow-none")}
              onClick={() => handleTest("telegram")}
              disabled={testingChannel !== null}
            >
              <Send className="mr-2 h-4 w-4" />
              {testingChannel === "telegram" ? "正在发送…" : "测试推送"}
            </Button>
          </CardFooter>
        </Card>

        <Card className={panelCardClass}>
          <CardHeader className={panelHeaderClass}>
            <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/10 text-sky-500">
                <Bell className="h-5 w-5" />
              </div>
              飞书告警
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-6 pb-6">
            <div className={adminDetailGroupClass}>
              <div className="grid gap-2">
                <Label htmlFor="feishu-webhook" className="text-xs font-black uppercase tracking-widest text-slate-400">Webhook 地址</Label>
                <Input
                  id="feishu-webhook"
                  type="url"
                  name="feishu-webhook"
                  autoComplete="off"
                  inputMode="url"
                  spellCheck={false}
                  className={adminInputClass}
                  aria-invalid={Boolean(fieldErrors.webhook)}
                  aria-describedby={fieldErrors.webhook ? "feishu-webhook-error" : undefined}
                  value={webhook}
                  onChange={createFieldChangeHandler("webhook", setWebhook)}
                  placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/…"
                />
                {fieldErrors.webhook ? (
                  <p id="feishu-webhook-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                    {fieldErrors.webhook}
                  </p>
                ) : null}
              </div>
            </div>
          </CardContent>
          <CardFooter className={`${panelFooterClass} px-6 pb-6`}>
            <Button
              variant="outline"
              className={cn(adminActionButtonClass, "h-11 shadow-none")}
              onClick={() => handleTest("feishu")}
              disabled={testingChannel !== null}
            >
              <Send className="mr-2 h-4 w-4" />
              {testingChannel === "feishu" ? "正在发送…" : "测试推送"}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
