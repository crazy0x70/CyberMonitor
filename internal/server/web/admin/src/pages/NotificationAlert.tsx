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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { AlertTriangle, Bell, Send, ShieldAlert } from "lucide-react";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { cn } from "@/lib/utils";
import { parseTelegramUserIds } from "@/lib/admin-format";
import {
  adminActionButtonClass,
  adminDetailGroupClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
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
  onSave: (payload: Record<string, unknown>) => Promise<SettingsView>;
  onTest: (payload: AlertTestPayload) => Promise<void>;
}

type PendingConfirm = {
  payload: Record<string, unknown>;
  title: string;
  description: string;
  confirmLabel: string;
};

type AlertSettingsDraft = {
  webhook: string;
  telegramToken: string;
  telegramUserIds: string;
  offlineMinutes: string;
};

function isValidHTTPURL(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function makeAlertSettingsDraft(settings: SettingsView | null): AlertSettingsDraft {
  const userIds = Array.isArray(settings?.alert_telegram_user_ids)
    ? settings?.alert_telegram_user_ids
    : typeof settings?.alert_telegram_user_id === "number" && settings.alert_telegram_user_id > 0
      ? [settings.alert_telegram_user_id]
      : [];

  return {
    webhook: settings?.alert_webhook || "",
    telegramToken: settings?.alert_telegram_token || "",
    telegramUserIds: userIds.length > 0 ? userIds.join(",") : "",
    offlineMinutes:
      settings?.alert_offline_sec && settings.alert_offline_sec > 0
        ? String(Math.round(settings.alert_offline_sec / 60))
        : "5",
  };
}

function alertSettingsDraftSignature(draft: AlertSettingsDraft) {
  return JSON.stringify(draft);
}

function alertSettingsSourceSignature(settings: SettingsView | null) {
  return alertSettingsDraftSignature(makeAlertSettingsDraft(settings));
}

export default function NotificationAlert({
  settings,
  nodes,
  onDirtyChange,
  saving = false,
  onSave,
  onTest,
}: NotificationAlertProps) {
  const [initialDraft] = useState(() => makeAlertSettingsDraft(settings));
  const [webhook, setWebhook] = useState(initialDraft.webhook);
  const [telegramToken, setTelegramToken] = useState(initialDraft.telegramToken);
  const [telegramUserIds, setTelegramUserIds] = useState(initialDraft.telegramUserIds);
  const [offlineMinutes, setOfflineMinutes] = useState(initialDraft.offlineMinutes);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [testingChannel, setTestingChannel] = useState<"telegram" | "feishu" | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<AlertField, string>>>({});
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(null);
  const isBusy = isSaving || saving || testingChannel !== null;
  const currentDraftSignature = alertSettingsDraftSignature({
    webhook,
    telegramToken,
    telegramUserIds,
    offlineMinutes,
  });

  const [, absorbSourceSignature] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: alertSettingsSourceSignature(settings),
    isBusy,
    resetDraft: () => {
      const draft = makeAlertSettingsDraft(settings);
      setWebhook(draft.webhook);
      setTelegramToken(draft.telegramToken);
      setTelegramUserIds(draft.telegramUserIds);
      setOfflineMinutes(draft.offlineMinutes);
    },
    warningText: "服务端告警配置已更新，当前未保存修改已保留。",
    onCleaned: () => {
      setIsDirty(false);
      setFieldErrors({});
    },
  });
  useDirtyNotification(onDirtyChange, isDirty);

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
      if (isBusy) {
        return;
      }
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

    // token 已配置但脱敏回显为空（保留态）：user_ids 回显非空不构成
    // "要求成对配置"的触发条件，留空保存表示保留现值。
    const telegramConfigured = Boolean(settings?.alert_telegram_token_set);
    // 已配置态下 token 与 ids 均清空 = 显式停用意图：保存时显式下发空值
    // （服务端仅在收到显式空值时才清空，省略字段一律保留）。测试通道
    // 仍要求有效配置，不构成停用意图。
    const disableTelegram = telegramConfigured && !requireTelegram && !normalizedToken && !normalizedUserIds;
    // ids 格式校验独立于成对分支：已配置态下输入了非法内容（如 "abc"）时
    // 也必须报错，否则保存会静默回滚输入。
    if (normalizedUserIds && ids.length === 0) {
      nextErrors.telegramUserIds = "用户 ID 必须为正整数，多个 ID 请用逗号分隔。";
    }
    if (requireTelegram || normalizedToken || (normalizedUserIds && !telegramConfigured)) {
      if (!normalizedToken && (requireTelegram || !telegramConfigured)) {
        nextErrors.telegramToken = "请输入 Telegram Bot Token。";
      }
      if (!normalizedUserIds) {
        nextErrors.telegramUserIds = "请输入至少一个 Telegram 用户 ID。";
      }
    }

    const firstField = (Object.keys(alertFieldIDMap) as AlertField[]).find((field) => nextErrors[field]);
    return {
      disableTelegram,
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

  const buildSavePayload = (validation: ReturnType<typeof validateAlertForm>) => {
    const payload: Record<string, unknown> = {
      alert_offline_sec: validation.normalizedMinutes * 60,
    };
    // 密钥已脱敏回传：留空表示保留现值（省略字段），仅在输入新值时携带。
    if (validation.normalizedWebhook) {
      payload.alert_webhook = validation.normalizedWebhook;
    }
    if (validation.disableTelegram) {
      // 显式停用：省略字段在服务端语义是"保留"，必须显式下发空值。
      payload.alert_telegram_token = "";
      payload.alert_telegram_user_ids = [];
    } else {
      if (validation.normalizedToken) {
        payload.alert_telegram_token = validation.normalizedToken;
      }
      // ids 与 token 解耦：token 已配置保留（留空）时也允许单独更新收件人。
      if (validation.ids.length > 0) {
        payload.alert_telegram_user_ids = validation.ids;
      }
    }
    return payload;
  };

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

  const runAction = useAsyncAction();

  const runSave = (payload: Record<string, unknown>) => {
    void runAction({
      action: () => onSave(payload),
      fallbackError: "保存告警配置失败",
      successToast: "告警配置已保存",
      onSuccess: (savedSettings) => {
        const canonicalDraft = makeAlertSettingsDraft(savedSettings);
        setWebhook(canonicalDraft.webhook);
        setTelegramToken(canonicalDraft.telegramToken);
        setTelegramUserIds(canonicalDraft.telegramUserIds);
        setOfflineMinutes(canonicalDraft.offlineMinutes);
        absorbSourceSignature(alertSettingsDraftSignature(canonicalDraft));
        setIsDirty(false);
        setFieldErrors({});
      },
      setBusy: setIsSaving,
    });
  };

  const handleSave = () => {
    if (isBusy) {
      return;
    }
    const validation = validateAlertForm({});
    if (!applyValidationResult(validation)) {
      return;
    }
    const payload = buildSavePayload(validation);
    if (validation.disableTelegram) {
      // "双空=停用"对用户不可见：清空收件人的本意可能只是改列表，弹窗
      // 明示保存会连同样销已配置的 Bot Token（显式空值不可恢复）。
      setPendingConfirm({
        payload,
        title: "确认停用 Telegram 通知？",
        description: "保存将同时清除已配置的 Bot Token 与收件人列表，清除后需重新输入才能恢复；表单中其他未保存的修改将一并保存。",
        confirmLabel: "停用并保存",
      });
      return;
    }
    runSave(payload);
  };

  const handleTest = (channel: "telegram" | "feishu") => {
    if (isBusy) {
      return;
    }
    const validation = validateAlertForm({
      requireTelegram: channel === "telegram",
      requireWebhook: channel === "feishu",
    });
    if (!applyValidationResult(validation)) {
      return;
    }

    void runAction({
      action: () => onTest(buildTestPayload(channel, validation)),
      fallbackError: "测试发送失败",
      successToast: "测试消息已发送",
      setBusy: (on) => setTestingChannel(on ? channel : null),
    });
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
            disabled={!isDirty || isBusy}
          >
            {isSaving || saving ? "保存中…" : "保存更改"}
          </Button>
        </div>
      </div>

      {!settings?.alert_webhook_set && !settings?.alert_telegram_token_set ? (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 px-5 py-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
          <p className="text-sm font-medium text-amber-600 dark:text-amber-400">
            尚未配置任何通知渠道：节点离线时不会发送任何告警通知。请先配置飞书 Webhook 或 Telegram。
          </p>
        </div>
      ) : null}

      <div className="grid auto-rows-fr gap-4 md:grid-cols-3">
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
                  disabled={isBusy}
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
                <div className="grid content-start gap-2">
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
                    disabled={isBusy}
                    onChange={createFieldChangeHandler("telegramToken", setTelegramToken)}
                    placeholder={settings?.alert_telegram_token_set ? "已配置（留空保持不变）" : "例如：123456789:ABC…"}
                  />
                  {fieldErrors.telegramToken ? (
                    <p id="telegram-token-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                      {fieldErrors.telegramToken}
                    </p>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
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
                    disabled={isBusy}
                    onChange={createFieldChangeHandler("telegramUserIds", setTelegramUserIds)}
                    placeholder="多个用户 ID 请使用逗号分隔"
                  />
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
              disabled={isBusy}
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
                  disabled={isBusy}
                  onChange={createFieldChangeHandler("webhook", setWebhook)}
                  placeholder={settings?.alert_webhook_set ? "已配置（留空保持不变）" : "https://open.feishu.cn/open-apis/bot/v2/hook/…"}
                />
                {fieldErrors.webhook ? (
                  <p id="feishu-webhook-error" className="text-[11px] font-medium text-rose-500" aria-live="polite">
                    {fieldErrors.webhook}
                  </p>
                ) : null}
                {settings?.alert_webhook_set ? (
                  <AlertDialog>
                    <AlertDialogTrigger
                      type="button"
                      className="h-8 w-fit px-2 text-xs font-bold text-rose-500 hover:text-rose-600"
                      disabled={isBusy || isDirty}
                      title={isDirty ? "请先保存或放弃当前修改" : undefined}
                    >
                      停用飞书 Webhook…
                    </AlertDialogTrigger>
                    <AlertDialogContent className={adminDialogContentClass}>
                      <AlertDialogHeader className={adminDialogHeaderClass}>
                        <AlertDialogTitle>确认停用飞书 Webhook？</AlertDialogTitle>
                        <AlertDialogDescription>
                          停用后节点离线将不再发送飞书通知，需重新填写 Webhook 才能恢复。
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter className={adminDialogFooterClass}>
                        <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                        <AlertDialogAction
                          className={adminDialogDangerActionClass}
                          disabled={isBusy}
                          onClick={() => runSave({ alert_webhook: "" })}
                        >
                          确认停用
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                ) : null}
              </div>
            </div>
          </CardContent>
          <CardFooter className={`${panelFooterClass} px-6 pb-6`}>
            <Button
              variant="outline"
              className={cn(adminActionButtonClass, "h-11 shadow-none")}
              onClick={() => handleTest("feishu")}
              disabled={isBusy}
            >
              <Send className="mr-2 h-4 w-4" />
              {testingChannel === "feishu" ? "正在发送…" : "测试推送"}
            </Button>
          </CardFooter>
        </Card>
      </div>

      <AlertDialog open={pendingConfirm !== null} onOpenChange={(open) => { if (!open) { setPendingConfirm(null); } }}>
        <AlertDialogContent className={adminDialogContentClass}>
          <AlertDialogHeader className={adminDialogHeaderClass}>
            <AlertDialogTitle>{pendingConfirm?.title}</AlertDialogTitle>
            <AlertDialogDescription>{pendingConfirm?.description}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className={adminDialogFooterClass}>
            <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
            <AlertDialogAction
              className={adminDialogDangerActionClass}
              onClick={() => {
                if (pendingConfirm) {
                  runSave(pendingConfirm.payload);
                }
                setPendingConfirm(null);
              }}
            >
              {pendingConfirm?.confirmLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
