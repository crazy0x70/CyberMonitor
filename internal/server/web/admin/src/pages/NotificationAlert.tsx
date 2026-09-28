import { useMemo, useState, type ChangeEvent } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { AlertTriangle, Bell, Send } from "lucide-react";
import {
  draftSignature,
  sourceSignature,
  useAsyncAction,
  useDirtyNotification,
  useDraftReconcile,
} from "@/lib/admin-hooks";
import { cn } from "@/lib/utils";
import { parseTelegramUserIds } from "@/lib/admin-format";
import {
  adminCompactActionButtonClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminDirtyBadgeClass,
  adminInputClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
} from "@/lib/admin-ui";
import type { AlertTestPayload, NodeView, SettingsUpdate, SettingsView } from "@/lib/admin-types";

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
  onSave: (payload: SettingsUpdate) => Promise<SettingsView>;
  onTest: (payload: AlertTestPayload) => Promise<void>;
}

type PendingConfirm = {
  payload: SettingsUpdate;
  title: string;
  description: string;
  confirmLabel: string;
  webhookOnly?: boolean;
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

function ChannelStatusBadge({ configured }: { configured: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium",
        configured
          ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300"
          : "border border-dashed border-slate-300 text-slate-400 dark:border-neutral-700 dark:text-neutral-500"
      )}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          configured ? "bg-emerald-500" : "bg-slate-300 dark:bg-neutral-600"
        )}
      />
      {configured ? "已配置" : "未配置"}
    </span>
  );
}

function makeAlertSettingsDraft(settings: SettingsView | null): AlertSettingsDraft {
  const userIds = Array.isArray(settings?.alert_telegram_user_ids)
    ? settings?.alert_telegram_user_ids
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
  const [webhookTouched, setWebhookTouched] = useState(false);
  const [telegramToken, setTelegramToken] = useState(initialDraft.telegramToken);
  const [telegramUserIds, setTelegramUserIds] = useState(initialDraft.telegramUserIds);
  const [offlineMinutes, setOfflineMinutes] = useState(initialDraft.offlineMinutes);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [testingChannel, setTestingChannel] = useState<"telegram" | "feishu" | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<AlertField, string>>>({});
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(null);
  const isBusy = isSaving || saving || testingChannel !== null;
  const currentDraftSignature = draftSignature({
    webhook,
    telegramToken,
    telegramUserIds,
    offlineMinutes,
  });

  const [, absorbSourceSignature] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: sourceSignature(makeAlertSettingsDraft, settings),
    isBusy,
    resetDraft: () => {
      const draft = makeAlertSettingsDraft(settings);
      setWebhook(draft.webhook);
      setWebhookTouched(false);
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
      if (field === "webhook") {
        setWebhookTouched(true);
      }
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

    const webhookConfigured = Boolean(settings?.alert_webhook_set);

    const disableWebhook =
      webhookConfigured && !requireWebhook && !normalizedWebhook && webhookTouched;

    const telegramConfigured = Boolean(settings?.alert_telegram_token_set);

    const disableTelegram = telegramConfigured && !requireTelegram && !normalizedToken && !normalizedUserIds;

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
      disableWebhook,
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

  const buildSavePayload = (validation: ReturnType<typeof validateAlertForm>): SettingsUpdate => {
    const payload: SettingsUpdate = {
      alert_offline_sec: validation.normalizedMinutes * 60,
    };

    if (validation.disableWebhook) {
      payload.alert_webhook = "";
    } else if (validation.normalizedWebhook) {
      payload.alert_webhook = validation.normalizedWebhook;
    }
    if (validation.disableTelegram) {

      payload.alert_telegram_token = "";
      payload.alert_telegram_user_ids = [];
    } else {
      if (validation.normalizedToken) {
        payload.alert_telegram_token = validation.normalizedToken;
      }

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

  const runSave = (payload: SettingsUpdate) => {
    void runAction({
      action: () => onSave(payload),
      fallbackError: "保存告警配置失败",
      successToast: "告警配置已保存",
      onSuccess: (savedSettings) => {
        const canonicalDraft = makeAlertSettingsDraft(savedSettings);
        setWebhook(canonicalDraft.webhook);
        setWebhookTouched(false);
        setTelegramToken(canonicalDraft.telegramToken);
        setTelegramUserIds(canonicalDraft.telegramUserIds);
        setOfflineMinutes(canonicalDraft.offlineMinutes);
        absorbSourceSignature(draftSignature(canonicalDraft));
        setIsDirty(false);
        setFieldErrors({});
      },
      setBusy: setIsSaving,
    });
  };

  const runDisableWebhook = (payload: SettingsUpdate) => {
    void runAction({
      action: () => onSave(payload),
      fallbackError: "停用飞书告警失败",
      successToast: "飞书告警已停用",
      onSuccess: (savedSettings) => {
        const canonicalDraft = makeAlertSettingsDraft(savedSettings);
        setWebhook(canonicalDraft.webhook);
        setWebhookTouched(false);
      },
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
    if (validation.disableWebhook) {
      setPendingConfirm({
        payload,
        title: "确认停用飞书告警？",
        description: "保存将清除已配置的 Webhook 地址，清除后需重新输入才能恢复；表单中其他未保存的修改将一并保存。",
        confirmLabel: "停用并保存",
      });
      return;
    }
    if (validation.disableTelegram) {

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

  const metricItems = [
    { label: "节点总数", value: counts.total },
    { label: "已启用告警的节点", value: counts.enabled },
    { label: "已关闭告警", value: counts.disabled },
  ] as const;

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="通知告警"
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
              {isSaving || saving ? "保存中…" : "保存更改"}
            </Button>
          </>
        }
      />

      {!settings?.alert_webhook_set && !settings?.alert_telegram_token_set ? (
        <div className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4">
          <AlertTriangle className="mt-1 h-5 w-5 shrink-0 text-amber-500" />
          <p className="text-sm font-medium text-amber-600 dark:text-amber-400">
            尚未配置任何通知渠道：节点离线时不会发送任何告警通知。请先配置飞书 Webhook 或 Telegram。
          </p>
        </div>
      ) : null}

      <AdminMetricStrip ariaLabel="告警统计" items={metricItems} />

      <AdminPanel
        title="全局告警策略"
        icon={<AlertTriangle className="h-4 w-4 text-[var(--label-3)]" />}
      >
        <AdminKVField label="离线阈值（分钟）" htmlFor="offline-minutes">
          <div className="max-w-md space-y-2">
            <Input
              id="offline-minutes"
              type="number"
              name="offline-minutes"
              min={1}
              autoComplete="off"
              inputMode="numeric"
              className={`${adminInputClass} data-text`}
              aria-invalid={Boolean(fieldErrors.offlineMinutes)}
              aria-describedby={fieldErrors.offlineMinutes ? "offline-minutes-error" : undefined}
              value={offlineMinutes}
              disabled={isBusy}
              onChange={createFieldChangeHandler("offlineMinutes", setOfflineMinutes)}
            />
            {fieldErrors.offlineMinutes ? (
              <p id="offline-minutes-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                {fieldErrors.offlineMinutes}
              </p>
            ) : null}
            <p className="text-xs text-slate-500 dark:text-neutral-400">当节点超过此时间未上报心跳时，将触发离线通知。</p>
          </div>
        </AdminKVField>
      </AdminPanel>

      <AdminPanel
        title="Telegram 告警"
        icon={<Bell className="h-4 w-4 text-[var(--label-3)]" />}
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <ChannelStatusBadge configured={Boolean(settings?.alert_telegram_token_set)} />
            <Button
              variant="outline"
              className={adminCompactActionButtonClass}
              onClick={() => handleTest("telegram")}
              disabled={isBusy}
            >
              <Send className="h-3.5 w-3.5" />
              {testingChannel === "telegram" ? "正在发送…" : "测试推送"}
            </Button>
          </div>
        }
      >
        { }
        <div className="space-y-4">
          <AdminKVField label="Bot Token" htmlFor="telegram-token">
            <div className="max-w-md space-y-2">
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
                <p id="telegram-token-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                  {fieldErrors.telegramToken}
                </p>
              ) : null}
            </div>
          </AdminKVField>
          <AdminKVField label="用户 ID" htmlFor="telegram-user-ids">
            <div className="max-w-md space-y-2">
              <Input
                id="telegram-user-ids"
                name="telegram-user-ids"
                autoComplete="off"
                inputMode="numeric"
                spellCheck={false}
                className={`${adminInputClass} data-text`}
                aria-invalid={Boolean(fieldErrors.telegramUserIds)}
                aria-describedby={fieldErrors.telegramUserIds ? "telegram-user-ids-error" : undefined}
                value={telegramUserIds}
                disabled={isBusy}
                onChange={createFieldChangeHandler("telegramUserIds", setTelegramUserIds)}
                placeholder="多个用户 ID 请使用逗号分隔"
              />
              {fieldErrors.telegramUserIds ? (
                <p id="telegram-user-ids-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                  {fieldErrors.telegramUserIds}
                </p>
              ) : null}
            </div>
          </AdminKVField>
        </div>
      </AdminPanel>

      <AdminPanel
        title="飞书告警"
        icon={<Bell className="h-4 w-4 text-[var(--label-3)]" />}
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <ChannelStatusBadge configured={Boolean(settings?.alert_webhook_set)} />
            {settings?.alert_webhook_set ? (
              <Button
                variant="outline"
                className={adminCompactActionButtonClass}
                onClick={() => {
                  if (isBusy) {
                    return;
                  }
                  setPendingConfirm({
                    payload: { alert_webhook: "" },
                    title: "确认停用飞书告警？",
                    description: "停用将清除已配置的 Webhook 地址，清除后需重新输入才能恢复；表单中其他未保存的修改不受影响。",
                    confirmLabel: "停用",
                    webhookOnly: true,
                  });
                }}
                disabled={isBusy}
              >
                停用
              </Button>
            ) : null}
            <Button
              variant="outline"
              className={adminCompactActionButtonClass}
              onClick={() => handleTest("feishu")}
              disabled={isBusy}
            >
              <Send className="h-3.5 w-3.5" />
              {testingChannel === "feishu" ? "正在发送…" : "测试推送"}
            </Button>
          </div>
        }
      >
        <AdminKVField label="Webhook 地址" htmlFor="feishu-webhook">
          <div className="max-w-xl space-y-2">
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
              placeholder={settings?.alert_webhook_set ? "已配置（输入新值可覆盖，停用请点右上角「停用」）" : "https://open.feishu.cn/open-apis/bot/v2/hook/…"}
            />
            {fieldErrors.webhook ? (
              <p id="feishu-webhook-error" className="text-xs font-medium text-rose-500" aria-live="polite">
                {fieldErrors.webhook}
              </p>
            ) : null}
          </div>
        </AdminKVField>
      </AdminPanel>

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
                  if (pendingConfirm.webhookOnly) {
                    runDisableWebhook(pendingConfirm.payload);
                  } else {
                    runSave(pendingConfirm.payload);
                  }
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
