import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminKVField } from "@/components/admin-kv-field";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  AlertTriangle,
  Download,
  ExternalLink,
  Globe,
  Key,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import type {
  ConfigImportResponse,
  SettingsView,
  SystemUpdateInfo,
  AdminAuthSettings,
  SettingsUpdate,
} from "@/lib/admin-types";
import { draftSignature, useAsyncAction, useDirtyNotification } from "@/lib/admin-hooks";
import { AdminApiError, adminAppLocation } from "@/lib/admin-api";
import {
  adminActionButtonClass,
  adminDangerOutlineButtonClass,
  adminDirtyBadgeClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminInputClass,
  adminMutedTextClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminTextareaClass,
} from "@/lib/admin-ui";
import { formatVersionLabel, getErrorMessage } from "@/lib/admin-format";
import { cn } from "@/lib/utils";

export interface BasicSettingsProps {
  settings: SettingsView | null;
  onDirtyChange?: (dirty: boolean) => void;
  onSave: (payload: SettingsUpdate) => Promise<SettingsView>;
  onExport: () => Promise<void>;
  onImport: (payload: Record<string, unknown>) => Promise<ConfigImportResponse>;
  systemUpdateInfo: SystemUpdateInfo | null;
  refreshingSystemUpdate: boolean;
  startingSystemUpdate: boolean;
  onRefreshSystemUpdate: () => Promise<void>;
  onTriggerSystemUpdate: () => Promise<void>;
}

function reportUpdateActionError(error: unknown, fallback: string) {
  if (error instanceof AdminApiError && error.status === 401) {
    return;
  }
  toast.error(getErrorMessage(error, fallback));
}

async function parseJSONFile(file: File) {
  try {
    return JSON.parse(await file.text()) as Record<string, unknown>;
  } catch {

    throw new Error("配置文件不是有效的 JSON");
  }
}

const toMinuteFieldValue = (seconds?: number) =>
  seconds ? String(Math.round(seconds / 60)) : "";

const localeOptions = [
  { value: "zh-CN", label: "简体中文" },
  { value: "en-US", label: "English" },
];

function normalizeLocaleValue(value?: string) {
  return value === "en-US" ? "en-US" : "zh-CN";
}

function joinListValue(values?: string[]) {
  return Array.isArray(values) ? values.join("\n") : "";
}

function parseListValue(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function adminAuthDraft(settings: SettingsView | null) {
  const adminAuth = settings?.admin_auth;
  const github = adminAuth?.github;
  const oidc = adminAuth?.oidc;
  return {
    passwordLoginEnabled: adminAuth?.password_login_enabled !== false,
    githubEnabled: Boolean(github?.enabled),
    githubDisplayName: github?.display_name || "GitHub",
    githubClientID: github?.client_id || "",
    githubClientSecret: "",
    githubScopes: joinListValue(github?.scopes),
    githubAllowedLogins: joinListValue(github?.allowed_logins),
    githubAllowedEmails: joinListValue(github?.allowed_emails),
    githubAllowedEmailDomains: joinListValue(github?.allowed_email_domains),
    githubRequireVerifiedEmail: Boolean(github?.require_verified_email),
    oidcEnabled: Boolean(oidc?.enabled),
    oidcDisplayName: oidc?.display_name || "OpenID Connect",
    oidcIssuerURL: oidc?.issuer_url || "",
    oidcClientID: oidc?.client_id || "",
    oidcClientSecret: "",
    oidcScopes: joinListValue(oidc?.scopes),
    oidcAllowedSubjects: joinListValue(oidc?.allowed_subjects),
    oidcAllowedEmails: joinListValue(oidc?.allowed_emails),
    oidcAllowedEmailDomains: joinListValue(oidc?.allowed_email_domains),
    oidcRequireEmailVerified: Boolean(oidc?.require_email_verified),
  };
}

type AdminAuthDraft = ReturnType<typeof adminAuthDraft>;

function adminAuthPayload(draft: AdminAuthDraft): AdminAuthSettings {
  return {
    password_login_enabled: draft.passwordLoginEnabled,
    github: {
      enabled: draft.githubEnabled,
      display_name: draft.githubDisplayName.trim(),
      client_id: draft.githubClientID.trim(),
      client_secret: draft.githubClientSecret.trim(),
      scopes: parseListValue(draft.githubScopes),
      allowed_logins: parseListValue(draft.githubAllowedLogins),
      allowed_emails: parseListValue(draft.githubAllowedEmails),
      allowed_email_domains: parseListValue(draft.githubAllowedEmailDomains),
      require_verified_email: draft.githubRequireVerifiedEmail,
    },
    oidc: {
      enabled: draft.oidcEnabled,
      display_name: draft.oidcDisplayName.trim(),
      issuer_url: draft.oidcIssuerURL.trim(),
      client_id: draft.oidcClientID.trim(),
      client_secret: draft.oidcClientSecret.trim(),
      scopes: parseListValue(draft.oidcScopes),
      allowed_subjects: parseListValue(draft.oidcAllowedSubjects),
      allowed_emails: parseListValue(draft.oidcAllowedEmails),
      allowed_email_domains: parseListValue(draft.oidcAllowedEmailDomains),
      require_email_verified: draft.oidcRequireEmailVerified,
    },
  };
}

function basicSettingsDraft(settings: SettingsView | null) {
  return {
    adminPath: settings?.admin_path || "",
    adminUser: settings?.admin_user || "",
    turnstileSiteKey: settings?.turnstile_site_key || "",
    turnstileSecretKey: settings?.turnstile_secret_key || "",
    agentToken: settings?.agent_token || "",
    agentEndpoint: settings?.agent_endpoint || "",
    siteTitle: settings?.site_title || "",
    siteIcon: settings?.site_icon || "",
    siteBackgroundImage: settings?.site_background_image || "",
    homeTitle: settings?.home_title || "",
    homeSubtitle: settings?.home_subtitle || "",
    locale: normalizeLocaleValue(settings?.locale),
    regionGroupEnabled: settings?.region_group_enabled !== false,
    loginFailLimit: String(settings?.login_fail_limit || 0),
    loginFailWindow: toMinuteFieldValue(settings?.login_fail_window_sec),
    loginLockMinutes: toMinuteFieldValue(settings?.login_lock_sec),
    adminAuth: adminAuthDraft(settings),
  };
}

type BasicSettingsDraft = ReturnType<typeof basicSettingsDraft>;

type BasicSettingsStringField = {
  [K in keyof BasicSettingsDraft]: BasicSettingsDraft[K] extends string ? K : never;
}[keyof BasicSettingsDraft];

const SETTINGS_SECTIONS = [
  { id: "settings-credentials", label: "后台入口与凭证" },
  { id: "settings-oauth", label: "OAuth / OIDC 登录" },
  { id: "settings-bruteforce", label: "防爆破策略" },
  { id: "settings-turnstile", label: "Cloudflare Turnstile" },
  { id: "settings-agent", label: "Agent 配置" },
  { id: "settings-site", label: "站点展示" },
  { id: "settings-update", label: "服务端更新" },
  { id: "settings-backup", label: "配置备份" },
] as const;

function KVSwitchField({
  id,
  checked,
  disabled,
  onCheckedChange,
  hint,
}: {
  id: string;
  checked: boolean;
  disabled?: boolean;
  onCheckedChange: (checked: boolean) => void;
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={onCheckedChange} />
      {hint ? <span className={`text-xs ${adminMutedTextClass}`}>{hint}</span> : null}
    </div>
  );
}

export default function BasicSettings({
  settings,
  onDirtyChange,
  onSave,
  onExport,
  onImport,
  systemUpdateInfo,
  refreshingSystemUpdate,
  startingSystemUpdate,
  onRefreshSystemUpdate,
  onTriggerSystemUpdate,
}: BasicSettingsProps) {

  const [basicDraft, setBasicDraft] = useState<BasicSettingsDraft>(() => basicSettingsDraft(settings));
  const [adminPass, setAdminPass] = useState("");
  const {
    adminPath,
    adminUser,
    turnstileSiteKey,
    turnstileSecretKey,
    agentToken,
    agentEndpoint,
    siteTitle,
    siteIcon,
    siteBackgroundImage,
    homeTitle,
    homeSubtitle,
    locale,
    regionGroupEnabled,
    loginFailLimit,
    loginFailWindow,
    loginLockMinutes,
    adminAuth: adminAuthDraftValue,
  } = basicDraft;
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [sourceSignature, setSourceSignature] = useState("");
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const isBusy = isSaving || isImporting;

  const currentDraftSignature = draftSignature(basicDraft);

  useEffect(() => {
    if (isBusy) {
      return;
    }
    const nextSourceSignature = draftSignature(basicSettingsDraft(settings));
    const currentDraftMatchesIncoming = !adminPass.trim() && currentDraftSignature === nextSourceSignature;
    if (isDirty && currentDraftMatchesIncoming) {
      setSourceSignature(nextSourceSignature);
      setIsDirty(false);
      setIsConfirmOpen(false);
      return;
    }
    if (nextSourceSignature === sourceSignature) {
      return;
    }
    if (isDirty) {
      setSourceSignature(nextSourceSignature);
      toast.warning("服务端基础设置已更新，当前未保存修改已保留。");
      return;
    }
    setBasicDraft(basicSettingsDraft(settings));
    setAdminPass("");
    setSourceSignature(nextSourceSignature);
    setIsDirty(false);
    setIsConfirmOpen(false);
  }, [adminPass, currentDraftSignature, isBusy, isDirty, settings, sourceSignature]);

  useDirtyNotification(onDirtyChange, isDirty);

  const updateBasicDraft = <TField extends keyof BasicSettingsDraft>(
    field: TField,
    value: BasicSettingsDraft[TField],
  ) => {
    if (isBusy) {
      return;
    }
    setBasicDraft((current) => ({ ...current, [field]: value }));
    setIsDirty(true);
  };

  const handleTextFieldChange =
    (field: BasicSettingsStringField) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      if (isBusy) {
        return;
      }
      updateBasicDraft(field, event.target.value);
      setIsDirty(true);
    };

  const handleTextInputChange =
    (setter: (value: string) => void) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      if (isBusy) {
        return;
      }
      setter(event.target.value);
      setIsDirty(true);
    };

  const updateAdminAuthDraft = <TField extends keyof AdminAuthDraft>(field: TField, value: AdminAuthDraft[TField]) => {
    if (isBusy) {
      return;
    }
    setBasicDraft((current) => ({ ...current, adminAuth: { ...current.adminAuth, [field]: value } }));
    setIsDirty(true);
  };

  const handleAdminAuthInputChange =
    <TField extends keyof AdminAuthDraft>(field: TField) =>
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      updateAdminAuthDraft(field, event.target.value as AdminAuthDraft[TField]);
    };

  const resetDirtyState = (closeConfirm = false) => {
    setIsDirty(false);
    if (closeConfirm) {
      setIsConfirmOpen(false);
    }
  };

  const buildPayload = (): SettingsUpdate => {
    const payload: SettingsUpdate = {
      agent_endpoint: agentEndpoint.trim(),
      turnstile_site_key: turnstileSiteKey.trim(),
      site_title: siteTitle.trim(),
      site_icon: siteIcon.trim(),
      site_background_image: siteBackgroundImage.trim(),
      home_title: homeTitle.trim(),
      home_subtitle: homeSubtitle.trim(),
      locale: normalizeLocaleValue(locale),
      region_group_enabled: regionGroupEnabled,
      admin_auth: adminAuthPayload(adminAuthDraftValue),
    };

    if (turnstileSecretKey.trim()) {
      payload.turnstile_secret_key = turnstileSecretKey.trim();
    }

    const currentAgentToken = (settings?.agent_token || "").trim();
    if (agentToken.trim() && agentToken.trim() !== currentAgentToken) {
      payload.agent_token = agentToken.trim();
    }
    if (adminPath.trim() !== (settings?.admin_path || "")) payload.admin_path = adminPath.trim();
    if (adminUser.trim() && adminUser.trim() !== settings?.admin_user) payload.admin_user = adminUser.trim();
    if (adminPass.trim()) payload.admin_pass = adminPass.trim();

    if (loginFailLimit.trim() !== "") payload.login_fail_limit = Number.parseInt(loginFailLimit, 10) || 0;
    if (loginFailWindow.trim() !== "") {
      payload.login_fail_window_sec = Math.max(Number.parseInt(loginFailWindow, 10) || 0, 0) * 60;
    }
    if (loginLockMinutes.trim() !== "") {
      payload.login_lock_sec = Math.max(Number.parseInt(loginLockMinutes, 10) || 0, 0) * 60;
    }

    return payload;
  };

  const runAction = useAsyncAction();

  const persistSettings = () => {
    if (isBusy) {
      return;
    }
    const previousPath = settings?.admin_path || "";
    const previousUser = settings?.admin_user || "";
    const submittedAdminPass = adminPass.trim();
    void runAction({
      action: () => onSave(buildPayload()),
      fallbackError: "保存基础设置失败",
      successToast: (next) => {
        const messages = ["基础设置已保存"];
        if (next.admin_path && next.admin_path !== previousPath) {
          messages.push(`后台路径已更新为 ${next.admin_path}`);
        }
        if (next.admin_user && next.admin_user !== previousUser) {
          messages.push("管理员账号已变更，登录态已自动刷新");
        }
        if (submittedAdminPass) {
          messages.push("密码已更新，登录态已自动刷新");
        }
        return messages.join("；");
      },
      onSuccess: (next) => {
        const canonicalDraft = basicSettingsDraft(next);
        setBasicDraft(canonicalDraft);
        setAdminPass("");
        setSourceSignature(draftSignature(canonicalDraft));
        resetDirtyState(true);
        if (next.admin_path && next.admin_path !== previousPath) {
          const nextAdminPath = adminAppLocation(next.admin_path);
          const currentLocation = `${window.location.pathname}${window.location.search}${window.location.hash}`;
          if (nextAdminPath && currentLocation !== nextAdminPath) {
            window.history.replaceState({}, "", nextAdminPath);
          }
        }
      },
      setBusy: setIsSaving,
    });
  };

  const handleImport = (file: File) => {
    if (isBusy) {
      return;
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    void runAction({
      action: async () => {
        const payload = await parseJSONFile(file);
        return onImport(payload);
      },
      fallbackError: "导入配置失败",
      successToast: (response) => {
        const messages = ["配置已导入"];
        if (response.settings?.admin_path) {
          messages.push(`后台路径已更新为 ${response.settings.admin_path}`);
        }
        return messages.join("；");
      },
      onSuccess: () => resetDirtyState(),
      setBusy: setIsImporting,
    });
  };

  const systemAlreadyLatest = Boolean(
    systemUpdateInfo?.supported !== false &&
      systemUpdateInfo?.latest_version &&
      !systemUpdateInfo.available,
  );

  const latestVersionLabel = (
    refreshing: boolean,
    alreadyLatest: boolean,
    info: SystemUpdateInfo | null,
  ) => {
    if (refreshing && !info) {
      return "检查中…";
    }
    if (alreadyLatest) {
      return "当前已为最新版";
    }
    return info?.latest_version ? formatVersionLabel(info.latest_version) : "未检查";
  };
  const systemUpdateActionDisabled =
    startingSystemUpdate ||
    refreshingSystemUpdate ||
    systemUpdateInfo?.supported === false ||
    systemUpdateInfo?.updating ||
    systemAlreadyLatest;

  const subHeadClass = "text-sm font-semibold text-slate-900 dark:text-neutral-50";
  const monoValueClass = "data-text text-sm font-medium text-slate-800 dark:text-neutral-200";

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="基础设置"
        actions={
          <>
            {isDirty ? (
              <span className={adminDirtyBadgeClass}>有未保存的修改</span>
            ) : null}
            <Button
              className={`${adminPrimaryButtonClass} h-9 px-4 font-medium`}
              disabled={!isDirty || isBusy}
              onClick={() => setIsConfirmOpen(true)}
            >
              {isSaving ? "保存中…" : "保存更改"}
            </Button>
            <AlertDialog open={isConfirmOpen} onOpenChange={setIsConfirmOpen}>
              <AlertDialogContent className={adminDialogContentClass}>
                <AlertDialogHeader className={adminDialogHeaderClass}>
                  <AlertDialogTitle>确认保存基础设置？</AlertDialogTitle>
                </AlertDialogHeader>
                <AlertDialogFooter className={adminDialogFooterClass}>
                  <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                  <AlertDialogAction onClick={persistSettings} className={adminPrimaryButtonClass}>
                    确认保存
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </>
        }
      />

      <nav
        aria-label="分区导航"
        className="sticky top-0 z-30 -mx-1 mb-2 flex flex-wrap gap-1.5 border-b border-[var(--separator)] bg-[var(--surface-base)]/95 px-1 py-2 backdrop-blur-sm"
      >
        {SETTINGS_SECTIONS.map((item) => (
          <a
            key={item.id}
            href={`#${item.id}`}
            className="rounded-full px-3 py-1 text-xs font-medium text-[var(--label-2)] transition-colors hover:bg-[var(--surface-2)] hover:text-foreground"
          >
            {item.label}
          </a>
        ))}
      </nav>

      <div className="max-w-3xl space-y-12">
        <AdminPanel
          id="settings-credentials"
          title="后台入口与凭证"
          icon={<Key className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="后台路径" htmlFor="admin-path">
              <Input
                id="admin-path"
                name="admin-path"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={adminPath}
                disabled={isBusy}
                onChange={handleTextFieldChange("adminPath")}
                placeholder="例如：/cm-admin…"
              />
            </AdminKVField>
            <AdminKVField label="管理员账号" htmlFor="admin-user">
              <Input
                id="admin-user"
                name="admin-user"
                className={adminInputClass}
                autoComplete="username"
                value={adminUser}
                disabled={isBusy}
                onChange={handleTextFieldChange("adminUser")}
              />
            </AdminKVField>
            <AdminKVField label="新密码" htmlFor="admin-pass">
              <div className="space-y-2">
                <Input
                  id="admin-pass"
                  name="admin-pass"
                  type="password"
                  className={adminInputClass}
                  autoComplete="new-password"
                  value={adminPass}
                  disabled={isBusy}
                  onChange={handleTextInputChange(setAdminPass)}
                />
                <p className={`text-xs ${adminMutedTextClass}`}>留空则不修改当前密码。</p>
              </div>
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-oauth"
          title="OAuth / OIDC 登录"
          icon={<ShieldCheck className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="启用密码登录" htmlFor="password-login-enabled">
              <KVSwitchField
                id="password-login-enabled"
                checked={adminAuthDraftValue.passwordLoginEnabled}
                disabled={isBusy}
                hint="关闭后只能通过已配置的 OAuth / OIDC 提供商登录。"
                onCheckedChange={(checked) => updateAdminAuthDraft("passwordLoginEnabled", Boolean(checked))}
              />
            </AdminKVField>
          </div>

          <div className="mt-10 space-y-6">
            <h3 className={subHeadClass}>GitHub OAuth</h3>
            <AdminKVField label="启用" htmlFor="github-oauth-enabled">
              <KVSwitchField
                id="github-oauth-enabled"
                checked={adminAuthDraftValue.githubEnabled}
                disabled={isBusy}
                hint="使用 GitHub 用户、邮箱或邮箱域名作为允许列表。"
                onCheckedChange={(checked) => updateAdminAuthDraft("githubEnabled", Boolean(checked))}
              />
            </AdminKVField>
            <AdminKVField label="显示名称" htmlFor="github-display-name">
              <Input
                id="github-display-name"
                name="github-display-name"
                className={adminInputClass}
                value={adminAuthDraftValue.githubDisplayName}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubDisplayName")}
              />
            </AdminKVField>
            <AdminKVField label="Client ID" htmlFor="github-client-id">
              <Input
                id="github-client-id"
                name="github-client-id"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={adminAuthDraftValue.githubClientID}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubClientID")}
              />
            </AdminKVField>
            <AdminKVField label="Client Secret" htmlFor="github-client-secret">
              <Input
                id="github-client-secret"
                name="github-client-secret"
                type="password"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={adminAuthDraftValue.githubClientSecret}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubClientSecret")}
                placeholder="留空则保留当前 Secret"
              />
              <p className={`text-xs ${adminMutedTextClass}`}>
                重置后留空 = 保留当前 Secret，不会清空。
              </p>
            </AdminKVField>
            <AdminKVField label="Scopes" htmlFor="github-scopes">
              <Textarea
                id="github-scopes"
                name="github-scopes"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.githubScopes}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubScopes")}
                placeholder={"read:user\nuser:email"}
              />
            </AdminKVField>
            <AdminKVField label="允许的用户名" htmlFor="github-allowed-logins">
              <Textarea
                id="github-allowed-logins"
                name="github-allowed-logins"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.githubAllowedLogins}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubAllowedLogins")}
                placeholder="octocat"
              />
            </AdminKVField>
            <AdminKVField label="允许的邮箱" htmlFor="github-allowed-emails">
              <Textarea
                id="github-allowed-emails"
                name="github-allowed-emails"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.githubAllowedEmails}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubAllowedEmails")}
                placeholder="admin@example.com"
              />
            </AdminKVField>
            <AdminKVField label="允许的邮箱域名" htmlFor="github-allowed-domains">
              <Textarea
                id="github-allowed-domains"
                name="github-allowed-domains"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.githubAllowedEmailDomains}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("githubAllowedEmailDomains")}
                placeholder="example.com"
              />
            </AdminKVField>
            <AdminKVField label="要求已验证邮箱" htmlFor="github-require-verified-email">
              <KVSwitchField
                id="github-require-verified-email"
                checked={adminAuthDraftValue.githubRequireVerifiedEmail}
                disabled={isBusy}
                onCheckedChange={(checked) => updateAdminAuthDraft("githubRequireVerifiedEmail", Boolean(checked))}
              />
            </AdminKVField>
          </div>

          <div className="mt-10 space-y-6">
            <h3 className={subHeadClass}>自定义 OIDC</h3>
            <AdminKVField label="启用" htmlFor="oidc-enabled">
              <KVSwitchField
                id="oidc-enabled"
                checked={adminAuthDraftValue.oidcEnabled}
                disabled={isBusy}
                hint="支持 Google、Authelia、Zitadel 或其他 OpenID Connect Issuer。"
                onCheckedChange={(checked) => updateAdminAuthDraft("oidcEnabled", Boolean(checked))}
              />
            </AdminKVField>
            <AdminKVField label="显示名称" htmlFor="oidc-display-name">
              <Input
                id="oidc-display-name"
                name="oidc-display-name"
                className={adminInputClass}
                value={adminAuthDraftValue.oidcDisplayName}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcDisplayName")}
              />
            </AdminKVField>
            <AdminKVField label="Issuer URL" htmlFor="oidc-issuer-url">
              <Input
                id="oidc-issuer-url"
                name="oidc-issuer-url"
                type="url"
                autoComplete="off"
                inputMode="url"
                spellCheck={false}
                className={adminInputClass}
                value={adminAuthDraftValue.oidcIssuerURL}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcIssuerURL")}
                placeholder="https://accounts.google.com"
              />
            </AdminKVField>
            <AdminKVField label="Client ID" htmlFor="oidc-client-id">
              <Input
                id="oidc-client-id"
                name="oidc-client-id"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={adminAuthDraftValue.oidcClientID}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcClientID")}
              />
            </AdminKVField>
            <AdminKVField label="Client Secret" htmlFor="oidc-client-secret">
              <Input
                id="oidc-client-secret"
                name="oidc-client-secret"
                type="password"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={adminAuthDraftValue.oidcClientSecret}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcClientSecret")}
                placeholder="留空则保留当前 Secret"
              />
              <p className={`text-xs ${adminMutedTextClass}`}>
                重置后留空 = 保留当前 Secret，不会清空。
              </p>
            </AdminKVField>
            <AdminKVField label="Scopes" htmlFor="oidc-scopes">
              <Textarea
                id="oidc-scopes"
                name="oidc-scopes"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.oidcScopes}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcScopes")}
                placeholder={"openid\nemail\nprofile"}
              />
            </AdminKVField>
            <AdminKVField label="允许的 Subject" htmlFor="oidc-allowed-subjects">
              <Textarea
                id="oidc-allowed-subjects"
                name="oidc-allowed-subjects"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.oidcAllowedSubjects}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcAllowedSubjects")}
              />
            </AdminKVField>
            <AdminKVField label="允许的邮箱" htmlFor="oidc-allowed-emails">
              <Textarea
                id="oidc-allowed-emails"
                name="oidc-allowed-emails"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.oidcAllowedEmails}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcAllowedEmails")}
                placeholder="admin@example.com"
              />
            </AdminKVField>
            <AdminKVField label="允许的邮箱域名" htmlFor="oidc-allowed-domains">
              <Textarea
                id="oidc-allowed-domains"
                name="oidc-allowed-domains"
                className={`min-h-[84px] ${adminTextareaClass}`}
                value={adminAuthDraftValue.oidcAllowedEmailDomains}
                disabled={isBusy}
                onChange={handleAdminAuthInputChange("oidcAllowedEmailDomains")}
                placeholder="example.com"
              />
            </AdminKVField>
            <AdminKVField label="要求 email_verified" htmlFor="oidc-require-email-verified">
              <KVSwitchField
                id="oidc-require-email-verified"
                checked={adminAuthDraftValue.oidcRequireEmailVerified}
                disabled={isBusy}
                onCheckedChange={(checked) => updateAdminAuthDraft("oidcRequireEmailVerified", Boolean(checked))}
              />
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-bruteforce"
          title="防爆破策略"
          icon={<ShieldAlert className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="失败次数上限" htmlFor="login-fail-limit">
              <Input
                id="login-fail-limit"
                name="login-fail-limit"
                type="number"
                min={0}
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={loginFailLimit}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginFailLimit")}
              />
            </AdminKVField>
            <AdminKVField label="统计窗口（分钟）" htmlFor="login-fail-window">
              <Input
                id="login-fail-window"
                name="login-fail-window"
                type="number"
                min={1}
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={loginFailWindow}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginFailWindow")}
              />
            </AdminKVField>
            <AdminKVField label="锁定时长（分钟）" htmlFor="login-lock-minutes">
              <Input
                id="login-lock-minutes"
                name="login-lock-minutes"
                type="number"
                min={1}
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={loginLockMinutes}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginLockMinutes")}
              />
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-turnstile"
          title="Cloudflare Turnstile"
          icon={<ShieldAlert className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="Site Key" htmlFor="turnstile-site-key">
              <Input
                id="turnstile-site-key"
                name="turnstile-site-key"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={turnstileSiteKey}
                disabled={isBusy}
                onChange={handleTextFieldChange("turnstileSiteKey")}
                placeholder="0x4AAAAA…"
              />
            </AdminKVField>
            <AdminKVField label="Secret Key" htmlFor="turnstile-secret-key">
              <Input
                id="turnstile-secret-key"
                name="turnstile-secret-key"
                type="password"
                autoComplete="off"
                className={`${adminInputClass} data-text`}
                value={turnstileSecretKey}
                disabled={isBusy}
                onChange={handleTextFieldChange("turnstileSecretKey")}
                placeholder="0x4AAAAA…"
              />
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-agent"
          title="Agent 配置"
          icon={<Terminal className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="Agent 对接地址" htmlFor="agent-endpoint">
              <Input
                id="agent-endpoint"
                name="agent-endpoint"
                type="url"
                autoComplete="off"
                inputMode="url"
                spellCheck={false}
                className={adminInputClass}
                value={agentEndpoint}
                disabled={isBusy}
                onChange={handleTextFieldChange("agentEndpoint")}
                placeholder="例如：https://monitor.example.com…"
              />
            </AdminKVField>
            <AdminKVField label="Agent Token" htmlFor="agent-token">
              <div className="space-y-2">
                <Input
                  id="agent-token"
                  name="agent-token"
                  autoComplete="off"
                  className={`${adminInputClass} data-text`}
                  value={agentToken}
                  disabled={isBusy}
                  onChange={handleTextFieldChange("agentToken")}
                  placeholder={settings?.agent_token_set ? "已配置（输入新值可更换）" : "例如：cm-agent-token-abc123…"}
                />
                <p className={`text-xs ${adminMutedTextClass}`}>
                  {settings?.agent_token_set
                    ? "当前 Token 已回显，可选中复制；输入新值并保存即完成更换，更换后新接入 Agent 需使用新 Token。"
                    : "建议使用高强度随机 Token，修改后新接入 Agent 需使用新 Token。"}
                </p>
              </div>
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-site"
          title="站点展示"
          icon={<Globe className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="站点 Title" htmlFor="site-title">
              <Input
                id="site-title"
                name="site-title"
                autoComplete="off"
                className={adminInputClass}
                value={siteTitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("siteTitle")}
              />
            </AdminKVField>
            <AdminKVField label="站点 Icon" htmlFor="site-icon">
              <Input
                id="site-icon"
                name="site-icon"
                type="url"
                autoComplete="off"
                inputMode="url"
                spellCheck={false}
                className={adminInputClass}
                value={siteIcon}
                disabled={isBusy}
                onChange={handleTextFieldChange("siteIcon")}
                placeholder="https://…"
              />
            </AdminKVField>
            <AdminKVField label="首页背景图" htmlFor="site-background-image">
              <Input
                id="site-background-image"
                name="site-background-image"
                type="url"
                autoComplete="off"
                inputMode="url"
                spellCheck={false}
                className={adminInputClass}
                value={siteBackgroundImage}
                disabled={isBusy}
                onChange={handleTextFieldChange("siteBackgroundImage")}
                placeholder="https://…"
              />
            </AdminKVField>
            <AdminKVField label="首页标题" htmlFor="home-title">
              <Input
                id="home-title"
                name="home-title"
                autoComplete="off"
                className={adminInputClass}
                value={homeTitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("homeTitle")}
              />
            </AdminKVField>
            <AdminKVField label="首页副标题" htmlFor="home-subtitle">
              <Input
                id="home-subtitle"
                name="home-subtitle"
                autoComplete="off"
                className={adminInputClass}
                value={homeSubtitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("homeSubtitle")}
              />
            </AdminKVField>
            <AdminKVField label="界面语言" htmlFor="site-locale">
              <Select
                value={locale}
                disabled={isBusy}
                onValueChange={(value) => {
                  if (isBusy) {
                    return;
                  }
                  updateBasicDraft("locale", normalizeLocaleValue(value || undefined));
                  setIsDirty(true);
                }}
              >
                <SelectTrigger id="site-locale" size="sm" className={adminSelectTriggerClass}>
                  <SelectValue placeholder="选择语言…">
                    {localeOptions.find((item) => item.value === locale)?.label || locale}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent className={adminSelectContentClass}>
                  {localeOptions.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </AdminKVField>
            <AdminKVField label="国家地区分组导航" htmlFor="region-group-enabled">
              <KVSwitchField
                id="region-group-enabled"
                checked={regionGroupEnabled}
                disabled={isBusy}
                hint="展示页按节点地区代码（C&R）二级分组。"
                onCheckedChange={(checked) => {
                  if (isBusy) {
                    return;
                  }
                  updateBasicDraft("regionGroupEnabled", Boolean(checked));
                  setIsDirty(true);
                }}
              />
            </AdminKVField>
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-update"
          title="服务端更新"
          icon={<RefreshCw className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="space-y-6">
            <AdminKVField label="当前版本">
              <span className={monoValueClass}>
                {formatVersionLabel(systemUpdateInfo?.current_version || settings?.version)}
              </span>
            </AdminKVField>
            <AdminKVField label="最新版本">
              <span
                className={cn(
                  "text-sm",
                  systemUpdateInfo?.latest_version && !systemAlreadyLatest && monoValueClass,
                  (!systemUpdateInfo?.latest_version || systemAlreadyLatest) &&
                    `font-normal ${adminMutedTextClass}`,
                )}
              >
                {latestVersionLabel(refreshingSystemUpdate, systemAlreadyLatest, systemUpdateInfo)}
              </span>
            </AdminKVField>
          </div>
          <div className="mt-6 flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              className={cn(adminActionButtonClass, "h-9 px-4")}
              disabled={refreshingSystemUpdate || startingSystemUpdate}
              onClick={() => {
                onRefreshSystemUpdate().catch((error) => {
                  reportUpdateActionError(error, "刷新服务端更新状态失败");
                });
              }}
            >
              <RefreshCw
                className={`mr-2 h-4 w-4 ${refreshingSystemUpdate ? "animate-spin" : ""}`}
              />
              检查更新
            </Button>
            <Button
              type="button"
              className={cn(adminPrimaryButtonClass, "h-9 px-4")}
              disabled={systemUpdateActionDisabled}
              onClick={() => {
                onTriggerSystemUpdate().catch((error) => {
                  reportUpdateActionError(error, "服务端更新操作失败");
                });
              }}
            >
              {startingSystemUpdate ? (
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              {systemUpdateInfo?.updating ? "更新中" : "立即更新"}
            </Button>
            {systemUpdateInfo?.html_url ? (
              <Button
                variant="outline"
                className={cn(adminActionButtonClass, "h-9 px-4")}
                nativeButton={false}
                render={(
                  <a
                    className="inline-flex items-center gap-2"
                    href={systemUpdateInfo.html_url}
                    rel="noreferrer"
                    target="_blank"
                  />
                )}
              >
                <ExternalLink className="h-4 w-4 shrink-0" />
                查看发布说明
              </Button>
            ) : null}
          </div>
        </AdminPanel>

        <AdminPanel
          id="settings-backup"
          title="配置备份"
          icon={<AlertTriangle className="h-4 w-4 text-[var(--label-3)]" />}
        >
          <div className="flex flex-wrap gap-3">
            <Button variant="outline" className={adminActionButtonClass} onClick={onExport}>
              <Download className="mr-2 h-4 w-4" />
              导出配置
            </Button>

            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(event) => {
                if (isBusy) {
                  return;
                }
                const file = event.target.files?.[0];
                if (file) {
                  void handleImport(file);
                }
              }}
            />

            <AlertDialog>
              <AlertDialogTrigger
                className={cn(
                  adminDangerOutlineButtonClass,
                  "inline-flex min-w-[110px] items-center justify-center px-4",
                )}
                type="button"
                disabled={isBusy}
              >
                <Upload className="mr-2 h-4 w-4" />
                导入配置
              </AlertDialogTrigger>
              <AlertDialogContent className={adminDialogContentClass}>
                <AlertDialogHeader className={adminDialogHeaderClass}>
                  <AlertDialogTitle>确认导入配置？当前环境凭证与 Agent 运行时任务会保留。</AlertDialogTitle>
                </AlertDialogHeader>
                <AlertDialogFooter className={adminDialogFooterClass}>
                  <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                  <AlertDialogAction
                    className={adminDialogDangerActionClass}
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isBusy}
                  >
                    {isImporting ? "导入中…" : "确认导入"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </AdminPanel>
      </div>
    </div>
  );
}
