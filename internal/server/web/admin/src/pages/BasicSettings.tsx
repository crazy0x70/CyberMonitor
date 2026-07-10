import { useEffect, useRef, useState, type ChangeEvent } from "react";
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
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
} from "@/lib/admin-types";
import { adminAppLocation } from "@/lib/admin-api";
import {
  adminActionButtonClass,
  adminDirtyBadgeClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminInputClass,
  adminMutedTextClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminPreviewPanelClass,
  adminSectionHeaderClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminStatEyebrowClass,
  adminSurfaceCardClass,
  adminTabsListClass,
  adminTabsTriggerClass,
  adminTextareaClass,
} from "@/lib/admin-ui";
import {
  buildAgentInstallCommand,
  buildAgentWindowsInstallCommand,
} from "@/lib/agent-install";
import { formatVersionLabel, getErrorMessage } from "@/lib/admin-format";
import { cn } from "@/lib/utils";

export interface BasicSettingsProps {
  settings: SettingsView | null;
  onDirtyChange?: (dirty: boolean) => void;
  onSave: (payload: Record<string, unknown>) => Promise<SettingsView>;
  onExport: () => Promise<void>;
  onImport: (payload: Record<string, unknown>) => Promise<ConfigImportResponse>;
  systemUpdateInfo: SystemUpdateInfo | null;
  refreshingSystemUpdate: boolean;
  startingSystemUpdate: boolean;
  onRefreshSystemUpdate: () => Promise<void>;
  onTriggerSystemUpdate: () => Promise<void>;
}

function parseJSONFile(file: File) {
  return file.text().then((text) => JSON.parse(text) as Record<string, unknown>);
}

const overviewLabelClass = adminStatEyebrowClass;

const panelCardClass = cn("overflow-hidden gap-0 py-0", adminSurfaceCardClass);

const panelCardHeaderClass = cn("border-b px-6 py-5", adminSectionHeaderClass);

const compactConfirmContentClass = cn(adminDialogContentClass, "gap-0");

const compactConfirmHeaderClass = cn(adminDialogHeaderClass, "border-b-0 pb-3");

const compactConfirmFooterClass = cn(adminDialogFooterClass, "border-t-0 bg-transparent pt-0");

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

function adminAuthPayload(draft: AdminAuthDraft) {
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
    loginFailLimit: String(settings?.login_fail_limit || 0),
    loginFailWindow: toMinuteFieldValue(settings?.login_fail_window_sec),
    loginLockMinutes: toMinuteFieldValue(settings?.login_lock_sec),
    adminAuth: adminAuthDraft(settings),
  };
}

type BasicSettingsDraft = ReturnType<typeof basicSettingsDraft>;

function basicSettingsDraftSignature(draft: BasicSettingsDraft) {
  return JSON.stringify(draft);
}

function basicSettingsSourceSignature(settings: SettingsView | null) {
  return basicSettingsDraftSignature(basicSettingsDraft(settings));
}

function applyBasicSettingsDraft(
  draft: BasicSettingsDraft,
  setters: {
    setAdminPath: (value: string) => void;
    setAdminUser: (value: string) => void;
    setAdminPass: (value: string) => void;
    setTurnstileSiteKey: (value: string) => void;
    setTurnstileSecretKey: (value: string) => void;
    setAgentToken: (value: string) => void;
    setAgentEndpoint: (value: string) => void;
    setSiteTitle: (value: string) => void;
    setSiteIcon: (value: string) => void;
    setSiteBackgroundImage: (value: string) => void;
    setHomeTitle: (value: string) => void;
    setHomeSubtitle: (value: string) => void;
    setLocale: (value: string) => void;
    setLoginFailLimit: (value: string) => void;
    setLoginFailWindow: (value: string) => void;
    setLoginLockMinutes: (value: string) => void;
    setAdminAuthDraft: (value: AdminAuthDraft) => void;
  },
) {
  setters.setAdminPath(draft.adminPath);
  setters.setAdminUser(draft.adminUser);
  setters.setAdminPass("");
  setters.setTurnstileSiteKey(draft.turnstileSiteKey);
  setters.setTurnstileSecretKey(draft.turnstileSecretKey);
  setters.setAgentToken(draft.agentToken);
  setters.setAgentEndpoint(draft.agentEndpoint);
  setters.setSiteTitle(draft.siteTitle);
  setters.setSiteIcon(draft.siteIcon);
  setters.setSiteBackgroundImage(draft.siteBackgroundImage);
  setters.setHomeTitle(draft.homeTitle);
  setters.setHomeSubtitle(draft.homeSubtitle);
  setters.setLocale(draft.locale);
  setters.setLoginFailLimit(draft.loginFailLimit);
  setters.setLoginFailWindow(draft.loginFailWindow);
  setters.setLoginLockMinutes(draft.loginLockMinutes);
  setters.setAdminAuthDraft(draft.adminAuth);
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
  const [adminPath, setAdminPath] = useState("");
  const [adminUser, setAdminUser] = useState("");
  const [adminPass, setAdminPass] = useState("");
  const [turnstileSiteKey, setTurnstileSiteKey] = useState("");
  const [turnstileSecretKey, setTurnstileSecretKey] = useState("");
  const [agentToken, setAgentToken] = useState("");
  const [agentEndpoint, setAgentEndpoint] = useState("");
  const [siteTitle, setSiteTitle] = useState("");
  const [siteIcon, setSiteIcon] = useState("");
  const [siteBackgroundImage, setSiteBackgroundImage] = useState("");
  const [homeTitle, setHomeTitle] = useState("");
  const [homeSubtitle, setHomeSubtitle] = useState("");
  const [locale, setLocale] = useState("zh-CN");
  const [loginFailLimit, setLoginFailLimit] = useState("0");
  const [loginFailWindow, setLoginFailWindow] = useState("");
  const [loginLockMinutes, setLoginLockMinutes] = useState("");
  const [adminAuthDraftValue, setAdminAuthDraftValue] = useState<AdminAuthDraft>(() => adminAuthDraft(null));
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [sourceSignature, setSourceSignature] = useState("");
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const isBusy = isSaving || isImporting;

  const currentDraftSignature = basicSettingsDraftSignature({
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
    loginFailLimit,
    loginFailWindow,
    loginLockMinutes,
    adminAuth: adminAuthDraftValue,
  });

  useEffect(() => {
    const nextSourceSignature = basicSettingsSourceSignature(settings);
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
    const draft = basicSettingsDraft(settings);
    applyBasicSettingsDraft(draft, {
      setAdminPath,
      setAdminUser,
      setAdminPass,
      setTurnstileSiteKey,
      setTurnstileSecretKey,
      setAgentToken,
      setAgentEndpoint,
      setSiteTitle,
      setSiteIcon,
      setSiteBackgroundImage,
      setHomeTitle,
      setHomeSubtitle,
      setLocale,
      setLoginFailLimit,
      setLoginFailWindow,
      setLoginLockMinutes,
      setAdminAuthDraft: setAdminAuthDraftValue,
    });
    setSourceSignature(nextSourceSignature);
    setIsDirty(false);
    setIsConfirmOpen(false);
  }, [adminPass, currentDraftSignature, isDirty, settings, sourceSignature]);

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

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
    setAdminAuthDraftValue((current) => ({ ...current, [field]: value }));
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

  const buildPayload = () => {
    const payload: Record<string, unknown> = {
      agent_token: agentToken.trim(),
      agent_endpoint: agentEndpoint.trim(),
      turnstile_site_key: turnstileSiteKey.trim(),
      site_title: siteTitle.trim(),
      site_icon: siteIcon.trim(),
      site_background_image: siteBackgroundImage.trim(),
      home_title: homeTitle.trim(),
      home_subtitle: homeSubtitle.trim(),
      locale: normalizeLocaleValue(locale),
      admin_auth: adminAuthPayload(adminAuthDraftValue),
    };

    if (turnstileSecretKey.trim()) {
      payload.turnstile_secret_key = turnstileSecretKey.trim();
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

  const persistSettings = async () => {
    if (isBusy) {
      return;
    }
    setIsSaving(true);
    try {
      const previousPath = settings?.admin_path || "";
      const previousUser = settings?.admin_user || "";
      const submittedAdminPass = adminPass.trim();
      const next = await onSave(buildPayload());
      const canonicalDraft = basicSettingsDraft(next);
      applyBasicSettingsDraft(canonicalDraft, {
        setAdminPath,
        setAdminUser,
        setAdminPass,
        setTurnstileSiteKey,
        setTurnstileSecretKey,
        setAgentToken,
        setAgentEndpoint,
        setSiteTitle,
        setSiteIcon,
        setSiteBackgroundImage,
        setHomeTitle,
        setHomeSubtitle,
        setLocale,
        setLoginFailLimit,
        setLoginFailWindow,
        setLoginLockMinutes,
        setAdminAuthDraft: setAdminAuthDraftValue,
      });
      setSourceSignature(basicSettingsDraftSignature(canonicalDraft));
      resetDirtyState(true);
      const messages = ["基础设置已保存"];
      if (next.admin_path && next.admin_path !== previousPath) {
        messages.push(`后台路径已更新为 ${next.admin_path}`);
        const nextAdminPath = adminAppLocation(next.admin_path);
        const currentLocation = `${window.location.pathname}${window.location.search}${window.location.hash}`;
        if (nextAdminPath && currentLocation !== nextAdminPath) {
          window.history.replaceState({}, "", nextAdminPath);
        }
      }
      if (next.admin_user && next.admin_user !== previousUser) {
        messages.push("管理员账号已变更，登录态已自动刷新");
      }
      if (submittedAdminPass) {
        messages.push("密码已更新，登录态已自动刷新");
      }
      toast.success(messages.join("；"));
    } catch (error) {
      toast.error(getErrorMessage(error, "保存基础设置失败"));
    } finally {
      setIsSaving(false);
    }
  };

  const handleImport = async (file: File) => {
    if (isBusy) {
      return;
    }
    setIsImporting(true);
    try {
      const payload = await parseJSONFile(file);
      const response = await onImport(payload);
      const messages = ["配置已导入"];
      if (response.settings?.admin_path) {
        messages.push(`后台路径已更新为 ${response.settings.admin_path}`);
      }
      toast.success(messages.join("；"));
      resetDirtyState();
    } catch (error) {
      toast.error(getErrorMessage(error, "导入配置失败"));
    } finally {
      setIsImporting(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const systemAlreadyLatest = Boolean(
    systemUpdateInfo?.supported !== false &&
      systemUpdateInfo?.latest_version &&
      !systemUpdateInfo.available,
  );
  const systemUpdateActionDisabled =
    startingSystemUpdate ||
    refreshingSystemUpdate ||
    systemUpdateInfo?.supported === false ||
    systemUpdateInfo?.updating ||
    systemAlreadyLatest;

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>基础设置</h1>
        </div>
        <div className={adminPageActionsClass}>
          {isDirty ? (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          ) : null}
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            disabled={!isDirty || isBusy}
            onClick={() => setIsConfirmOpen(true)}
          >
            {isSaving ? "保存中…" : "保存更改"}
          </Button>
          <AlertDialog open={isConfirmOpen} onOpenChange={setIsConfirmOpen}>
            <AlertDialogContent className={compactConfirmContentClass}>
              <AlertDialogHeader className={compactConfirmHeaderClass}>
                <AlertDialogTitle>确认保存基础设置？</AlertDialogTitle>
              </AlertDialogHeader>
              <AlertDialogFooter className={compactConfirmFooterClass}>
                <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                <AlertDialogAction onClick={persistSettings} className={adminPrimaryButtonClass}>
	                  确认保存
	                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </div>

      <Tabs defaultValue="security" className="w-full">
        <TabsList
          variant="line"
          className={cn(adminTabsListClass, "mx-auto sm:max-w-5xl sm:grid-cols-4")}
        >
          <TabsTrigger value="security" className={adminTabsTriggerClass}>
            安全控制
          </TabsTrigger>
          <TabsTrigger value="agent" className={adminTabsTriggerClass}>
            Agent 配置
          </TabsTrigger>
          <TabsTrigger value="display" className={adminTabsTriggerClass}>
            站点展示
          </TabsTrigger>
          <TabsTrigger value="backup" className={adminTabsTriggerClass}>
            备份与更新
          </TabsTrigger>
        </TabsList>

        <TabsContent value="security" className="mt-6 space-y-6">
          <div className="grid gap-6">
            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5 text-rose-500 dark:text-rose-300" />
                  后台入口与凭证
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-6 px-6 py-6">
                <div className="grid gap-2">
                  <Label htmlFor="admin-path">后台路径</Label>
                  <Input
                    id="admin-path"
                    name="admin-path"
                    autoComplete="off"
                    className={adminInputClass}
                    value={adminPath}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setAdminPath)}
                    placeholder="例如：/cm-admin…"
                  />
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="admin-user">管理员账号</Label>
                    <Input
                      id="admin-user"
                      name="admin-user"
                      className={adminInputClass}
                      autoComplete="username"
                      value={adminUser}
                      disabled={isBusy}
                      onChange={handleTextInputChange(setAdminUser)}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="admin-pass">新密码</Label>
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
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      留空则不修改当前密码。
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-emerald-500 dark:text-emerald-300" />
                  OAuth / OIDC 登录
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6 px-6 py-6">
                <div className="flex flex-col gap-3 rounded-[1.25rem] border border-slate-200 bg-white/50 p-4 dark:border-slate-800 dark:bg-slate-950/50 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <Label htmlFor="password-login-enabled" className="text-sm font-semibold">
                      启用密码登录
                    </Label>
                    <p className={`mt-1 text-xs ${adminMutedTextClass}`}>
                      关闭后只能通过已配置的 OAuth / OIDC 提供商登录。
                    </p>
                  </div>
                  <Switch
                    id="password-login-enabled"
                    checked={adminAuthDraftValue.passwordLoginEnabled}
                    disabled={isBusy}
                    onCheckedChange={(checked) => updateAdminAuthDraft("passwordLoginEnabled", Boolean(checked))}
                  />
                </div>

                <div className="grid gap-6 xl:grid-cols-2">
                  <div className="space-y-5 rounded-[1.25rem] border border-slate-200 bg-white/50 p-5 dark:border-slate-800 dark:bg-slate-950/50">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-emerald-500 dark:text-emerald-300" />
                        <div>
                          <Label htmlFor="github-oauth-enabled" className="text-sm font-semibold">
                            GitHub OAuth
                          </Label>
                          <p className={`mt-1 text-xs ${adminMutedTextClass}`}>
                            使用 GitHub 用户、邮箱或邮箱域名作为允许列表。
                          </p>
                        </div>
                      </div>
                      <Switch
                        id="github-oauth-enabled"
                        checked={adminAuthDraftValue.githubEnabled}
                        disabled={isBusy}
                        onCheckedChange={(checked) => updateAdminAuthDraft("githubEnabled", Boolean(checked))}
                      />
                    </div>

                    <div className="grid gap-4">
                      <div className="grid gap-2">
                        <Label htmlFor="github-display-name">显示名称</Label>
                        <Input
                          id="github-display-name"
                          name="github-display-name"
                          className={adminInputClass}
                          value={adminAuthDraftValue.githubDisplayName}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubDisplayName")}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-client-id">Client ID</Label>
                        <Input
                          id="github-client-id"
                          name="github-client-id"
                          autoComplete="off"
                          className={adminInputClass}
                          value={adminAuthDraftValue.githubClientID}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubClientID")}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-client-secret">Client Secret</Label>
                        <Input
                          id="github-client-secret"
                          name="github-client-secret"
                          type="password"
                          autoComplete="off"
                          className={adminInputClass}
                          value={adminAuthDraftValue.githubClientSecret}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubClientSecret")}
                          placeholder="留空则保留当前 Secret"
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-scopes">Scopes</Label>
                        <Textarea
                          id="github-scopes"
                          name="github-scopes"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.githubScopes}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubScopes")}
                          placeholder={"read:user\nuser:email"}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-allowed-logins">允许的 GitHub 用户名</Label>
                        <Textarea
                          id="github-allowed-logins"
                          name="github-allowed-logins"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.githubAllowedLogins}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubAllowedLogins")}
                          placeholder="octocat"
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-allowed-emails">允许的邮箱</Label>
                        <Textarea
                          id="github-allowed-emails"
                          name="github-allowed-emails"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.githubAllowedEmails}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubAllowedEmails")}
                          placeholder="admin@example.com"
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="github-allowed-domains">允许的邮箱域名</Label>
                        <Textarea
                          id="github-allowed-domains"
                          name="github-allowed-domains"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.githubAllowedEmailDomains}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("githubAllowedEmailDomains")}
                          placeholder="example.com"
                        />
                      </div>
                      <div className="flex items-center justify-between gap-4">
                        <Label htmlFor="github-require-verified-email" className="text-sm font-medium">
                          要求已验证邮箱
                        </Label>
                        <Switch
                          id="github-require-verified-email"
                          checked={adminAuthDraftValue.githubRequireVerifiedEmail}
                          disabled={isBusy}
                          onCheckedChange={(checked) => updateAdminAuthDraft("githubRequireVerifiedEmail", Boolean(checked))}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-5 rounded-[1.25rem] border border-slate-200 bg-white/50 p-5 dark:border-slate-800 dark:bg-slate-950/50">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-sky-500 dark:text-sky-300" />
                        <div>
                          <Label htmlFor="oidc-enabled" className="text-sm font-semibold">
                            自定义 OIDC
                          </Label>
                          <p className={`mt-1 text-xs ${adminMutedTextClass}`}>
                            支持 Google、Authelia、Zitadel 或其他 OpenID Connect Issuer。
                          </p>
                        </div>
                      </div>
                      <Switch
                        id="oidc-enabled"
                        checked={adminAuthDraftValue.oidcEnabled}
                        disabled={isBusy}
                        onCheckedChange={(checked) => updateAdminAuthDraft("oidcEnabled", Boolean(checked))}
                      />
                    </div>

                    <div className="grid gap-4">
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-display-name">显示名称</Label>
                        <Input
                          id="oidc-display-name"
                          name="oidc-display-name"
                          className={adminInputClass}
                          value={adminAuthDraftValue.oidcDisplayName}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcDisplayName")}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-issuer-url">Issuer URL</Label>
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
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-client-id">Client ID</Label>
                        <Input
                          id="oidc-client-id"
                          name="oidc-client-id"
                          autoComplete="off"
                          className={adminInputClass}
                          value={adminAuthDraftValue.oidcClientID}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcClientID")}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-client-secret">Client Secret</Label>
                        <Input
                          id="oidc-client-secret"
                          name="oidc-client-secret"
                          type="password"
                          autoComplete="off"
                          className={adminInputClass}
                          value={adminAuthDraftValue.oidcClientSecret}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcClientSecret")}
                          placeholder="留空则保留当前 Secret"
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-scopes">Scopes</Label>
                        <Textarea
                          id="oidc-scopes"
                          name="oidc-scopes"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.oidcScopes}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcScopes")}
                          placeholder={"openid\nemail\nprofile"}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-allowed-subjects">允许的 Subject</Label>
                        <Textarea
                          id="oidc-allowed-subjects"
                          name="oidc-allowed-subjects"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.oidcAllowedSubjects}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcAllowedSubjects")}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-allowed-emails">允许的邮箱</Label>
                        <Textarea
                          id="oidc-allowed-emails"
                          name="oidc-allowed-emails"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.oidcAllowedEmails}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcAllowedEmails")}
                          placeholder="admin@example.com"
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="oidc-allowed-domains">允许的邮箱域名</Label>
                        <Textarea
                          id="oidc-allowed-domains"
                          name="oidc-allowed-domains"
                          className={`min-h-[84px] ${adminTextareaClass}`}
                          value={adminAuthDraftValue.oidcAllowedEmailDomains}
                          disabled={isBusy}
                          onChange={handleAdminAuthInputChange("oidcAllowedEmailDomains")}
                          placeholder="example.com"
                        />
                      </div>
                      <div className="flex items-center justify-between gap-4">
                        <Label htmlFor="oidc-require-email-verified" className="text-sm font-medium">
                          要求 email_verified
                        </Label>
                        <Switch
                          id="oidc-require-email-verified"
                          checked={adminAuthDraftValue.oidcRequireEmailVerified}
                          disabled={isBusy}
                          onCheckedChange={(checked) => updateAdminAuthDraft("oidcRequireEmailVerified", Boolean(checked))}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2 dark:text-slate-50">
                  <ShieldAlert className="h-5 w-5 text-amber-500 dark:text-amber-300" />
                  防爆破策略
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 px-6 py-6">
                <div className="grid gap-2">
                  <Label htmlFor="login-fail-limit">失败次数上限</Label>
                  <Input
                    id="login-fail-limit"
                    name="login-fail-limit"
                    type="number"
                    min={0}
                    autoComplete="off"
                    className={adminInputClass}
                    value={loginFailLimit}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setLoginFailLimit)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="login-fail-window">统计窗口（分钟）</Label>
                  <Input
                    id="login-fail-window"
                    name="login-fail-window"
                    type="number"
                    min={1}
                    autoComplete="off"
                    className={adminInputClass}
                    value={loginFailWindow}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setLoginFailWindow)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="login-lock-minutes">锁定时长（分钟）</Label>
                  <Input
                    id="login-lock-minutes"
                    name="login-lock-minutes"
                    type="number"
                    min={1}
                    autoComplete="off"
                    className={adminInputClass}
                    value={loginLockMinutes}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setLoginLockMinutes)}
                  />
                </div>
              </CardContent>
            </Card>

            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-sky-500 dark:text-sky-300" />
                  Cloudflare Turnstile
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-5 px-6 py-6">
                <div className="grid gap-2">
                  <Label htmlFor="turnstile-site-key">Site Key</Label>
                  <Input
                    id="turnstile-site-key"
                    name="turnstile-site-key"
                    autoComplete="off"
                    className={adminInputClass}
                    value={turnstileSiteKey}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setTurnstileSiteKey)}
                    placeholder="0x4AAAAA…"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="turnstile-secret-key">Secret Key</Label>
                  <Input
                    id="turnstile-secret-key"
                    name="turnstile-secret-key"
                    type="password"
                    autoComplete="off"
                    className={adminInputClass}
                    value={turnstileSecretKey}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setTurnstileSecretKey)}
                    placeholder="0x4AAAAA…"
                  />
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="agent" className="mt-6 space-y-6">
          <div className="grid gap-6">
            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-5 w-5 text-emerald-500 dark:text-emerald-300" />
                  Agent 配置
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6 px-6 py-6">
                <div className="grid gap-2">
                  <Label htmlFor="agent-endpoint">Agent 对接地址</Label>
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
                    onChange={handleTextInputChange(setAgentEndpoint)}
                    placeholder="例如：https://monitor.example.com…"
                  />
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="agent-token">Agent Token</Label>
                  <Input
                    id="agent-token"
                    name="agent-token"
                    autoComplete="off"
                    className={cn(adminInputClass, "font-mono")}
                    value={agentToken}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setAgentToken)}
                    placeholder="例如：cm-agent-token-abc123…"
                  />
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    建议使用高强度随机 Token，修改后新接入 Agent 需使用新 Token。
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="display" className="mt-6 space-y-6">
          <div className="grid gap-6">
            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-indigo-500 dark:text-indigo-300" />
                  站点展示
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-5 px-6 py-6">
                <div className="grid gap-2">
                  <Label htmlFor="site-title">站点 Title</Label>
                  <Input
                    id="site-title"
                    name="site-title"
                    autoComplete="off"
                    className={adminInputClass}
                    value={siteTitle}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setSiteTitle)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="site-icon">站点 Icon</Label>
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
                    onChange={handleTextInputChange(setSiteIcon)}
                    placeholder="https://…"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="site-background-image">首页背景图</Label>
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
                    onChange={handleTextInputChange(setSiteBackgroundImage)}
                    placeholder="https://…"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="home-title">首页标题</Label>
                  <Input
                    id="home-title"
                    name="home-title"
                    autoComplete="off"
                    className={adminInputClass}
                    value={homeTitle}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setHomeTitle)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="home-subtitle">首页副标题</Label>
                  <Input
                    id="home-subtitle"
                    name="home-subtitle"
                    autoComplete="off"
                    className={adminInputClass}
                    value={homeSubtitle}
                    disabled={isBusy}
                    onChange={handleTextInputChange(setHomeSubtitle)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="site-locale">界面语言</Label>
                  <Select
                    value={locale}
                    disabled={isBusy}
                    onValueChange={(value) => {
                      if (isBusy) {
                        return;
                      }
                      setLocale(normalizeLocaleValue(value || undefined));
                      setIsDirty(true);
                    }}
                  >
                    <SelectTrigger id="site-locale" className={`w-full ${adminSelectTriggerClass}`}>
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
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="backup" className="mt-6 space-y-6">
          <div className="grid gap-6">
            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-slate-50">
                  <RefreshCw className="h-5 w-5 text-sky-500 dark:text-sky-300" />
                  服务端更新
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-5 px-6 py-6">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className={adminPreviewPanelClass}>
                    <p className={overviewLabelClass}>当前版本</p>
                    <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                      {formatVersionLabel(systemUpdateInfo?.current_version || settings?.version)}
                    </p>
                  </div>
                  <div className={adminPreviewPanelClass}>
                    <p className={overviewLabelClass}>最新版本</p>
                    <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                      {refreshingSystemUpdate && !systemUpdateInfo
                        ? "检查中…"
                        : systemAlreadyLatest
                          ? "当前已为最新版"
                        : systemUpdateInfo?.latest_version
                          ? formatVersionLabel(systemUpdateInfo.latest_version)
                          : "未检查"}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <Button
                    type="button"
                    variant="outline"
                    className={cn(adminActionButtonClass, "h-11 px-5")}
                    disabled={refreshingSystemUpdate || startingSystemUpdate}
                    onClick={() => {
                      onRefreshSystemUpdate().catch((error) => {
                        toast.error(getErrorMessage(error, "刷新服务端更新状态失败"));
                      });
                    }}
                  >
                    {refreshingSystemUpdate ? (
                      <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <RefreshCw className="mr-2 h-4 w-4" />
                    )}
                    检查更新
                  </Button>
                  <Button
                    type="button"
                    className={cn(adminPrimaryButtonClass, "h-11 px-5")}
                    disabled={systemUpdateActionDisabled}
                    onClick={() => {
                      onTriggerSystemUpdate().catch((error) => {
                        toast.error(getErrorMessage(error, "服务端更新操作失败"));
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
                      className={cn(adminActionButtonClass, "h-11 px-5")}
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
              </CardContent>
            </Card>

            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-rose-500 dark:text-rose-300" />
                  配置备份
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 px-6 py-6">
                <Button variant="outline" className={cn("w-full", adminActionButtonClass)} onClick={onExport}>
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
                      "w-full",
                      adminActionButtonClass,
                      "border-rose-200 bg-rose-50 text-rose-600 hover:bg-rose-100 dark:border-rose-800 dark:bg-rose-950 dark:text-rose-200 dark:hover:bg-rose-900",
                    )}
                    type="button"
                    disabled={isBusy}
                  >
                    <Upload className="mr-2 h-4 w-4" />
                    导入配置
                  </AlertDialogTrigger>
                  <AlertDialogContent className={compactConfirmContentClass}>
                    <AlertDialogHeader className={compactConfirmHeaderClass}>
                      <AlertDialogTitle>确认导入配置？当前环境凭证与 Agent 运行时任务会保留。</AlertDialogTitle>
                    </AlertDialogHeader>
                    <AlertDialogFooter className={compactConfirmFooterClass}>
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
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
