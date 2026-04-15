import { useEffect, useRef, useState } from "react";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  AlertTriangle,
  Download,
  Eye,
  ExternalLink,
  Globe,
  Key,
  RefreshCw,
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
  adminStatEyebrowClass,
  adminSurfaceCardClass,
  adminTabsListClass,
  adminTabsTriggerClass,
} from "@/lib/admin-ui";
import {
  buildAgentInstallCommand,
  buildAgentWindowsInstallCommand,
} from "@/lib/agent-install";
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

function formatVersionText(value?: string) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return "--";
  }
  return normalized.startsWith("v") ? normalized : `v${normalized}`;
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
  const [homeTitle, setHomeTitle] = useState("");
  const [homeSubtitle, setHomeSubtitle] = useState("");
  const [loginFailLimit, setLoginFailLimit] = useState("0");
  const [loginFailWindow, setLoginFailWindow] = useState("");
  const [loginLockMinutes, setLoginLockMinutes] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    setAdminPath(settings?.admin_path || "");
    setAdminUser(settings?.admin_user || "");
    setAdminPass("");
    setTurnstileSiteKey(settings?.turnstile_site_key || "");
    setTurnstileSecretKey(settings?.turnstile_secret_key || "");
    setAgentToken(settings?.agent_token || "");
    setAgentEndpoint(settings?.agent_endpoint || "");
    setSiteTitle(settings?.site_title || "");
    setSiteIcon(settings?.site_icon || "");
    setHomeTitle(settings?.home_title || "");
    setHomeSubtitle(settings?.home_subtitle || "");
    setLoginFailLimit(String(settings?.login_fail_limit || 0));
    setLoginFailWindow(
      settings?.login_fail_window_sec ? String(Math.round(settings.login_fail_window_sec / 60)) : "",
    );
    setLoginLockMinutes(
      settings?.login_lock_sec ? String(Math.round(settings.login_lock_sec / 60)) : "",
    );
    setIsDirty(false);
    setIsConfirmOpen(false);
  }, [settings]);

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

  const buildPayload = () => {
    const payload: Record<string, unknown> = {
      agent_token: agentToken.trim(),
      agent_endpoint: agentEndpoint.trim(),
      turnstile_site_key: turnstileSiteKey.trim(),
      turnstile_secret_key: turnstileSecretKey.trim(),
      site_title: siteTitle.trim(),
      site_icon: siteIcon.trim(),
      home_title: homeTitle.trim(),
      home_subtitle: homeSubtitle.trim(),
    };

    if (adminPath.trim()) payload.admin_path = adminPath.trim();
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
    setIsSaving(true);
    try {
      const previousPath = settings?.admin_path || "";
      const previousUser = settings?.admin_user || "";
      const next = await onSave(buildPayload());
      setIsConfirmOpen(false);
      const messages = ["基础设置已保存"];
      if (next.admin_path && next.admin_path !== previousPath) {
        messages.push(`后台路径已更新为 ${next.admin_path}`);
        if (window.location.pathname !== next.admin_path) {
          window.history.replaceState({}, "", next.admin_path);
        }
      }
      if (next.admin_user && next.admin_user !== previousUser) {
        messages.push("管理员账号已变更，登录态已自动刷新");
      }
      if (adminPass.trim()) {
        messages.push("密码已更新，登录态已自动刷新");
      }
      toast.success(messages.join("；"));
      setIsDirty(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存基础设置失败");
    } finally {
      setIsSaving(false);
    }
  };

  const handleImport = async (file: File) => {
    setIsImporting(true);
    try {
      const payload = await parseJSONFile(file);
      const response = await onImport(payload);
      const messages = ["配置已导入"];
      if (response.settings?.admin_path) {
        messages.push(`后台路径已更新为 ${response.settings.admin_path}`);
      }
      if (response.reauth_required) {
        messages.push("管理员登录态已自动刷新");
      }
      toast.success(messages.join("；"));
      setIsDirty(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "导入配置失败");
    } finally {
      setIsImporting(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

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
            disabled={!isDirty || isSaving}
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
                    onChange={(event) => {
                      setAdminPath(event.target.value);
                      setIsDirty(true);
                    }}
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
                      onChange={(event) => {
                        setAdminUser(event.target.value);
                        setIsDirty(true);
                      }}
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
                      onChange={(event) => {
                        setAdminPass(event.target.value);
                        setIsDirty(true);
                      }}
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
                    onChange={(event) => {
                      setLoginFailLimit(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setLoginFailWindow(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setLoginLockMinutes(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setTurnstileSiteKey(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setTurnstileSecretKey(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setAgentEndpoint(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setAgentToken(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setSiteTitle(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setSiteIcon(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setHomeTitle(event.target.value);
                      setIsDirty(true);
                    }}
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
                    onChange={(event) => {
                      setHomeSubtitle(event.target.value);
                      setIsDirty(true);
                    }}
                  />
                </div>
              </CardContent>
            </Card>

            <Card className={panelCardClass}>
              <CardHeader className={panelCardHeaderClass}>
                <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-slate-50">
                  <Eye className="h-5 w-5 text-sky-500 dark:text-sky-300" />
                  展示预览
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 px-6 py-6">
                <div className={adminPreviewPanelClass}>
                  <p className={overviewLabelClass}>Title</p>
                  <p className="mt-3 text-xl font-semibold text-slate-900 dark:text-slate-100">{siteTitle || "CyberMonitor"}</p>
                  <p className={cn("mt-2 text-sm", adminMutedTextClass)}>{siteIcon || "--"}</p>
                </div>
                <div className={adminPreviewPanelClass}>
                  <p className={overviewLabelClass}>首页</p>
                  <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                    {homeTitle || siteTitle || "CyberMonitor"}
                  </p>
                  <p className={cn("mt-2 text-sm leading-6", adminMutedTextClass)}>{homeSubtitle || "--"}</p>
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
                      {formatVersionText(systemUpdateInfo?.current_version || settings?.version)}
                    </p>
                  </div>
                  <div className={adminPreviewPanelClass}>
                    <p className={overviewLabelClass}>最新版本</p>
                    <p className="mt-3 text-2xl font-semibold text-slate-900 dark:text-slate-100">
                      {refreshingSystemUpdate && !systemUpdateInfo
                        ? "检查中…"
                        : systemUpdateInfo?.latest_version
                          ? formatVersionText(systemUpdateInfo.latest_version)
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
                        toast.error(error instanceof Error ? error.message : "刷新服务端更新状态失败");
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
                    disabled={
                      startingSystemUpdate ||
                      refreshingSystemUpdate ||
                      systemUpdateInfo?.supported === false ||
                      systemUpdateInfo?.updating
                    }
                    onClick={() => {
                      onTriggerSystemUpdate().catch((error) => {
                        toast.error(error instanceof Error ? error.message : "服务端更新操作失败");
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
                  >
                    <Upload className="mr-2 h-4 w-4" />
                    导入配置（覆盖）
                  </AlertDialogTrigger>
                  <AlertDialogContent className={compactConfirmContentClass}>
                    <AlertDialogHeader className={compactConfirmHeaderClass}>
                      <AlertDialogTitle>确认导入并覆盖当前配置？</AlertDialogTitle>
                    </AlertDialogHeader>
                    <AlertDialogFooter className={compactConfirmFooterClass}>
                      <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                      <AlertDialogAction
                        className={adminDialogDangerActionClass}
                        onClick={() => fileInputRef.current?.click()}
                        disabled={isImporting}
                      >
                        {isImporting ? "导入中…" : "确认覆盖"}
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
