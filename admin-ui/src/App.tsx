import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Bell,
  Bot,
  FolderTree,
  LayoutDashboard,
  Loader2,
  LogOut,
  Menu,
  Moon,
  Sun,
  Server,
  Settings,
} from "lucide-react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import {
  AdminApiError,
  connectAdminSocket,
  deleteNodeProfile,
  exportConfig,
  fetchAgentUpdateInfo,
  fetchLoginConfig,
  fetchAIModels,
  fetchNodes,
  fetchSystemUpdateInfo,
  fetchPublicSnapshot,
  fetchSettings,
  getStoredAdminToken,
  importConfig,
  loginAdmin,
  saveNodeProfile,
  saveSettings,
  setStoredAdminToken,
  triggerAgentUpdate,
  triggerSystemUpdate,
  testAlertChannels,
  testAIProvider,
} from "@/lib/admin-api";
import type {
  AlertTestPayload,
  AIProviderConfig,
  ConfigImportResponse,
  GroupNode,
  LoginConfigResponse,
  NodeProfilePayload,
  NodeView,
  PublicSettings,
  SettingsView,
  SystemUpdateInfo,
} from "@/lib/admin-types";
import {
  adminLoadingCardClass,
  adminLoadingCardContentClass,
  adminSidebarIconButtonClass,
  adminSidebarNavItemClass,
  adminSidebarNavLabelClass,
  adminSidebarLogoChipClass,
  adminSidebarSecondaryButtonClass,
  adminThemeToggleButtonClass,
} from "@/lib/admin-ui";

type Page = "dashboard" | "servers" | "groups" | "probes" | "settings" | "alerts" | "ai";
type LoginErrorType = "none" | "invalid" | "expired" | "locked";
type ThemeMode = "light" | "dark";

type LoginState = {
  errorMessage: string;
  errorType: LoginErrorType;
  retryAfterSec: number;
};

function parseDownloadFilename(disposition: string) {
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const simpleMatch = disposition.match(/filename="?([^";]+)"?/i);
  return simpleMatch?.[1] || "cybermonitor-config.json";
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function createLoginState(
  errorType: LoginErrorType = "none",
  errorMessage = "",
  retryAfterSec = 0,
): LoginState {
  return { errorMessage, errorType, retryAfterSec };
}

const THEME_STORAGE_KEY = "cm-admin-theme";
const LoginPage = lazy(() => import("./pages/Login"));
const DashboardPage = lazy(() => import("./pages/Dashboard"));
const ServerManagementPage = lazy(() => import("./pages/ServerManagement"));
const GroupManagementPage = lazy(() => import("./pages/GroupManagement"));
const ProbeSettingsPage = lazy(() => import("./pages/ProbeSettings"));
const BasicSettingsPage = lazy(() => import("./pages/BasicSettings"));
const NotificationAlertPage = lazy(() => import("./pages/NotificationAlert"));
const AIProviderPage = lazy(() => import("./pages/AIProvider"));

function resolveInitialTheme(): ThemeMode {
  if (typeof window === "undefined") {
    return "light";
  }
  const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (storedTheme === "light" || storedTheme === "dark") {
    return storedTheme;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function SectionLoader({
  label = "正在加载页面...",
  minHeightClass = "min-h-[40vh]",
}: {
  label?: string;
  minHeightClass?: string;
}) {
  return (
    <div className={`flex items-center justify-center ${minHeightClass}`}>
      <Card className={adminLoadingCardClass}>
        <CardContent className={adminLoadingCardContentClass}>
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
          {label}
        </CardContent>
      </Card>
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => resolveInitialTheme());
  const [token, setToken] = useState(() => getStoredAdminToken());
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [loginConfig, setLoginConfig] = useState<LoginConfigResponse | null>(null);
  const [publicSettings, setPublicSettings] = useState<PublicSettings | null>(null);
  const [systemUpdateInfo, setSystemUpdateInfo] = useState<SystemUpdateInfo | null>(null);
  const [nodes, setNodes] = useState<NodeView[]>([]);
  const [currentPage, setCurrentPage] = useState<Page>("dashboard");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [loading, setLoading] = useState(Boolean(token));
  const [refreshingNodes, setRefreshingNodes] = useState(false);
  const [refreshingSystemUpdate, setRefreshingSystemUpdate] = useState(false);
  const [startingSystemUpdate, setStartingSystemUpdate] = useState(false);
  const [savingPage, setSavingPage] = useState<Page | null>(null);
  const [loginState, setLoginState] = useState<LoginState>(() => createLoginState());
  const socketRef = useRef<WebSocket | null>(null);
  const isDark = theme === "dark";
  const siteIcon = (settings?.site_icon || publicSettings?.site_icon || "").trim();
  const siteTitle = (settings?.site_title || publicSettings?.site_title || "CyberMonitor").trim();
  const deployedVersion = (settings?.version || publicSettings?.version || "dev").trim();

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", isDark);
    root.style.colorScheme = theme;
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [isDark, theme]);

  function toggleTheme() {
    setTheme((current) => (current === "light" ? "dark" : "light"));
  }

  function handleLogout(nextLoginState?: Partial<LoginState>) {
    socketRef.current?.close();
    socketRef.current = null;
    setStoredAdminToken("");
    setToken("");
    setSettings(null);
    setSystemUpdateInfo(null);
    setNodes([]);
    setLoginState(
      createLoginState(
        nextLoginState?.errorType || "none",
        nextLoginState?.errorMessage || "",
        nextLoginState?.retryAfterSec || 0,
      ),
    );
  }

  async function loadAll(nextToken = token) {
    if (!nextToken) {
      setSettings(null);
      setNodes([]);
      return;
    }

    setLoading(true);
    try {
      const [settingsData, nodesData] = await Promise.all([
        fetchSettings(nextToken),
        fetchNodes(nextToken),
      ]);
      setSettings(settingsData);
      setNodes(nodesData.nodes || []);
      setToken(getStoredAdminToken());
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
        return;
      }
      throw error;
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(username: string, password: string, turnstileToken = "") {
    setLoginState(createLoginState());

    try {
      const data = await loginAdmin(username, password, turnstileToken);
      setToken(data.token);
    } catch (error) {
      setStoredAdminToken("");
      setToken("");

      if (error instanceof AdminApiError) {
        if (error.status === 429) {
          setLoginState(
            createLoginState(
              "locked",
              error.message || "连续登录失败次数过多，触发防爆破保护。",
              error.retryAfterSec || 0,
            ),
          );
          return;
        }

        setLoginState(
          createLoginState("invalid", error.message || "用户名或密码错误，请检查后重试。"),
        );
        return;
      }

      setLoginState(
        createLoginState("invalid", error instanceof Error ? error.message : "登录失败，请稍后重试。"),
      );
    }
  }

  useEffect(() => {
    if (!token) {
      return;
    }
    loadAll(token).catch((error) => {
      toast.error(error instanceof Error ? error.message : "初始化后台数据失败");
    });
  }, [token]);

  useEffect(() => {
    if (token) {
      return;
    }
    let cancelled = false;
    fetchLoginConfig()
      .then((config) => {
        if (!cancelled) {
          setLoginConfig(config);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setLoginConfig(null);
          toast.error(error instanceof Error ? error.message : "加载登录配置失败");
        }
      });
    fetchPublicSnapshot()
      .then((snapshot) => {
        if (!cancelled) {
          setPublicSettings(snapshot.settings || null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPublicSettings(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (!token) {
      socketRef.current?.close();
      socketRef.current = null;
      return;
    }
    const socket = connectAdminSocket(token, (snapshot) => {
      if (Array.isArray(snapshot.nodes)) {
        setNodes(snapshot.nodes);
      }
    });
    socketRef.current = socket;
    socket.addEventListener("close", () => {
      if (socketRef.current === socket) {
        socketRef.current = null;
      }
    });
    return () => {
      socket.close();
    };
  }, [token]);

  const navigation = [
    {
      title: "总览",
      items: [{ id: "dashboard", label: "首页", icon: LayoutDashboard }],
    },
    {
      title: "节点与策略",
      items: [
        { id: "servers", label: "节点管理", icon: Server },
        { id: "groups", label: "分组管理", icon: FolderTree },
        { id: "probes", label: "探测设置", icon: Activity },
      ],
    },
    {
      title: "系统配置",
      items: [
        { id: "settings", label: "基础设置", icon: Settings },
        { id: "alerts", label: "通知告警", icon: Bell },
        { id: "ai", label: "AI 服务商", icon: Bot },
      ],
    },
  ] as const;

  function BrandIcon({ sizeClass = "h-5 w-5" }: { sizeClass?: string }) {
    if (siteIcon) {
      return (
        <img
          alt={siteTitle}
          className={`h-full w-full object-cover ${sizeClass}`}
          src={siteIcon}
        />
      );
    }
    return <Activity className={sizeClass} />;
  }

  async function updateSettings(page: Page, payload: Record<string, unknown>) {
    setSavingPage(page);
    try {
      const data = await saveSettings(payload, token);
      setSettings(data);
      setToken(getStoredAdminToken());
      const nextNodes = await fetchNodes(getStoredAdminToken());
      setNodes(nextNodes.nodes || []);
      return data;
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "管理员凭证或会话已更新，请重新登录后继续。",
          errorType: "expired",
        });
      }
      throw error;
    } finally {
      setSavingPage(null);
    }
  }

  async function handleExport() {
    const data = await exportConfig(token);
    triggerDownload(data.blob, parseDownloadFilename(data.disposition));
  }

  async function handleImport(payload: Record<string, unknown>): Promise<ConfigImportResponse> {
    setSavingPage("settings");
    try {
      const data = await importConfig(payload, token);
      if (data.settings) {
        setSettings(data.settings);
      }
      setToken(getStoredAdminToken());
      const snapshot = await fetchNodes(getStoredAdminToken());
      setNodes(snapshot.nodes || []);
      if (data.settings?.admin_path) {
        window.history.replaceState({}, "", data.settings.admin_path);
      }
      if (data.reauth_required && !data.settings?.session_token) {
        handleLogout({
          errorMessage: "管理员账号已变更，当前会话无法继续复用。",
          errorType: "expired",
        });
      }
      return data;
    } finally {
      setSavingPage(null);
    }
  }

  async function handleRefreshNodes() {
    setRefreshingNodes(true);
    try {
      const snapshot = await fetchNodes(token);
      setNodes(snapshot.nodes || []);
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "节点数据拉取失败，当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
      }
      throw error;
    } finally {
      setRefreshingNodes(false);
    }
  }

  async function refreshSystemUpdate(force = false) {
    if (!token) {
      setSystemUpdateInfo(null);
      return;
    }
    setRefreshingSystemUpdate(true);
    try {
      const data = await fetchSystemUpdateInfo(token);
      setSystemUpdateInfo(data);
      if (force && data.message) {
        toast.message(data.message);
      }
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "服务端更新状态查询失败，当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
        return;
      }
      throw error;
    } finally {
      setRefreshingSystemUpdate(false);
    }
  }

  async function handleSystemUpdate() {
    if (!token) {
      return;
    }
    setStartingSystemUpdate(true);
    try {
      const data = await triggerSystemUpdate(token);
      if (data.status === "up_to_date") {
        toast.success("当前服务端已经是最新正式版");
      } else {
        toast.success(`服务端更新已开始，目标版本 ${data.target_version || "latest"}`);
      }
      window.setTimeout(() => {
        refreshSystemUpdate(true).catch((error) => {
          toast.error(error instanceof Error ? error.message : "刷新服务端更新状态失败");
        });
      }, 1200);
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "服务端更新失败，当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
        return;
      }
      throw error;
    } finally {
      setStartingSystemUpdate(false);
    }
  }

  async function handleSaveNode(nodeID: string, payload: NodeProfilePayload) {
    try {
      await saveNodeProfile(nodeID, payload, token);
      await handleRefreshNodes();
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "节点配置保存失败，当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
      }
      throw error;
    }
  }

  async function handleDeleteNode(nodeID: string) {
    try {
      await deleteNodeProfile(nodeID, token);
      await handleRefreshNodes();
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "节点删除失败，当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
      }
      throw error;
    }
  }

  function NavContent() {
    return (
      <div className="flex h-[calc(100vh-2rem)] flex-col m-4 rounded-[2.5rem] border border-sidebar-border bg-white/70 backdrop-blur-3xl text-sidebar-foreground shadow-[0_32px_64px_-32px_rgba(15,23,42,0.15)] dark:bg-slate-950/70 dark:shadow-[0_32px_64px_-32px_rgba(2,8,23,0.5)]">
        <div className="border-b border-sidebar-border/40 px-6 py-8">
          <div className="flex items-center gap-4 text-[18px] font-black tracking-tighter text-sidebar-foreground">
            <div className={`${adminSidebarLogoChipClass} h-12 w-12 shrink-0 overflow-hidden shadow-lg`}>
              <BrandIcon sizeClass="h-7 w-7" />
            </div>
            <div className="min-w-0 flex-1 leading-tight overflow-hidden">
              <div className="truncate whitespace-nowrap bg-gradient-to-br from-slate-900 to-slate-500 bg-clip-text text-transparent dark:from-white dark:to-slate-400 italic">
                {siteTitle}
              </div>
              <div className="mt-1">
                <span className="inline-flex h-5 items-center rounded-full border border-slate-200 bg-slate-100/50 px-2.5 text-[8px] font-black uppercase tracking-[0.22em] text-slate-500 dark:border-slate-800 dark:bg-slate-900/50 dark:text-slate-400">
                  v{deployedVersion}
                </span>
              </div>
            </div>
          </div>
        </div>
        <ScrollArea className="flex-1 px-5 py-8">
          <div className="space-y-9 pb-8">
            {navigation.map((group) => (
              <div key={group.title}>
                <h4 className="mb-4 px-4 text-[10px] font-black uppercase tracking-[0.3em] text-slate-400 dark:text-slate-500">
                  {group.title}
                </h4>
                <div className="space-y-1.5">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const active = currentPage === item.id;
                    return (
                      <button
                        key={item.id}
                        className={`${adminSidebarNavItemClass} relative overflow-hidden ${
                          active
                            ? "bg-slate-950 text-white shadow-[0_12px_24px_-8px_rgba(0,0,0,0.3)] dark:bg-white dark:text-slate-950 dark:shadow-[0_12px_24px_-8px_rgba(255,255,255,0.1)]"
                            : "border-transparent text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-900 dark:hover:text-slate-100"
                        }`}
                        onClick={() => {
                          setCurrentPage(item.id);
                          setIsMobileMenuOpen(false);
                        }}
                        type="button"
                      >
                        <span className={adminSidebarNavLabelClass}>
                          <Icon
                            className={`h-4 w-4 transition-transform group-hover:scale-110 ${
                              active ? (isDark ? "text-slate-950" : "text-white") : "text-slate-400 group-hover:text-current"
                            }`}
                          />
                          <span className="tracking-tight">{item.label}</span>
                        </span>
                        {active ? (
                          <div className="h-1.5 w-1.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
                        ) : null}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
        <div className="mt-auto p-5 border-t border-sidebar-border/40">
          <Button
            className={`${adminSidebarSecondaryButtonClass} group`}
            variant="outline"
            onClick={() => handleLogout()}
          >
            <LogOut className="mr-3 h-4 w-4 transition-transform group-hover:-translate-x-1" />
            <span className="tracking-tight">退出登录</span>
          </Button>
        </div>
      </div>
    );
  }

  const pageContent = useMemo(() => {
    switch (currentPage) {
      case "dashboard":
        return (
          <Suspense fallback={<SectionLoader label="正在加载首页..." />}>
            <DashboardPage settings={settings} nodes={nodes} onNavigate={setCurrentPage} />
          </Suspense>
        );
      case "servers":
        return (
          <Suspense fallback={<SectionLoader label="正在加载节点管理..." />}>
            <ServerManagementPage
              loading={refreshingNodes || loading}
              nodes={nodes}
              onCheckAgentUpdate={(nodeID) => fetchAgentUpdateInfo(nodeID, token)}
              onDeleteNode={handleDeleteNode}
              onRefresh={handleRefreshNodes}
              onSaveNode={handleSaveNode}
              onTriggerAgentUpdate={(nodeID) => triggerAgentUpdate(nodeID, token)}
              settings={settings}
            />
          </Suspense>
        );
      case "groups":
        return (
          <Suspense fallback={<SectionLoader label="正在加载分组管理..." />}>
            <GroupManagementPage
              groupTree={settings?.group_tree || []}
              nodes={nodes}
              onSave={(groupTree: GroupNode[]) =>
                updateSettings("groups", { group_tree: groupTree }).then(() => undefined)
              }
              saving={savingPage === "groups"}
            />
          </Suspense>
        );
      case "probes":
        return (
          <Suspense fallback={<SectionLoader label="正在加载探测设置..." />}>
            <ProbeSettingsPage
              onSave={(testCatalog) => updateSettings("probes", { test_catalog: testCatalog })}
              saving={savingPage === "probes"}
              testCatalog={settings?.test_catalog || []}
            />
          </Suspense>
        );
      case "settings":
        return (
          <Suspense fallback={<SectionLoader label="正在加载基础设置..." />}>
            <BasicSettingsPage
              onExport={handleExport}
              onImport={handleImport}
              onRefreshSystemUpdate={() => refreshSystemUpdate(true)}
              onSave={(payload) => updateSettings("settings", payload)}
              onTriggerSystemUpdate={handleSystemUpdate}
              refreshingSystemUpdate={refreshingSystemUpdate}
              settings={settings}
              startingSystemUpdate={startingSystemUpdate}
              systemUpdateInfo={systemUpdateInfo}
            />
          </Suspense>
        );
      case "alerts":
        return (
          <Suspense fallback={<SectionLoader label="正在加载通知告警..." />}>
            <NotificationAlertPage
              nodes={nodes}
              onSave={(payload) => updateSettings("alerts", payload).then(() => undefined)}
              onTest={(payload: AlertTestPayload) =>
                testAlertChannels(payload, token).then(() => undefined)
              }
              saving={savingPage === "alerts"}
              settings={settings}
            />
          </Suspense>
        );
      case "ai":
        return (
          <Suspense fallback={<SectionLoader label="正在加载 AI 服务商..." />}>
            <AIProviderPage
              onFetchModels={(provider: string, config: AIProviderConfig) =>
                fetchAIModels(provider, config, token).then((data) => data.models || [])
              }
              onSave={(payload) => updateSettings("ai", payload).then(() => undefined)}
              onTestProvider={(provider: string, config: AIProviderConfig) =>
                testAIProvider(provider, config, token).then(() => undefined)
              }
              settings={settings}
            />
          </Suspense>
        );
      default:
        return null;
    }
  }, [
    currentPage,
    loading,
    nodes,
    refreshingNodes,
    refreshingSystemUpdate,
    savingPage,
    settings,
    startingSystemUpdate,
    systemUpdateInfo,
    token,
  ]);

  if (!token) {
    return (
      <Suspense fallback={<SectionLoader label="正在加载登录页..." />}>
        <LoginPage
          errorMessage={loginState.errorMessage}
          errorType={loginState.errorType}
          homeSubtitle={publicSettings?.home_subtitle || "主机监控"}
          homeTitle={publicSettings?.home_title || "CyberMonitor"}
          onLogin={handleLogin}
          onToggleTheme={toggleTheme}
          retryAfterSec={loginState.retryAfterSec}
          theme={theme}
          turnstileSiteKey={loginConfig?.turnstile_enabled ? loginConfig.turnstile_site_key : ""}
        />
      </Suspense>
    );
  }

  return (
    <div className="flex min-h-screen font-sans text-foreground">
      <aside className="fixed inset-y-0 z-50 hidden w-72 flex-col md:flex">
        <NavContent />
      </aside>

      <header className="fixed left-0 right-0 top-0 z-50 flex h-16 items-center border-b border-border/40 bg-white/70 backdrop-blur-3xl px-6 md:hidden dark:bg-slate-950/70">
        <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
          <SheetTrigger asChild>
            <Button className={adminSidebarIconButtonClass} size="icon" variant="outline">
              <Menu className="h-5 w-5" />
            </Button>
          </SheetTrigger>
          <SheetContent className="w-[310px] p-0 bg-transparent border-none shadow-none" side="left">
            <NavContent />
          </SheetContent>
        </Sheet>
        <div className="ml-4 flex items-center gap-3 font-black tracking-tighter text-foreground">
          <div className={`${adminSidebarLogoChipClass} h-10 w-10 rounded-xl overflow-hidden shadow-lg`}>
            <BrandIcon sizeClass="h-5 w-5" />
          </div>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-[17px] italic">{siteTitle}</div>
            <div className="mt-0.5 text-[8px] font-black tracking-[0.2em] text-muted-foreground uppercase">
              v{deployedVersion}
            </div>
          </div>
        </div>
        <Button
          aria-label={isDark ? "切换到浅色模式" : "切换到深色模式"}
          className={`ml-auto ${adminThemeToggleButtonClass}`}
          variant="outline"
          size="icon"
          onClick={toggleTheme}
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </header>

      <main className="relative flex min-h-screen flex-1 flex-col pt-20 md:pl-72 md:pt-4">
        <ScrollArea className="flex-1">
          <div className="w-full p-6 md:p-10 md:pt-10">
            <div className="mb-8 hidden justify-end md:flex">
              <Button
                aria-label={isDark ? "切换到浅色模式" : "切换到深色模式"}
                className={adminThemeToggleButtonClass}
                variant="outline"
                size="icon"
                onClick={toggleTheme}
              >
                {isDark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
              </Button>
            </div>
            {loading ? (
              <SectionLoader label="正在加载数据..." minHeightClass="min-h-[50vh]" />
            ) : (
              <div className="animate-in fade-in slide-in-from-bottom-6 duration-1000 ease-out fill-mode-both">
                {pageContent}
              </div>
            )}
          </div>
        </ScrollArea>
      </main>
      <Toaster position="top-center" theme={theme} />
    </div>
  );
}
