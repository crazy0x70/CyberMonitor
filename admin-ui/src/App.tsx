import { Suspense, lazy, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
  fetchSessionStatus,
  fetchSystemUpdateInfo,
  fetchPublicSnapshot,
  fetchSettings,
  getStoredAdminToken,
  readAdminBootPayload,
  importConfig,
  loginAdmin,
  logoutAdmin,
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
  AdminBootPayload,
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
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminLoadingCardClass,
  adminLoadingCardContentClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
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

declare global {
  interface Window {
    __CM_ADMIN_BOOT__?: AdminBootPayload;
  }
}

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

const THEME_STORAGE_KEY = "cm_theme_mode";
const PAGE_QUERY_KEY = "page";
const PAGE_VALUES = ["dashboard", "servers", "groups", "probes", "settings", "alerts", "ai"] as const;
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

function resolveInitialPage(): Page {
  if (typeof window === "undefined") {
    return "dashboard";
  }
  const page = new URLSearchParams(window.location.search).get(PAGE_QUERY_KEY);
  return PAGE_VALUES.includes(page as Page) ? (page as Page) : "dashboard";
}

function syncPageToURL(page: Page, replace = false) {
  if (typeof window === "undefined") {
    return;
  }
  const nextURL = new URL(window.location.href);
  if (page === "dashboard") {
    nextURL.searchParams.delete(PAGE_QUERY_KEY);
  } else {
    nextURL.searchParams.set(PAGE_QUERY_KEY, page);
  }
  const nextLocation = `${nextURL.pathname}${nextURL.search}${nextURL.hash}`;
  const currentLocation = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (nextLocation === currentLocation) {
    return;
  }
  if (replace) {
    window.history.replaceState({}, "", nextLocation);
  } else {
    window.history.pushState({}, "", nextLocation);
  }
}

function pageHref(page: Page) {
  if (typeof window === "undefined") {
    return page === "dashboard" ? "/" : `/?${PAGE_QUERY_KEY}=${page}`;
  }
  const nextURL = new URL(window.location.href);
  if (page === "dashboard") {
    nextURL.searchParams.delete(PAGE_QUERY_KEY);
  } else {
    nextURL.searchParams.set(PAGE_QUERY_KEY, page);
  }
  return `${nextURL.pathname}${nextURL.search}${nextURL.hash}`;
}

function resolveBrandTitle(settings: SettingsView | null, publicSettings: PublicSettings | null) {
  return (
    settings?.site_title ||
    publicSettings?.site_title ||
    settings?.home_title ||
    publicSettings?.home_title ||
    "CyberMonitor"
  ).trim();
}

function versionLabel(value?: string | null) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return "--";
  }
  return normalized.startsWith("v") ? normalized : `v${normalized}`;
}

function adminBrowserTitle(settings: SettingsView | null, publicSettings: PublicSettings | null) {
  const siteTitle = (settings?.site_title || publicSettings?.site_title || "CyberMonitor").trim() || "CyberMonitor";
  return `${siteTitle} 管理后台`;
}

function publicSettingsFromSettings(settings: SettingsView | null): PublicSettings | null {
  if (!settings) {
    return null;
  }
  return {
    site_title: settings.site_title,
    site_icon: settings.site_icon,
    home_title: settings.home_title,
    home_subtitle: settings.home_subtitle,
    version: settings.version,
    commit: settings.commit,
  };
}

function mergePublicSettings(
  settings: SettingsView | null,
  current: PublicSettings | null,
): PublicSettings | null {
  const next = publicSettingsFromSettings(settings);
  if (!next) {
    return current;
  }
  return {
    ...current,
    ...next,
  };
}

function SectionLoader({
  label = "正在加载页面…",
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
  const bootPayload = readAdminBootPayload();
  const [theme, setTheme] = useState<ThemeMode>(() => resolveInitialTheme());
  const [token, setToken] = useState(() => getStoredAdminToken());
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [loginConfig, setLoginConfig] = useState<LoginConfigResponse | null>(null);
  const [publicSettings, setPublicSettings] = useState<PublicSettings | null>(() => bootPayload.settings || null);
  const [systemUpdateInfo, setSystemUpdateInfo] = useState<SystemUpdateInfo | null>(null);
  const [nodes, setNodes] = useState<NodeView[]>([]);
  const [currentPage, setCurrentPage] = useState<Page>(() => resolveInitialPage());
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [loading, setLoading] = useState(Boolean(token));
  const [refreshingNodes, setRefreshingNodes] = useState(false);
  const [refreshingSystemUpdate, setRefreshingSystemUpdate] = useState(false);
  const [startingSystemUpdate, setStartingSystemUpdate] = useState(false);
  const [savingPage, setSavingPage] = useState<Page | null>(null);
  const [loginState, setLoginState] = useState<LoginState>(() => createLoginState());
  const [hasUnsavedPageChanges, setHasUnsavedPageChanges] = useState(false);
  const [pendingPageNavigation, setPendingPageNavigation] = useState<Page | null>(null);
  const [unsavedDialogOpen, setUnsavedDialogOpen] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const systemUpdatePollRef = useRef<number | null>(null);
  const isDark = theme === "dark";
  const siteIcon = (settings?.site_icon || publicSettings?.site_icon || "").trim();
  const siteTitle = resolveBrandTitle(settings, publicSettings);
  const deployedVersion = (settings?.version || publicSettings?.version || "").trim();
  const deployedVersionLabel = versionLabel(deployedVersion);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", isDark);
    root.setAttribute("data-theme", theme);
    root.style.colorScheme = theme;
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [isDark, theme]);

  useEffect(() => {
    document.title = adminBrowserTitle(settings, publicSettings);
  }, [publicSettings, settings]);

  useEffect(() => {
    syncPageToURL(currentPage, true);
  }, [currentPage]);

  useEffect(() => {
    const handlePopState = () => {
      const nextPage = resolveInitialPage();
      if (nextPage === currentPage) {
        return;
      }
      if (hasUnsavedPageChanges) {
        syncPageToURL(currentPage, true);
        setPendingPageNavigation(nextPage);
        setUnsavedDialogOpen(true);
        return;
      }
      setCurrentPage(nextPage);
    };
    window.addEventListener("popstate", handlePopState);
    return () => {
      window.removeEventListener("popstate", handlePopState);
    };
  }, [currentPage, hasUnsavedPageChanges]);

  useEffect(() => {
    if (!hasUnsavedPageChanges) {
      return;
    }
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, [hasUnsavedPageChanges]);

  function toggleTheme() {
    setTheme((current) => (current === "light" ? "dark" : "light"));
  }

  function proceedToPage(page: Page) {
    syncPageToURL(page);
    setCurrentPage(page);
    setHasUnsavedPageChanges(false);
    setPendingPageNavigation(null);
    setUnsavedDialogOpen(false);
    setIsMobileMenuOpen(false);
  }

  function navigateToPage(page: Page) {
    if (page === currentPage) {
      setIsMobileMenuOpen(false);
      return;
    }
    if (hasUnsavedPageChanges) {
      setPendingPageNavigation(page);
      setUnsavedDialogOpen(true);
      setIsMobileMenuOpen(false);
      return;
    }
    proceedToPage(page);
  }

  function shouldHandleClientNavigation(event: MouseEvent<HTMLAnchorElement>) {
    return !(
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    );
  }

  function handleNavLinkClick(event: MouseEvent<HTMLAnchorElement>, page: Page) {
    if (!shouldHandleClientNavigation(event)) {
      return;
    }
    event.preventDefault();
    navigateToPage(page);
  }

  function handleLogout(nextLoginState?: Partial<LoginState>) {
    socketRef.current?.close();
    socketRef.current = null;
    setStoredAdminToken("");
    setToken("");
    setSettings(null);
    setSystemUpdateInfo(null);
    setNodes([]);
    setHasUnsavedPageChanges(false);
    setPendingPageNavigation(null);
    setUnsavedDialogOpen(false);
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
    const nodesPromise = fetchNodes(nextToken)
      .then((data) => ({ data }))
      .catch((error) => ({ error }));
    try {
      const settingsData = await fetchSettings(nextToken);
      setSettings(settingsData);
      setPublicSettings((current) => mergePublicSettings(settingsData, current));
      setStoredAdminToken("session");
      setToken("session");
      setLoading(false);
      const nodesResult = await nodesPromise;
      if ("error" in nodesResult) {
        const { error } = nodesResult;
        if (error instanceof AdminApiError && error.status === 401) {
          handleLogout({
            errorMessage: "节点数据拉取失败，当前登录态已失效，请重新登录。",
            errorType: "expired",
          });
          return;
        }
        toast.error(error instanceof Error ? error.message : "初始化节点数据失败");
        return;
      }
      setNodes(nodesResult.data.nodes || []);
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
      await loginAdmin(username, password, turnstileToken);
      setToken("session");
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

  async function handleUserLogout() {
    try {
      await logoutAdmin();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "退出登录失败");
      return;
    }
    handleLogout();
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
    if (!token || currentPage !== "settings") {
      return;
    }
    refreshSystemUpdate().catch((error) => {
      toast.error(error instanceof Error ? error.message : "加载服务端更新状态失败");
    });
  }, [currentPage, token]);

  useEffect(() => {
    if (systemUpdatePollRef.current != null) {
      window.clearInterval(systemUpdatePollRef.current);
      systemUpdatePollRef.current = null;
    }
    if (!token || !systemUpdateInfo?.updating) {
      return;
    }
    systemUpdatePollRef.current = window.setInterval(() => {
      refreshSystemUpdate().catch((error) => {
        toast.error(error instanceof Error ? error.message : "刷新服务端更新状态失败");
      });
    }, 1500);
    return () => {
      if (systemUpdatePollRef.current != null) {
        window.clearInterval(systemUpdatePollRef.current);
        systemUpdatePollRef.current = null;
      }
    };
  }, [systemUpdateInfo?.updating, token]);

  useEffect(() => {
    if (token) {
      return;
    }
    let cancelled = false;
    fetchSessionStatus()
      .then((result) => {
        if (!cancelled && result.authenticated) {
          setStoredAdminToken("session");
          setToken("session");
        }
      })
      .catch((error) => {
        if (!cancelled) {
          toast.error(error instanceof Error ? error.message : "恢复登录会话失败");
        }
      });
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
          width={40}
          height={40}
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
      setPublicSettings((current) => mergePublicSettings(data, current));
      setStoredAdminToken("session");
      setToken("session");
      const nextNodes = await fetchNodes("session");
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
        setPublicSettings((current) => mergePublicSettings(data.settings || null, current));
      }
      setStoredAdminToken("session");
      setToken("session");
      const snapshot = await fetchNodes("session");
      setNodes(snapshot.nodes || []);
      if (data.settings?.admin_path) {
        window.history.replaceState({}, "", data.settings.admin_path);
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
      if (data.current_version) {
        setSettings((current) => (current ? { ...current, version: data.current_version } : current));
        setPublicSettings((current) =>
          current ? { ...current, version: data.current_version } : current,
        );
      }
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
        await refreshSystemUpdate(true);
      } else {
        toast.success(`服务端更新已开始，目标版本 ${data.target_version || "latest"}`);
        setSystemUpdateInfo((current) => ({
          current_version: current?.current_version || settings?.version || publicSettings?.version || "",
          latest_version: data.target_version || current?.latest_version || "",
          available: true,
          updating: true,
          supported: current?.supported ?? true,
          mode: current?.mode || "binary",
          message: current?.message,
          html_url: current?.html_url,
          published_at: current?.published_at,
          last_checked_at: current?.last_checked_at,
          last_started_at: Math.floor(Date.now() / 1000),
          last_finished_at: current?.last_finished_at,
        }));
        await refreshSystemUpdate(true);
      }
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
      <div className="m-4 flex h-[calc(100vh-2rem)] flex-col rounded-[2.5rem] border border-[var(--cm-sidebar-border)] bg-[var(--cm-sidebar-bg)] text-sidebar-foreground shadow-[var(--cm-panel-shadow)] backdrop-blur-3xl">
        <div className="border-b border-[var(--cm-sidebar-border)] px-6 py-8">
          <div className="flex items-center gap-4 text-[18px] font-black tracking-tighter text-sidebar-foreground">
            <div className={`${adminSidebarLogoChipClass} h-12 w-12 shrink-0 overflow-hidden shadow-lg`}>
              <BrandIcon sizeClass="h-7 w-7" />
            </div>
            <div className="min-w-0 flex-1 leading-tight overflow-hidden">
              <div className="truncate whitespace-nowrap bg-gradient-to-br from-slate-900 to-slate-500 bg-clip-text text-transparent dark:from-white dark:to-slate-400 italic">
                {siteTitle}
              </div>
              <div className="mt-1">
                <span className="inline-flex h-5 items-center rounded-full border border-slate-200 bg-slate-100/50 px-2.5 text-[8px] font-black tracking-[0.18em] text-slate-500 dark:border-slate-800 dark:bg-slate-900/50 dark:text-slate-400">
                  {deployedVersionLabel}
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
                      <a
                        key={item.id}
                        href={pageHref(item.id)}
                        className={`${adminSidebarNavItemClass} relative overflow-hidden ${
                          active
                            ? "border-transparent bg-[#1f5dff] text-white shadow-[0_14px_32px_-14px_rgba(31,93,255,0.55)] dark:bg-[#2563eb] dark:text-white"
                            : "border-transparent text-slate-500 hover:bg-[var(--cm-control-bg)] hover:text-slate-900 dark:text-slate-400 dark:hover:bg-[var(--cm-control-bg)] dark:hover:text-slate-100"
                        }`}
                        onClick={(event) => {
                          handleNavLinkClick(event, item.id);
                        }}
                      >
                        <span className={adminSidebarNavLabelClass}>
                          <Icon
                            className={`h-4 w-4 ${active ? "text-white" : "text-slate-400 group-hover:text-current"}`}
                          />
                          <span className="tracking-tight">{item.label}</span>
                        </span>
                        {active ? (
                          <div className="h-1.5 w-1.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
                        ) : null}
                      </a>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
        <div className="mt-auto border-t border-[var(--cm-sidebar-border)] p-5">
          <Button
            className={`${adminSidebarSecondaryButtonClass} group`}
            variant="outline"
            onClick={() => {
              void handleUserLogout();
            }}
          >
            <LogOut className="mr-3 h-4 w-4" />
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
          <Suspense fallback={<SectionLoader label="正在加载首页…" />}>
            <DashboardPage settings={settings} nodes={nodes} onNavigate={navigateToPage} />
          </Suspense>
        );
      case "servers":
        return (
          <Suspense fallback={<SectionLoader label="正在加载节点管理…" />}>
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
          <Suspense fallback={<SectionLoader label="正在加载分组管理…" />}>
            <GroupManagementPage
              groupTree={settings?.group_tree || []}
              nodes={nodes}
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(groupTree: GroupNode[]) =>
                updateSettings("groups", { group_tree: groupTree }).then(() => undefined)
              }
              saving={savingPage === "groups"}
            />
          </Suspense>
        );
      case "probes":
        return (
          <Suspense fallback={<SectionLoader label="正在加载探测设置…" />}>
            <ProbeSettingsPage
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(testCatalog) => updateSettings("probes", { test_catalog: testCatalog })}
              saving={savingPage === "probes"}
              testCatalog={settings?.test_catalog || []}
            />
          </Suspense>
        );
      case "settings":
        return (
          <Suspense fallback={<SectionLoader label="正在加载基础设置…" />}>
            <BasicSettingsPage
              onDirtyChange={setHasUnsavedPageChanges}
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
          <Suspense fallback={<SectionLoader label="正在加载通知告警…" />}>
            <NotificationAlertPage
              nodes={nodes}
              onDirtyChange={setHasUnsavedPageChanges}
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
          <Suspense fallback={<SectionLoader label="正在加载 AI 服务商…" />}>
            <AIProviderPage
              onFetchModels={(provider: string, config: AIProviderConfig) =>
                fetchAIModels(provider, config, token).then((data) => data.models || [])
              }
              onDirtyChange={setHasUnsavedPageChanges}
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
    hasUnsavedPageChanges,
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
      <Suspense fallback={<SectionLoader label="正在加载登录页…" />}>
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
      <a
        href="#admin-main-content"
        className="sr-only fixed left-4 top-4 z-[70] rounded-full bg-slate-950 px-4 py-2 text-sm font-medium text-white shadow-lg focus:not-sr-only focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 dark:bg-white dark:text-slate-950"
      >
        跳转到主要内容
      </a>
      <aside className="fixed inset-y-0 z-50 hidden w-72 flex-col md:flex">
        <NavContent />
      </aside>

      <header className="fixed left-0 right-0 top-0 z-50 flex h-16 items-center border-b border-[var(--cm-sidebar-border)] bg-[var(--cm-sidebar-bg)] px-6 backdrop-blur-3xl md:hidden">
        <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
          <SheetTrigger asChild>
            <Button
              aria-label="打开导航菜单"
              className={adminSidebarIconButtonClass}
              size="icon"
              variant="outline"
            >
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
            <div className="mt-0.5 text-[8px] font-black tracking-[0.18em] text-muted-foreground">
              {deployedVersionLabel}
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

      <main id="admin-main-content" className="relative flex min-h-screen flex-1 flex-col pt-20 md:pl-72 md:pt-4">
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
              <SectionLoader label="正在加载数据…" minHeightClass="min-h-[50vh]" />
            ) : (
              <div className="animate-in fade-in slide-in-from-bottom-6 duration-1000 ease-out fill-mode-both">
                {pageContent}
              </div>
            )}
          </div>
        </ScrollArea>
      </main>
      <AlertDialog
        open={unsavedDialogOpen}
        onOpenChange={(open) => {
          setUnsavedDialogOpen(open);
          if (!open) {
            setPendingPageNavigation(null);
          }
        }}
      >
        <AlertDialogContent className={adminDialogContentClass}>
          <AlertDialogHeader className={adminDialogHeaderClass}>
            <AlertDialogTitle>离开当前页面前先处理未保存内容？</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter className={adminDialogFooterClass}>
            <AlertDialogCancel className={`${adminDialogCancelClass} ${adminOutlineButtonClass}`}>
              继续编辑
            </AlertDialogCancel>
            <AlertDialogAction
              className={adminPrimaryButtonClass}
              onClick={() => {
                if (pendingPageNavigation) {
                  proceedToPage(pendingPageNavigation);
                } else {
                  setUnsavedDialogOpen(false);
                }
              }}
            >
              放弃未保存修改
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <Toaster position="top-center" theme={theme} />
    </div>
  );
}
