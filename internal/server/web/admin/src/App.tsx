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
  Languages,
  Loader2,
  LogOut,
  Menu,
  Monitor,
  Moon,
  ScrollText,
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
  addAdminUnauthorizedListener,
  adminAppLocation,
  adminOAuthLoginLocation,
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
  publicMonitorPath,
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
  NodeDeleteResponse,
  NodeProfilePayload,
  NodeView,
  PublicSettings,
  SettingsView,
  SystemUpdateInfo,
} from "@/lib/admin-types";
import { formatVersionLabel, getErrorMessage, upsertNodeView } from "@/lib/admin-format";
import {
  ADMIN_LOCALE_OPTIONS,
  adminBrowserTitleForLocale,
  adminText,
  normalizeAdminLocale,
  readStoredAdminLocale,
  translateAdminDOM,
  writeStoredAdminLocale,
  type AdminLocale,
} from "@/lib/admin-i18n";
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

type Page = "dashboard" | "servers" | "groups" | "probes" | "settings" | "alerts" | "ai" | "logs";
type LoginErrorType = "none" | "invalid" | "expired" | "locked";
type ThemeMode = "auto" | "light" | "dark";
type ResolvedTheme = "light" | "dark";

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
const ADMIN_THEME_OPTIONS: Array<{ value: ThemeMode; label: string }> = [
  { value: "auto", label: "跟随系统" },
  { value: "light", label: "浅色主题" },
  { value: "dark", label: "深色主题" },
];
const PAGE_QUERY_KEY = "page";
const PAGE_VALUES = ["dashboard", "servers", "groups", "probes", "settings", "alerts", "ai", "logs"] as const;
const LoginPage = lazy(() => import("./pages/Login"));
const DashboardPage = lazy(() => import("./pages/Dashboard"));
const ServerManagementPage = lazy(() => import("./pages/ServerManagement"));
const GroupManagementPage = lazy(() => import("./pages/GroupManagement"));
const ProbeSettingsPage = lazy(() => import("./pages/ProbeSettings"));
const BasicSettingsPage = lazy(() => import("./pages/BasicSettings"));
const NotificationAlertPage = lazy(() => import("./pages/NotificationAlert"));
const AIProviderPage = lazy(() => import("./pages/AIProvider"));
const AdminLogsPage = lazy(() => import("./pages/AdminLogs"));

function normalizeThemeMode(value: string | null | undefined): ThemeMode {
  const mode = String(value || "").trim().toLowerCase();
  return mode === "light" || mode === "dark" ? mode : "auto";
}

function resolveSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined") {
    return "light";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function resolveInitialThemeMode(): ThemeMode {
  if (typeof window === "undefined") {
    return "auto";
  }
  let storedTheme = "";
  try {
    storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY) || "";
  } catch {
    storedTheme = "";
  }
  return normalizeThemeMode(storedTheme);
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

function resolveInitialAdminLocale(settings: PublicSettings | null): AdminLocale {
  return readStoredAdminLocale() || normalizeAdminLocale(settings?.locale);
}

function normalizePublicIconURL(value: string | undefined | null) {
  const raw = String(value || "").trim();
  if (!raw || raw.startsWith("//") || raw.includes("\\") || /[\u0000-\u001F\u007F]/.test(raw)) {
    return "";
  }
  try {
    const parsed = new URL(raw, window.location.href);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? raw : "";
  } catch {
    return "";
  }
}

function publicSettingsFromSettings(settings: SettingsView | null): PublicSettings | null {
  if (!settings) {
    return null;
  }
  return {
    site_title: settings.site_title,
    site_icon: settings.site_icon,
    site_background_image: settings.site_background_image,
    home_title: settings.home_title,
    home_subtitle: settings.home_subtitle,
    locale: settings.locale,
    version: settings.version,
    commit: settings.commit,
  };
}

function publicSettingsFromSnapshot(settings: PublicSettings | undefined): PublicSettings | null {
  return settings || null;
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

function AdminLocaleSwitcher({
  activeLocaleOption,
  className = "",
  locale,
  onLocaleChange,
  t,
}: {
  activeLocaleOption: { value: AdminLocale; label: string; shortLabel: string };
  className?: string;
  locale: AdminLocale;
  onLocaleChange: (value: AdminLocale) => void;
  t: (text: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handlePointerDown = (event: PointerEvent) => {
      if (menuRef.current?.contains(event.target as Node)) {
        return;
      }
      setOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={menuRef} className="relative">
      <Button
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={t("界面语言")}
        className={`${adminThemeToggleButtonClass} ${className}`}
        size="icon"
        title={t("界面语言")}
        variant="outline"
        onClick={() => setOpen((current) => !current)}
      >
        <Languages className="h-4 w-4" />
      </Button>
      {open ? (
        <div
          role="menu"
          className="absolute right-0 top-full z-[90] mt-2 max-h-[min(320px,calc(100vh-5rem))] min-w-[9rem] overflow-y-auto rounded-xl border border-[var(--cm-control-border)] bg-popover p-1.5 text-popover-foreground shadow-xl"
        >
          {ADMIN_LOCALE_OPTIONS.map((item) => (
            <button
              key={item.value}
              aria-checked={item.value === locale}
              className="flex min-h-9 w-full cursor-pointer items-center justify-between rounded-lg px-3 py-2 text-left text-sm font-semibold outline-none hover:bg-accent focus-visible:bg-accent"
              role="menuitemradio"
              type="button"
              onClick={() => {
                setOpen(false);
                onLocaleChange(item.value);
              }}
            >
              <span>{item.label}</span>
              {item.value === locale ? <Languages className="h-4 w-4 text-sky-500" /> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function AdminThemeSwitcher({
  activeThemeOption,
  className = "",
  isDark,
  onThemeModeChange,
  t,
  themeMode,
}: {
  activeThemeOption: { value: ThemeMode; label: string };
  className?: string;
  isDark: boolean;
  onThemeModeChange: (value: ThemeMode) => void;
  t: (text: string) => string;
  themeMode: ThemeMode;
}) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const ThemeIcon = themeMode === "auto" ? Monitor : isDark ? Moon : Sun;

  useEffect(() => {
    if (!open) {
      return;
    }
    const handlePointerDown = (event: PointerEvent) => {
      if (menuRef.current?.contains(event.target as Node)) {
        return;
      }
      setOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={menuRef} className="relative">
      <Button
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={t("主题模式")}
        className={`${adminThemeToggleButtonClass} ${className}`}
        size="icon"
        title={t(activeThemeOption.label)}
        variant="outline"
        onClick={() => setOpen((current) => !current)}
      >
        <ThemeIcon className="h-4 w-4" />
      </Button>
      {open ? (
        <div
          role="menu"
          className="absolute right-0 top-full z-[90] mt-2 max-h-[min(320px,calc(100vh-5rem))] min-w-[9rem] overflow-y-auto rounded-xl border border-[var(--cm-control-border)] bg-popover p-1.5 text-popover-foreground shadow-xl"
        >
          {ADMIN_THEME_OPTIONS.map((item) => (
            <button
              key={item.value}
              aria-checked={item.value === themeMode}
              className="flex min-h-9 w-full cursor-pointer items-center justify-between rounded-lg px-3 py-2 text-left text-sm font-semibold outline-none hover:bg-accent focus-visible:bg-accent"
              role="menuitemradio"
              type="button"
              onClick={() => {
                setOpen(false);
                onThemeModeChange(item.value);
              }}
            >
              <span>{t(item.label)}</span>
              {item.value === themeMode ? <ThemeIcon className="h-4 w-4 text-sky-500" /> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export default function App() {
  const bootPayload = readAdminBootPayload();
  const [locale, setLocale] = useState<AdminLocale>(() => resolveInitialAdminLocale(bootPayload.settings || null));
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => resolveInitialThemeMode());
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => resolveSystemTheme());
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
  const socketRef = useRef<{ close: () => void } | null>(null);
  const systemUpdatePollRef = useRef<number | null>(null);
  const loadAllRequestRef = useRef(0);
  const theme = themeMode === "auto" ? systemTheme : themeMode;
  const isDark = theme === "dark";
  const siteIcon = normalizePublicIconURL(settings?.site_icon || publicSettings?.site_icon || "");
  const siteTitle = resolveBrandTitle(settings, publicSettings);
  const deployedVersion = (settings?.version || publicSettings?.version || "").trim();
  const deployedVersionLabel = formatVersionLabel(deployedVersion);
  const activeLocaleOption = ADMIN_LOCALE_OPTIONS.find((item) => item.value === locale) || ADMIN_LOCALE_OPTIONS[0];
  const activeThemeOption = ADMIN_THEME_OPTIONS.find((item) => item.value === themeMode) || ADMIN_THEME_OPTIONS[0];
  const t = (text: string) => adminText(locale, text);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", isDark);
    root.setAttribute("data-theme", theme);
    root.setAttribute("data-theme-mode", themeMode);
    root.style.colorScheme = theme;
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, themeMode);
    } catch {
      // storage may be disabled by browser policy
    }
  }, [isDark, theme, themeMode]);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) {
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handleSystemThemeChange = () => {
      setSystemTheme(resolveSystemTheme());
    };
    handleSystemThemeChange();
    media.addEventListener("change", handleSystemThemeChange);
    return () => {
      media.removeEventListener("change", handleSystemThemeChange);
    };
  }, []);

  useEffect(() => {
    document.title = adminBrowserTitleForLocale(locale, siteTitle);
  }, [locale, siteTitle]);

  useEffect(() => {
    const storedLocale = readStoredAdminLocale();
    if (storedLocale) {
      return;
    }
    setLocale(normalizeAdminLocale(settings?.locale || publicSettings?.locale));
  }, [publicSettings?.locale, settings?.locale]);

  useEffect(() => {
    document.documentElement.lang = locale;
    const root = document.body;
    if (!root) {
      return;
    }

    let frame = 0;
    const applyTranslations = () => {
      frame = 0;
      translateAdminDOM(root, locale);
    };

    applyTranslations();
    const observer = new MutationObserver(() => {
      if (frame) {
        return;
      }
      frame = window.requestAnimationFrame(applyTranslations);
    });
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["aria-label", "placeholder", "title"],
      characterData: true,
      childList: true,
      subtree: true,
    });

    return () => {
      observer.disconnect();
      if (frame) {
        window.cancelAnimationFrame(frame);
      }
    };
  }, [locale]);

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

  function handleThemeModeChange(value: ThemeMode) {
    setThemeMode(normalizeThemeMode(value));
  }

  async function handleAdminLocaleChange(value: AdminLocale) {
    const nextLocale = normalizeAdminLocale(value);
    setLocale(nextLocale);
    writeStoredAdminLocale(nextLocale);
    if (!token) {
      return;
    }
    try {
      const data = await saveSettings({ locale: nextLocale });
      setSettings(data);
      setPublicSettings((current) => mergePublicSettings(data, current));
      toast.success(adminText(nextLocale, "界面语言已更新"));
    } catch (error) {
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: adminText(nextLocale, "当前登录态已失效，请重新登录。"),
          errorType: "expired",
        });
        return;
      }
      toast.error(getErrorMessage(error, adminText(nextLocale, "界面语言更新失败")));
    }
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
    loadAllRequestRef.current += 1;
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
    setLoading(false);
    setLoginState(
      createLoginState(
        nextLoginState?.errorType || "none",
        nextLoginState?.errorMessage || "",
        nextLoginState?.retryAfterSec || 0,
      ),
    );
  }

  async function loadAll() {
    if (!token) {
      loadAllRequestRef.current += 1;
      setSettings(null);
      setNodes([]);
      setLoading(false);
      return;
    }

    const requestID = loadAllRequestRef.current + 1;
    loadAllRequestRef.current = requestID;
    const isCurrentLoad = () => loadAllRequestRef.current === requestID;
    setLoading(true);
    const nodesPromise = fetchNodes()
      .then((data) => ({ data }))
      .catch((error) => ({ error }));
    try {
      const settingsData = await fetchSettings();
      if (!isCurrentLoad()) {
        return;
      }
      setSettings(settingsData);
      setPublicSettings((current) => mergePublicSettings(settingsData, current));
      setStoredAdminToken("session");
      setToken("session");
      setLoading(false);
      const nodesResult = await nodesPromise;
      if (!isCurrentLoad()) {
        return;
      }
      if ("error" in nodesResult) {
        const { error } = nodesResult;
        if (error instanceof AdminApiError && error.status === 401) {
          handleLogout({
            errorMessage: "节点数据拉取失败，当前登录态已失效，请重新登录。",
            errorType: "expired",
          });
          return;
        }
        toast.error(getErrorMessage(error, "初始化节点数据失败"));
        return;
      }
      setNodes(nodesResult.data.nodes || []);
    } catch (error) {
      if (!isCurrentLoad()) {
        return;
      }
      if (error instanceof AdminApiError && error.status === 401) {
        handleLogout({
          errorMessage: "当前登录态已失效，请重新登录。",
          errorType: "expired",
        });
        return;
      }
      throw error;
    } finally {
      if (isCurrentLoad()) {
        setLoading(false);
      }
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
          createLoginState("invalid", error.message || "账号或密码错误，请检查后重试。"),
        );
        return;
      }

      setLoginState(
        createLoginState("invalid", getErrorMessage(error, "登录失败，请稍后重试。")),
      );
    }
  }

  function handleOAuthLogin(providerID: string) {
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    window.location.assign(adminOAuthLoginLocation(providerID, returnTo));
  }

  async function handleUserLogout() {
    try {
      await logoutAdmin();
    } catch (error) {
      toast.error(getErrorMessage(error, "退出登录失败"));
      return;
    }
    handleLogout();
  }

  useEffect(() => {
    if (!token) {
      return;
    }
    loadAll().catch((error) => {
      toast.error(getErrorMessage(error, "初始化后台数据失败"));
    });
  }, [token]);

  useEffect(() => {
    return addAdminUnauthorizedListener(() => {
      handleLogout({
        errorMessage: "当前登录态已失效，请重新登录。",
        errorType: "expired",
      });
    });
  }, []);

  useEffect(() => {
    if (!token || currentPage !== "settings") {
      return;
    }
    refreshSystemUpdate().catch((error) => {
      toast.error(getErrorMessage(error, "加载服务端更新状态失败"));
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
        toast.error(getErrorMessage(error, "刷新服务端更新状态失败"));
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
          toast.error(getErrorMessage(error, "恢复登录会话失败"));
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
          toast.error(getErrorMessage(error, "加载登录配置失败"));
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
    const socket = connectAdminSocket(
      (snapshot) => {
        if (Array.isArray(snapshot.nodes)) {
          setNodes(snapshot.nodes);
        }
        const snapshotSettings = publicSettingsFromSnapshot(snapshot.settings);
        if (snapshotSettings) {
          setPublicSettings((current) => ({ ...(current || {}), ...snapshotSettings }));
        }
      },
      (node) => {
        setNodes((current) => upsertNodeView(current, node));
      },
    );
    socketRef.current = socket;
    return () => {
      socket.close();
      if (socketRef.current === socket) {
        socketRef.current = null;
      }
    };
  }, [token]);

  const navigation = [
    {
      title: t("总览"),
      items: [{ id: "dashboard", label: t("首页"), icon: LayoutDashboard }],
    },
    {
      title: t("节点与策略"),
      items: [
        { id: "servers", label: t("节点管理"), icon: Server },
        { id: "groups", label: t("分组管理"), icon: FolderTree },
        { id: "probes", label: t("探测设置"), icon: Activity },
      ],
    },
    {
      title: t("系统配置"),
      items: [
        { id: "settings", label: t("基础设置"), icon: Settings },
        { id: "alerts", label: t("通知告警"), icon: Bell },
        { id: "ai", label: t("AI 服务商"), icon: Bot },
        { id: "logs", label: t("日志查看"), icon: ScrollText },
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
          referrerPolicy="no-referrer"
        />
      );
    }
    return <Activity className={sizeClass} />;
  }

  async function refreshNodesAfterMutation(successLabel: string, successLocale: AdminLocale = locale) {
    try {
      const snapshot = await fetchNodes();
      setNodes(snapshot.nodes || []);
    } catch (error) {
      const message = getErrorMessage(error, adminText(successLocale, "节点列表刷新失败"));
      toast.warning(
        successLocale === "en-US"
          ? `${successLabel}, but node refresh failed: ${message}`
          : `${successLabel}，但节点列表刷新失败：${message}`,
      );
    }
  }

  async function updateSettings(page: Page, payload: Record<string, unknown>) {
    setSavingPage(page);
    try {
      const data = await saveSettings(payload);
      setSettings(data);
      setPublicSettings((current) => mergePublicSettings(data, current));
      const nextLocale = normalizeAdminLocale(data.locale);
      setLocale(nextLocale);
      writeStoredAdminLocale(nextLocale);
      setStoredAdminToken("session");
      setToken("session");
      void refreshNodesAfterMutation(adminText(nextLocale, "设置已保存"), nextLocale);
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
    const data = await exportConfig();
    triggerDownload(data.blob, parseDownloadFilename(data.disposition));
  }

  async function handleImport(payload: Record<string, unknown>): Promise<ConfigImportResponse> {
    setSavingPage("settings");
    try {
      const data = await importConfig(payload);
      let nextLocale = locale;
      if (data.settings) {
        setSettings(data.settings);
        setPublicSettings((current) => mergePublicSettings(data.settings || null, current));
        nextLocale = normalizeAdminLocale(data.settings.locale);
        setLocale(nextLocale);
        writeStoredAdminLocale(nextLocale);
      }
      setStoredAdminToken("session");
      setToken("session");
      void refreshNodesAfterMutation(adminText(nextLocale, "配置已导入"), nextLocale);
      if (data.settings?.admin_path) {
        const nextAdminPath = adminAppLocation(data.settings.admin_path);
        if (nextAdminPath) {
          window.history.replaceState({}, "", nextAdminPath);
        }
      }
      return data;
    } finally {
      setSavingPage(null);
    }
  }

  async function handleRefreshNodes() {
    setRefreshingNodes(true);
    try {
      const snapshot = await fetchNodes();
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
      const data = await fetchSystemUpdateInfo();
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
      const data = await triggerSystemUpdate();
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
      await saveNodeProfile(nodeID, payload);
      void refreshNodesAfterMutation(t("节点配置已保存并下发"));
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

  async function handleDeleteNode(nodeID: string): Promise<NodeDeleteResponse> {
    try {
      const result = await deleteNodeProfile(nodeID);
      void refreshNodesAfterMutation(t("节点已删除"));
      if (result.history_error) {
        toast.warning(
          locale === "en-US"
            ? `${t("节点已删除")}, but history cleanup failed: ${result.history_error}`
            : `${t("节点已删除")}，但历史数据清理失败：${result.history_error}`,
        );
      }
      return result;
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
    const monitorHref = publicMonitorPath();

    return (
      <div className="m-4 flex h-[calc(100vh-2rem)] flex-col rounded-[2.5rem] border border-[var(--cm-sidebar-border)] bg-[var(--cm-sidebar-bg)] text-sidebar-foreground shadow-[var(--cm-panel-shadow)] backdrop-blur-3xl">
        <div className="border-b border-[var(--cm-sidebar-border)] px-6 py-8">
          <a
            aria-label={t("打开监控页")}
            className="flex items-center gap-4 rounded-2xl text-[18px] font-black tracking-tighter text-sidebar-foreground transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/45"
            href={monitorHref}
          >
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
          </a>
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
            <span className="tracking-tight">{t("退出登录")}</span>
          </Button>
        </div>
      </div>
    );
  }

  const pageContent = useMemo(() => {
    switch (currentPage) {
      case "dashboard":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载首页…")} />}>
            <DashboardPage settings={settings} nodes={nodes} onNavigate={navigateToPage} />
          </Suspense>
        );
      case "servers":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载节点管理…")} />}>
            <ServerManagementPage
              loading={refreshingNodes || loading}
              nodes={nodes}
              onCheckAgentUpdate={(nodeID) => fetchAgentUpdateInfo(nodeID)}
              onDeleteNode={handleDeleteNode}
              onDirtyChange={setHasUnsavedPageChanges}
              onRefresh={handleRefreshNodes}
              onSaveNode={handleSaveNode}
              onTriggerAgentUpdate={(nodeID) => triggerAgentUpdate(nodeID)}
              settings={settings}
            />
          </Suspense>
        );
      case "groups":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载分组管理…")} />}>
            <GroupManagementPage
              groupTree={settings?.group_tree || []}
              nodes={nodes}
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(groupTree: GroupNode[]) => updateSettings("groups", { group_tree: groupTree })}
              saving={savingPage === "groups"}
            />
          </Suspense>
        );
      case "probes":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载探测设置…")} />}>
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
          <Suspense fallback={<SectionLoader label={t("正在加载基础设置…")} />}>
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
          <Suspense fallback={<SectionLoader label={t("正在加载通知告警…")} />}>
            <NotificationAlertPage
              nodes={nodes}
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(payload) => updateSettings("alerts", payload)}
              onTest={(payload: AlertTestPayload) =>
                testAlertChannels(payload).then(() => undefined)
              }
              saving={savingPage === "alerts"}
              settings={settings}
            />
          </Suspense>
        );
      case "ai":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载 AI 服务商…")} />}>
            <AIProviderPage
              onFetchModels={(provider: string, config: AIProviderConfig) =>
                fetchAIModels(provider, config).then((data) => data.models || [])
              }
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(payload) => updateSettings("ai", payload)}
              onTestProvider={(provider: string, config: AIProviderConfig) =>
                testAIProvider(provider, config).then(() => undefined)
              }
              saving={savingPage === "ai"}
              settings={settings}
            />
          </Suspense>
        );
      case "logs":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载日志查看…")} />}>
            <AdminLogsPage />
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
    locale,
  ]);

  if (!token) {
    return (
      <Suspense fallback={<SectionLoader label={t("正在加载登录页…")} />}>
        <LoginPage
          errorMessage={loginState.errorMessage}
          errorType={loginState.errorType}
          homeSubtitle={publicSettings?.home_subtitle || "主机监控"}
          homeTitle={publicSettings?.home_title || "CyberMonitor"}
          onLogin={handleLogin}
          onOAuthLogin={handleOAuthLogin}
          oauthProviders={loginConfig?.oauth_providers || []}
          passwordLoginEnabled={loginConfig?.password_login_enabled !== false}
          retryAfterSec={loginState.retryAfterSec}
          theme={theme}
            topControls={
              <>
                <AdminLocaleSwitcher
                  activeLocaleOption={activeLocaleOption}
                  locale={locale}
                  t={t}
                  onLocaleChange={(nextLocale) => {
                    void handleAdminLocaleChange(nextLocale);
                  }}
                />
                <AdminThemeSwitcher
                  activeThemeOption={activeThemeOption}
                  isDark={isDark}
                  t={t}
                  themeMode={themeMode}
                  onThemeModeChange={handleThemeModeChange}
                />
              </>
            }
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
        {t("跳转到主要内容")}
      </a>
      <aside className="fixed inset-y-0 z-50 hidden w-72 flex-col md:flex">
        <NavContent />
      </aside>

      <header className="fixed left-0 right-0 top-0 z-50 flex h-16 items-center border-b border-[var(--cm-sidebar-border)] bg-[var(--cm-sidebar-bg)] px-6 backdrop-blur-3xl md:hidden">
        <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
          <SheetTrigger
            render={(
              <Button
                aria-label={t("打开导航菜单")}
                className={adminSidebarIconButtonClass}
                size="icon"
                variant="outline"
              >
                <Menu className="h-5 w-5" />
              </Button>
            )}
          />
          <SheetContent className="w-[310px] p-0 bg-transparent border-none shadow-none" side="left">
            <NavContent />
          </SheetContent>
        </Sheet>
        <a
          aria-label={t("打开监控页")}
          className="ml-4 flex min-w-0 items-center gap-3 rounded-xl font-black tracking-tighter text-foreground transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/45"
          href={publicMonitorPath()}
        >
          <div className={`${adminSidebarLogoChipClass} h-10 w-10 rounded-xl overflow-hidden shadow-lg`}>
            <BrandIcon sizeClass="h-5 w-5" />
          </div>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-[17px] italic">{siteTitle}</div>
            <div className="mt-0.5 text-[8px] font-black tracking-[0.18em] text-muted-foreground">
              {deployedVersionLabel}
            </div>
          </div>
        </a>
        <div className="ml-auto flex items-center gap-2">
          <AdminLocaleSwitcher
            activeLocaleOption={activeLocaleOption}
            locale={locale}
            t={t}
            onLocaleChange={(nextLocale) => {
              void handleAdminLocaleChange(nextLocale);
            }}
          />
          <AdminThemeSwitcher
            activeThemeOption={activeThemeOption}
            isDark={isDark}
            t={t}
            themeMode={themeMode}
            onThemeModeChange={handleThemeModeChange}
          />
        </div>
      </header>

      <main id="admin-main-content" className="relative flex min-h-screen flex-1 flex-col pt-20 md:pl-72 md:pt-4">
        <ScrollArea className="flex-1">
          <div className="w-full p-6 md:p-10 md:pt-10">
            <div className="mb-8 hidden justify-end gap-2 md:flex">
              <AdminLocaleSwitcher
                activeLocaleOption={activeLocaleOption}
                locale={locale}
                t={t}
                onLocaleChange={(nextLocale) => {
                  void handleAdminLocaleChange(nextLocale);
                }}
              />
              <AdminThemeSwitcher
                activeThemeOption={activeThemeOption}
                isDark={isDark}
                t={t}
                themeMode={themeMode}
                onThemeModeChange={handleThemeModeChange}
              />
            </div>
            {loading ? (
              <SectionLoader label={t("正在加载数据…")} minHeightClass="min-h-[50vh]" />
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
            <AlertDialogTitle>{t("离开当前页面前先处理未保存内容？")}</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter className={adminDialogFooterClass}>
            <AlertDialogCancel className={`${adminDialogCancelClass} ${adminOutlineButtonClass}`}>
              {t("继续编辑")}
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
              {t("放弃未保存修改")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <Toaster position="top-center" theme={theme} />
    </div>
  );
}
