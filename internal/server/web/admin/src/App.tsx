import { Suspense, lazy, useCallback, useEffect, useId, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";
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
  AlertTriangle,
  Bell,
  Bot,
  ChevronRight,
  FolderTree,
  LayoutDashboard,
  Languages,
  LogOut,
  Menu,
  Moon,
  ScrollText,
  Sun,
  Server,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import {
  AdminSkeletonDashboard,
  AdminSkeletonList,
  AdminSkeletonSettings,
} from "@/components/admin-skeleton";
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
  GroupMove,
  GroupNode,
  LoginConfigResponse,
  NodeDeleteResponse,
  NodeProfilePayload,
  NodeView,
  BootPublicSettings,
  PublicSettings,
  SettingsView,
  SystemUpdateInfo,
  SettingsUpdate,
} from "@/lib/admin-types";
import {
  ADMIN_PAGE_QUERY_KEY,
  ADMIN_SECTION_QUERY_KEY,
  adminPageHref,
  formatVersionLabel,
  getErrorMessage,
  shouldHandleAdminNavigation,
  upsertNodeView,
  type AdminPage,
} from "@/lib/admin-format";
import {
  adminPageSections,
  hasAdminPageSections,
  resolveAdminSection,
} from "@/lib/admin-sections";
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
  adminSidebarSecondaryButtonClass,
  adminThemeToggleButtonClass,
} from "@/lib/admin-ui";

type Page = AdminPage;
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
const PAGE_QUERY_KEY = ADMIN_PAGE_QUERY_KEY;
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

// 初始分区来自 URL：section 查询参数优先，兼容旧锚点（#settings-oauth → oauth），
// 非法或缺省回落该页第一个分区；无分区的页面返回 null。
function resolveInitialSection(page: Page): string | null {
  if (typeof window === "undefined") {
    return null;
  }
  const section = new URLSearchParams(window.location.search).get(ADMIN_SECTION_QUERY_KEY);
  return resolveAdminSection(page, section, window.location.hash);
}

function syncPageToURL(page: Page, section: string | null, replace = false) {
  if (typeof window === "undefined") {
    return;
  }
  // new URL() 对畸形输入会抛 TypeError：这里只是同步查询串，解析失败就跳过同步，
  // 不能让它冒泡成未捕获异常打断导航。
  let nextURL: URL;
  try {
    nextURL = new URL(window.location.href);
  } catch {
    return;
  }
  if (page === "dashboard") {
    nextURL.searchParams.delete(PAGE_QUERY_KEY);
  } else {
    nextURL.searchParams.set(PAGE_QUERY_KEY, page);
  }
  // section 只在有分区的页面存在；不带分区的导航（跨页/无分区页）清除 section 与
  // hash，避免上一页的旧锚点/分区串到下一页（R7）。
  const normalizedSection = String(section || "").trim();
  if (normalizedSection) {
    nextURL.searchParams.set(ADMIN_SECTION_QUERY_KEY, normalizedSection);
  } else {
    nextURL.searchParams.delete(ADMIN_SECTION_QUERY_KEY);
  }
  nextURL.hash = "";
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

function publicSettingsFromSettings(settings: SettingsView | null): BootPublicSettings | null {
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
  current: BootPublicSettings | null,
): BootPublicSettings | null {
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
  variant = "list",
}: {
  label?: string;
  minHeightClass?: string;
  variant?: "list" | "settings" | "dashboard";
}) {
  // A-15 / 0.1.2：加载态改为与目标页面同构的骨架屏（替换原白卡片「正在加载…」）；
  // label 保留为骨架内的视觉隐藏文本；按页面类型选骨架——
  // settings / alerts / ai → 设置骨架，dashboard → 首页骨架，其余 → 列表骨架。
  return (
    <div className={minHeightClass}>
      {variant === "settings" ? (
        <AdminSkeletonSettings label={label} />
      ) : variant === "dashboard" ? (
        <AdminSkeletonDashboard label={label} />
      ) : (
        <AdminSkeletonList label={label} />
      )}
    </div>
  );
}

function AdminDropdownSwitcher<T extends string>({
  className = "",
  icon: Icon,
  ariaLabel,
  triggerTitle,
  options,
  activeValue,
  optionLabel,
  onSelect,
}: {
  className?: string;
  icon: LucideIcon;
  ariaLabel: string;
  triggerTitle: string;
  options: ReadonlyArray<{ value: T; label: string }>;
  activeValue: T;
  optionLabel: (label: string) => string;
  onSelect: (value: T) => void;
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
        aria-label={ariaLabel}
        className={`${adminThemeToggleButtonClass} ${className}`}
        size="icon"
        title={triggerTitle}
        variant="outline"
        onClick={() => setOpen((current) => !current)}
      >
        <Icon className="h-4 w-4" />
      </Button>
      {open ? (
        <div
          role="menu"
          // A-13 第 1 条：与 dropdown-menu.tsx 同款玻璃菜单 —— --mat-popover-bg + --blur-thick
          // + --hairline 边 + 上沿内高光 + --shadow-3，圆角 14px（P-02 第 3 条规格）
          className="absolute right-0 top-full z-[90] mt-2 max-h-[min(320px,calc(100vh-5rem))] min-w-[9rem] overflow-y-auto rounded-[14px] border border-[var(--hairline)] bg-[var(--mat-popover-bg)] p-1 text-popover-foreground shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-3)] [-webkit-backdrop-filter:var(--blur-thick)] [backdrop-filter:var(--blur-thick)]"
        >
          {options.map((item) => (
            <button
              key={item.value}
              aria-checked={item.value === activeValue}
              className="group flex min-h-9 w-full cursor-pointer items-center justify-between rounded-md px-2 py-2 text-left text-sm font-semibold outline-none hover:bg-accent hover:text-white focus-visible:bg-accent focus-visible:text-white"
              role="menuitemradio"
              type="button"
              onClick={() => {
                setOpen(false);
                onSelect(item.value);
              }}
            >
              <span>{optionLabel(item.label)}</span>
              {item.value === activeValue ? (
                <span aria-hidden="true" className="h-1.5 w-1.5 flex-none rounded-full bg-[var(--primary)] group-hover:bg-white group-focus-visible:bg-white" />
              ) : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function AdminLocaleSwitcher({
  className = "",
  locale,
  onLocaleChange,
  t,
}: {
  className?: string;
  locale: AdminLocale;
  onLocaleChange: (value: AdminLocale) => void;
  t: (text: string) => string;
}) {
  return (
    <AdminDropdownSwitcher
      activeValue={locale}
      ariaLabel={t("界面语言")}
      className={className}
      icon={Languages}
      onSelect={onLocaleChange}
      optionLabel={(label) => label}
      options={ADMIN_LOCALE_OPTIONS}
      triggerTitle={t("界面语言")}
    />
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
  // 按实际生效主题显示图标（isDark 已解析跟随系统），与公开页 theme.js 行为一致；
  // aria-label/title 仍由 triggerTitle 显示当前模式名（含"跟随系统"）。
  const ThemeIcon = isDark ? Moon : Sun;
  return (
    <AdminDropdownSwitcher
      activeValue={themeMode}
      ariaLabel={t("主题模式")}
      className={className}
      icon={ThemeIcon}
      onSelect={onThemeModeChange}
      optionLabel={t}
      options={ADMIN_THEME_OPTIONS}
      triggerTitle={t(activeThemeOption.label)}
    />
  );
}

const BOOT_PAYLOAD = readAdminBootPayload();

type AdminNavChildItem = { id: string; label: string };
type AdminNavItem = { id: Page; label: string; icon: LucideIcon; children?: AdminNavChildItem[] };
type AdminNavGroup = { title: string; items: AdminNavItem[] };
// 每页存在校验错误的分区（通知告警 / 基础设置页上报，F3 第 4 条扩展到 settings），
// 用于侧栏子项红点提示。
type AdminSectionErrors = Partial<Record<Page, readonly string[]>>;

// 站点未配置 site_icon 时回退到内置图标，与前台展示页的 DEFAULT_SITE_ICON 保持一致。
// 注意：这里是 data URI，不能经过 normalizePublicIconURL（它只放行 http/https）。
const DEFAULT_SITE_ICON =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%231f5dff'/%3E%3Cpath d='M18 40L28 24l8 10 10-14' fill='none' stroke='white' stroke-width='6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";

function BrandIcon({
  siteIcon,
  siteTitle,
  sizeClass = "h-5 w-5",
}: {
  siteIcon: string;
  siteTitle: string;
  sizeClass?: string;
}) {
  return (
    <img
      alt={siteTitle}
      className={`h-full w-full object-cover ${sizeClass}`}
      src={siteIcon || DEFAULT_SITE_ICON}
      width={40}
      height={40}
      referrerPolicy="no-referrer"
    />
  );
}

function NavContent({
  activeSection,
  currentPage,
  deployedVersionLabel,
  footerControls,
  navigation,
  onLogout,
  onNavLinkClick,
  sectionErrors,
  siteIcon,
  siteTitle,
  t,
}: {
  activeSection: string | null;
  currentPage: Page;
  deployedVersionLabel: string;
  footerControls?: ReactNode;
  navigation: AdminNavGroup[];
  onLogout: () => void;
  onNavLinkClick: (
    event: MouseEvent<HTMLAnchorElement>,
    page: Page,
    section?: string | null,
  ) => void;
  sectionErrors: AdminSectionErrors;
  siteIcon: string;
  siteTitle: string;
  t: (text: string) => string;
}) {
  const monitorHref = publicMonitorPath();

  // A-06：可展开父项的展开集合。初始为当前页；currentPage 变化时只增不减
  // （新页加入集合，不移除其他页）。桌面侧栏与手机抽屉各自实例化 NavContent，
  // 两份状态互不影响。点击左侧标签区导航到新页时，由下面的 effect 自动展开。
  const [expandedPages, setExpandedPages] = useState<Set<Page>>(() => new Set([currentPage]));
  // 桌面侧栏与手机抽屉同时存在时避免 aria-controls 的 id 撞车。
  const navPanelIdPrefix = useId();

  useEffect(() => {
    setExpandedPages((current) => {
      if (current.has(currentPage)) {
        return current;
      }
      const next = new Set(current);
      next.add(currentPage);
      return next;
    });
  }, [currentPage]);

  const toggleNavExpanded = (page: Page) => {
    setExpandedPages((current) => {
      const next = new Set(current);
      if (next.has(page)) {
        next.delete(page);
      } else {
        next.add(page);
      }
      return next;
    });
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col text-sidebar-foreground">
      {/* A-02 品牌区：高 56px，Logo 28px 圆角 8px 带 --shadow-1；与导航间 16px 留白不画线 */}
      <div className="flex h-14 shrink-0 items-center gap-2.5 px-4">
        <a
          aria-label={t("打开监控页")}
          className="flex min-w-0 flex-1 items-center gap-2.5 rounded-md text-[15px] font-[650] tracking-tight text-foreground outline-none transition-opacity hover:opacity-80 focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]"
          href={monitorHref}
        >
          <span className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-[8px] shadow-[var(--shadow-1)]">
            <BrandIcon siteIcon={siteIcon} siteTitle={siteTitle} sizeClass="h-full w-full" />
          </span>
          <span className="min-w-0 truncate">{siteTitle}</span>
        </a>
        <span className="data-text shrink-0 rounded-[var(--r-full)] bg-[var(--surface-sunken)] px-1.5 py-0.5 text-[10px] leading-none text-[var(--label-3)]">
          {deployedVersionLabel}
        </span>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        {/* nav 顶部 16px 留白接品牌区；分组名上 20px（首组除外）、下 6px */}
        <nav className="px-2 pt-4 pb-6">
          {navigation.map((group) => (
            <div key={group.title} className="mt-5 first:mt-0">
              <h4 className="pl-1 pr-2 pb-1.5 text-[11px] font-semibold leading-[1.3] text-[var(--label-3)]">
                {group.title}
              </h4>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = currentPage === item.id;
                  const hasChildren = Boolean(item.children?.length);
                  // A-06：展开状态由 expandedPages 集合驱动，可展开也可收起；
                  // 非当前页的父项同样可通过箭头按钮预览子菜单。
                  const expanded = hasChildren && expandedPages.has(item.id);
                  const panelId = `${navPanelIdPrefix}-${item.id}-panel`;
                  return (
                    <div key={item.id}>
                      {/* A-06：一行两个热区——左侧 <a> 标签区导航 + 切换，右侧独立按钮只切换 */}
                      <div className="flex w-full items-center gap-1">
                        <a
                          href={adminPageHref(item.id, item.children?.[0]?.id ?? null)}
                          aria-current={active && !hasChildren ? "page" : undefined}
                          className={`${adminSidebarNavItemClass} ${
                            active
                              ? hasChildren
                                ? // E-04：子项选中时父项仅文字 --label-1 semibold、图标 --accent，不加背景块
                                  "font-semibold text-[var(--label-1)] hover:text-[var(--label-1)] dark:text-[var(--label-1)] dark:hover:text-[var(--label-1)]"
                                : // 0.1.1 白色滑块：--surface-solid 底 + --shadow-1，文字 --label-1/600，图标 --accent
                                  "bg-[var(--surface-solid)] font-semibold text-[var(--label-1)] shadow-[var(--shadow-1)] hover:bg-[var(--surface-solid)] hover:text-[var(--label-1)] dark:bg-[var(--surface-solid)] dark:text-[var(--label-1)] dark:hover:bg-[var(--surface-solid)] dark:hover:text-[var(--label-1)]"
                              : ""
                          }`}
                          onClick={(event) => {
                            if (!shouldHandleAdminNavigation(event)) {
                              return;
                            }
                            if (active) {
                              // A-06：已在该页时，左侧热区只切换展开 / 收起，不再导航。
                              event.preventDefault();
                              if (hasChildren) {
                                toggleNavExpanded(item.id);
                              }
                              return;
                            }
                            onNavLinkClick(event, item.id);
                          }}
                        >
                          <span className={`${adminSidebarNavLabelClass} flex-1`}>
                            <Icon
                              className={`h-5 w-5 shrink-0 md:h-4 md:w-4 ${
                                active ? "text-[var(--accent)]" : ""
                              }`}
                              strokeWidth={1.75}
                            />
                            <span className="truncate tracking-tight">{item.label}</span>
                          </span>
                        </a>
                        {hasChildren ? (
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-controls={panelId}
                            aria-label={expanded ? t("收起子菜单") : t("展开子菜单")}
                            className="mr-0.5 flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-full text-[var(--label-3)] outline-none transition-colors duration-[var(--dur-2)] hover:bg-[rgba(0,0,0,0.04)] hover:text-[var(--label-1)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:hover:bg-[rgba(255,255,255,0.06)] dark:hover:text-[var(--label-1)]"
                            onClick={() => toggleNavExpanded(item.id)}
                          >
                            <ChevronRight
                              aria-hidden="true"
                              className={`h-3 w-3 shrink-0 transition-transform duration-[var(--dur-2)] ${
                                expanded ? "rotate-90" : ""
                              }`}
                            />
                          </button>
                        ) : null}
                      </div>
                      {/* 展开收起高度过渡：grid-template-rows 0fr→1fr（A-02 第 7 条）。
                          收起时 invisible，避免隐藏子项仍可被 Tab 聚焦。
                          始终渲染（含无子项的空面板），保证首次展开也有过渡。 */}
                      <div
                        id={panelId}
                        className={`grid transition-[grid-template-rows] duration-[var(--dur-3)] ease-[var(--ease-spring)] ${
                          expanded ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
                        }`}
                      >
                        <div className={`overflow-hidden ${expanded ? "" : "invisible"}`}>
                          {/* 子项缩进 28px（A-02 第 7 条） */}
                          <div className="space-y-0.5 pb-1">
                            {item.children?.map((child) => {
                              const childActive = active && activeSection === child.id;
                              // 该分区存在校验错误时在子项文字前显示 --status-danger 小圆点。
                              const childHasError = sectionErrors[item.id]?.includes(child.id) ?? false;
                              return (
                                <a
                                  key={child.id}
                                  href={adminPageHref(item.id, child.id)}
                                  aria-current={childActive ? "page" : undefined}
                                  className={`relative flex h-11 items-center rounded-[var(--r-sm)] pl-[28px] pr-2.5 text-[16px] font-normal text-[var(--label-2)] outline-none transition-colors duration-150 hover:bg-[rgba(0,0,0,0.04)] hover:text-[var(--label-1)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] md:h-7 md:text-[13px] dark:hover:bg-[rgba(255,255,255,0.06)] ${
                                    childActive
                                      ? // A-07 第 2 条：选中滑块 --surface-solid + --shadow-1 + inset 1px hairline，
                                        // 文字 --label-1/600；左侧 3×14px --accent 圆角竖条（left 6px 垂直居中）
                                        "bg-[var(--surface-solid)] font-semibold text-[var(--label-1)] shadow-[var(--shadow-1),inset_0_0_0_1px_var(--hairline)] hover:bg-[var(--surface-solid)] hover:text-[var(--label-1)] dark:bg-[var(--surface-solid)] dark:text-[var(--label-1)] dark:hover:bg-[var(--surface-solid)] dark:hover:text-[var(--label-1)]"
                                      : ""
                                  }`}
                                  onClick={(event) => {
                                    onNavLinkClick(event, item.id, child.id);
                                  }}
                                >
                                  {childActive ? (
                                    <span
                                      aria-hidden="true"
                                      className="absolute left-1.5 top-1/2 h-3.5 w-[3px] -translate-y-1/2 rounded-full bg-[var(--accent)]"
                                    />
                                  ) : null}
                                  {childHasError ? (
                                    <span
                                      aria-hidden="true"
                                      className="mr-1.5 h-1.5 w-1.5 flex-none rounded-full bg-[var(--status-danger)]"
                                    />
                                  ) : null}
                                  <span className="truncate tracking-tight">{child.label}</span>
                                </a>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </ScrollArea>
      {/* A-02 底部工具区：上方 12px 留白不画线；退出登录 32px 行，语言/主题圆形按钮同行右侧 */}
      <div className="mt-auto flex shrink-0 items-center gap-2 p-3">
        <Button
          className={`${adminSidebarSecondaryButtonClass} group flex-1 gap-2 py-0`}
          variant="ghost"
          onClick={onLogout}
        >
          <LogOut className="h-4 w-4 shrink-0" />
          <span className="tracking-tight">{t("退出登录")}</span>
        </Button>
        {footerControls ? (
          // 侧栏底部的下拉菜单向上展开并左对齐，避免固定侧栏下缘被视口裁切、右锚定左溢出视口
          <div className="flex shrink-0 items-center gap-2 [&_[role=menu]]:bottom-full [&_[role=menu]]:left-0 [&_[role=menu]]:mb-2 [&_[role=menu]]:mt-0 [&_[role=menu]]:right-auto [&_[role=menu]]:top-auto">
            {footerControls}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function App() {
  const [locale, setLocale] = useState<AdminLocale>(() => resolveInitialAdminLocale(BOOT_PAYLOAD.settings || null));
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => resolveInitialThemeMode());
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => resolveSystemTheme());
  const [token, setToken] = useState(() => getStoredAdminToken());
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [loginConfig, setLoginConfig] = useState<LoginConfigResponse | null>(null);

  const [loginConfigLoaded, setLoginConfigLoaded] = useState(false);
  const [publicSettings, setPublicSettings] = useState<BootPublicSettings | null>(() => BOOT_PAYLOAD.settings || null);
  const [systemUpdateInfo, setSystemUpdateInfo] = useState<SystemUpdateInfo | null>(null);
  const [nodes, setNodes] = useState<NodeView[]>([]);
  const [currentPage, setCurrentPage] = useState<Page>(() => resolveInitialPage());
  // 设置类页面（settings/alerts）的当前分区；其余页面（含 ai 运维助手单页）恒为 null。
  const [currentSection, setCurrentSection] = useState<string | null>(() =>
    resolveInitialSection(resolveInitialPage()),
  );
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [loading, setLoading] = useState(Boolean(token));
  // 区分「加载中 / 加载成功 / 加载失败(非 401)」：settings 加载失败时保持 settings=null，
  // 但绝不能把 null 交给依赖 settings 的配置页（否则空草稿会被整份 PATCH 覆盖服务端配置）。
  const [loadError, setLoadError] = useState<string | null>(null);
  const [refreshingNodes, setRefreshingNodes] = useState(false);
  const [refreshingSystemUpdate, setRefreshingSystemUpdate] = useState(false);
  const [startingSystemUpdate, setStartingSystemUpdate] = useState(false);
  const [savingPage, setSavingPage] = useState<Page | null>(null);
  const [loginState, setLoginState] = useState<LoginState>(() => createLoginState());
  const [hasUnsavedPageChanges, setHasUnsavedPageChanges] = useState(false);
  const [pendingPageNavigation, setPendingPageNavigation] = useState<Page | null>(null);
  const [unsavedDialogOpen, setUnsavedDialogOpen] = useState(false);
  // 通知告警 / 基础设置页上报的“存在校验错误的分区”，供侧栏子项红点展示（U1-b 第 3 条、F3 第 4 条）。
  const [sectionValidationErrors, setSectionValidationErrors] = useState<AdminSectionErrors>({});
  const socketRef = useRef<{ close: () => void } | null>(null);
  const systemUpdatePollRef = useRef<number | null>(null);
  const loadAllRequestRef = useRef(0);
  const systemUpdatePollErrorToastAtRef = useRef(0);
  const localeChangeSeqRef = useRef(0);

  const reportActionError = (error: unknown, fallback: string) => {
    if (error instanceof AdminApiError && error.status === 401) {
      return;
    }
    toast.error(getErrorMessage(error, fallback));
  };
  const theme = themeMode === "auto" ? systemTheme : themeMode;
  const isDark = theme === "dark";
  const siteIcon = normalizePublicIconURL(settings?.site_icon || publicSettings?.site_icon || "");
  const siteTitle = resolveBrandTitle(settings, publicSettings);
  const deployedVersion = (settings?.version || publicSettings?.version || "").trim();

  const deployedVersionLabel = formatVersionLabel(deployedVersion);
  const activeThemeOption = ADMIN_THEME_OPTIONS.find((item) => item.value === themeMode) || ADMIN_THEME_OPTIONS[0];
  const t = useCallback((text: string) => adminText(locale, text), [locale]);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", isDark);
    root.setAttribute("data-theme", theme);
    root.setAttribute("data-theme-mode", themeMode);
    root.style.colorScheme = theme;
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, themeMode);
    } catch {
      // localStorage 不可用时主题仅存内存，勿因持久化失败打断渲染。
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

    translateAdminDOM(root, locale);
    if (locale === "zh-CN") {
      return;
    }

    let timer = 0;
    const scheduleTranslations = () => {
      if (timer) {
        return;
      }
      timer = window.setTimeout(() => {
        timer = 0;
        translateAdminDOM(root, locale);
      }, 150);
    };

    const observer = new MutationObserver(scheduleTranslations);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["aria-label", "placeholder", "title"],
      characterData: true,
      childList: true,
      subtree: true,
    });

    return () => {
      observer.disconnect();
      if (timer) {
        clearTimeout(timer);
      }
    };
  }, [locale]);

  useEffect(() => {
    // 以 replace 修正 URL：非法/缺省 section 回落第一项、旧锚点（#settings-oauth）
    // 收敛为 section 查询参数；显式的分区切换在 navigateToPage 中已用 pushState。
    syncPageToURL(currentPage, currentSection, true);
  }, [currentPage, currentSection]);

  useEffect(() => {
    const handlePopState = () => {
      const nextPage = resolveInitialPage();
      if (nextPage === currentPage) {
        // 同页分区间前进/后退：只同步分区，不触发跨页未保存拦截。
        const nextSection = resolveInitialSection(nextPage);
        if (nextSection !== currentSection) {
          setCurrentSection(nextSection);
        }
        return;
      }
      if (hasUnsavedPageChanges) {
        syncPageToURL(currentPage, currentSection, true);
        setPendingPageNavigation(nextPage);
        setUnsavedDialogOpen(true);
        return;
      }
      setCurrentPage(nextPage);
      setCurrentSection(resolveInitialSection(nextPage));
    };
    window.addEventListener("popstate", handlePopState);
    return () => {
      window.removeEventListener("popstate", handlePopState);
    };
  }, [currentPage, currentSection, hasUnsavedPageChanges]);

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
    const requestSeq = ++localeChangeSeqRef.current;
    try {
      const data = await saveSettings({ locale: nextLocale });
      if (localeChangeSeqRef.current !== requestSeq) {
        return;
      }
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

  function proceedToPage(page: Page, section?: string | null) {
    // 跨页导航不带分区时进入目标页第一个分区（U1-b 第 1 条，取“第一分区”方案）。
    const nextSection = resolveAdminSection(page, section ?? null);
    syncPageToURL(page, nextSection);
    setCurrentPage(page);
    setCurrentSection(nextSection);
    setHasUnsavedPageChanges(false);
    setPendingPageNavigation(null);
    setUnsavedDialogOpen(false);
    setIsMobileMenuOpen(false);
  }

  const navigateToPage = useCallback(
    (page: Page, section?: string | null) => {
      if (page === currentPage) {
        // 同页切换分区：pushState 保留后退能力；页面组件不卸载、草稿不清空，
        // 也不触发“未保存修改”拦截（拦截只保留给跨页导航）。
        if (hasAdminPageSections(page)) {
          const nextSection = resolveAdminSection(page, section ?? null);
          if (nextSection && nextSection !== currentSection) {
            syncPageToURL(page, nextSection);
            setCurrentSection(nextSection);
          }
        }
        setIsMobileMenuOpen(false);
        return;
      }
      if (hasUnsavedPageChanges) {
        setPendingPageNavigation(page);
        setUnsavedDialogOpen(true);
        setIsMobileMenuOpen(false);
        return;
      }
      proceedToPage(page, section);
    },

    [currentPage, currentSection, hasUnsavedPageChanges],
  );

  // 通知告警页校验失败时切换到出错字段所在分区（同页导航，走 navigateToPage 的分区分支）。
  const handleAlertSectionRequest = useCallback(
    (section: string) => {
      navigateToPage("alerts", section);
    },
    [navigateToPage],
  );

  // 通知告警页上报存在校验错误的分区；函数式更新保证回调引用稳定。
  const handleAlertValidationErrorSections = useCallback((sections: readonly string[]) => {
    setSectionValidationErrors((current) => ({ ...current, alerts: sections }));
  }, []);

  // 基础设置页上报存在校验错误的分区（F3 第 4 条）；函数式更新保证回调引用稳定。
  const handleBasicValidationErrorSections = useCallback((sections: readonly string[]) => {
    setSectionValidationErrors((current) => ({ ...current, settings: sections }));
  }, []);

  function handleNavLinkClick(
    event: MouseEvent<HTMLAnchorElement>,
    page: Page,
    section?: string | null,
  ) {
    if (!shouldHandleAdminNavigation(event)) {
      return;
    }
    event.preventDefault();
    navigateToPage(page, section);
  }

  const handleLogout = useCallback((nextLoginState?: Partial<LoginState>) => {
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
    setLoadError(null);
    setLoginState(
      createLoginState(
        nextLoginState?.errorType || "none",
        nextLoginState?.errorMessage || "",
        nextLoginState?.retryAfterSec || 0,
      ),
    );
  }, []);

  async function loadAll() {
    if (!token) {
      loadAllRequestRef.current += 1;
      setSettings(null);
      setNodes([]);
      setLoading(false);
      setLoadError(null);
      return;
    }

    const requestID = loadAllRequestRef.current + 1;
    loadAllRequestRef.current = requestID;
    const isCurrentLoad = () => loadAllRequestRef.current === requestID;
    setLoading(true);
    setLoadError(null);
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
      setLoadError(getErrorMessage(error, "初始化后台数据失败"));
      throw error;
    } finally {
      if (isCurrentLoad()) {
        setLoading(false);
      }
    }
  }

  function handleRetryLoad() {
    void loadAll().catch((error) => {
      toast.error(getErrorMessage(error, "初始化后台数据失败"));
    });
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
      reportActionError(error, "加载服务端更新状态失败");
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

        const now = Date.now();
        if (now - systemUpdatePollErrorToastAtRef.current < 30_000) {
          return;
        }
        systemUpdatePollErrorToastAtRef.current = now;
        reportActionError(error, "刷新服务端更新状态失败");
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
          setLoginConfigLoaded(true);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setLoginConfig(null);
          setLoginConfigLoaded(true);
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
          // 快照每秒全量推送：字段未变时复用 current，避免引用抖动触发无谓重渲染。
          setPublicSettings((current) => {
            if (!current) {
              return snapshotSettings;
            }
            const changed = Object.keys(snapshotSettings).some(
              (key) =>
                current[key as keyof BootPublicSettings] !==
                snapshotSettings[key as keyof PublicSettings],
            );
            return changed ? { ...current, ...snapshotSettings } : current;
          });
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

  // 设置类页面的侧栏子项与页面分区共用 ADMIN_PAGE_SECTIONS 这一份定义。
  const navChildren = (page: Page): AdminNavChildItem[] =>
    adminPageSections(page).map((child) => ({ id: child.id, label: t(child.label) }));

  const navigation: AdminNavGroup[] = [
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
        { id: "settings", label: t("基础设置"), icon: Settings, children: navChildren("settings") },
        { id: "alerts", label: t("通知告警"), icon: Bell, children: navChildren("alerts") },
        { id: "ai", label: t("运维助手"), icon: Bot },
        { id: "logs", label: t("日志查看"), icon: ScrollText },
      ],
    },
  ];

  const refreshNodesAfterMutation = useCallback(
    async (successLabel: string, successLocale: AdminLocale = locale) => {
      const requestID = loadAllRequestRef.current;
      try {
        const snapshot = await fetchNodes();
        if (loadAllRequestRef.current !== requestID) {
          return;
        }
        setNodes(snapshot.nodes || []);
      } catch (error) {
        if (loadAllRequestRef.current !== requestID) {
          return;
        }
        const message = getErrorMessage(error, adminText(successLocale, "节点列表刷新失败"));
        toast.warning(
          successLocale === "en-US"
            ? `${successLabel}, but node refresh failed: ${message}`
            : `${successLabel}，但节点列表刷新失败：${message}`,
        );
      }
    },
    [locale],
  );

  const updateSettings = useCallback(
    async (page: Page, payload: SettingsUpdate) => {
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
    },
    [handleLogout, refreshNodesAfterMutation],
  );

  const handleExport = useCallback(async () => {
    const data = await exportConfig();
    triggerDownload(data.blob, parseDownloadFilename(data.disposition));
  }, []);

  const handleImport = useCallback(
    async (payload: Record<string, unknown>): Promise<ConfigImportResponse> => {
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
    },
    [locale, refreshNodesAfterMutation],
  );

  const handleRefreshNodes = useCallback(
    async () => {
      setRefreshingNodes(true);
      const requestID = loadAllRequestRef.current;
      try {
        const snapshot = await fetchNodes();
        if (loadAllRequestRef.current !== requestID) {
          return;
        }
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
    },
    [handleLogout],
  );

  const refreshSystemUpdate = useCallback(
    async (force = false) => {
      if (!token) {
        setSystemUpdateInfo(null);
        return;
      }
      setRefreshingSystemUpdate(true);
      try {
        const data = await fetchSystemUpdateInfo(force);
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
        }
        throw error;
      } finally {
        setRefreshingSystemUpdate(false);
      }
    },
    [handleLogout, token],
  );

  const handleSystemUpdate = useCallback(
    async () => {
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
        }
        throw error;
      } finally {
        setStartingSystemUpdate(false);
      }
    },
    [handleLogout, publicSettings, refreshSystemUpdate, settings, token],
  );

  const handleSaveNode = useCallback(
    async (nodeID: string, payload: NodeProfilePayload) => {
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
    },
    [handleLogout, refreshNodesAfterMutation, t],
  );

  const handleDeleteNode = useCallback(
    async (nodeID: string): Promise<NodeDeleteResponse> => {
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
    },
    [handleLogout, locale, refreshNodesAfterMutation, t],
  );

  const nodePageContent = useMemo(() => {
    switch (currentPage) {
      case "dashboard":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载首页…")} variant="dashboard" />}>
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
              // F4 节点抽屉「为此节点新增规则」：走 App 现有 updateSettings 通道保存
              // alert_rules，保存成功后同步刷新 App 内 settings，避免「告警策略」页
              // 草稿从过期 settings 初始化后保存时覆盖新增规则。
              onSaveSettings={(payload: SettingsUpdate) => updateSettings("servers", payload)}
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
              onSave={(groupTree: GroupNode[], groupMoves?: GroupMove[]) =>
                updateSettings(
                  "groups",
                  // F1：拖拽 / 改名产生的归属迁移随 group_moves 下发；无迁移时请求体与旧版一致。
                  groupMoves && groupMoves.length > 0
                    ? { group_tree: groupTree, group_moves: groupMoves }
                    : { group_tree: groupTree },
                )
              }
              saving={savingPage === "groups"}
            />
          </Suspense>
        );
      case "alerts":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载通知告警…")} variant="settings" />}>
            <NotificationAlertPage
              nodes={nodes}
              onDirtyChange={setHasUnsavedPageChanges}
              onRequestSectionChange={handleAlertSectionRequest}
              onSave={(payload) => updateSettings("alerts", payload)}
              onTest={(payload: AlertTestPayload) =>
                testAlertChannels(payload).then(() => undefined)
              }
              onValidationErrorSectionsChange={handleAlertValidationErrorSections}
              saving={savingPage === "alerts"}
              section={currentSection}
              settings={settings}
            />
          </Suspense>
        );
      default:
        return null;
    }
  }, [
    currentPage,
    currentSection,
    handleAlertSectionRequest,
    handleAlertValidationErrorSections,
    handleDeleteNode,
    handleRefreshNodes,
    handleSaveNode,
    loading,
    navigateToPage,
    nodes,
    refreshingNodes,
    savingPage,
    settings,
    t,
    updateSettings,
  ]);

  const staticPageContent = useMemo(() => {
    switch (currentPage) {
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
          <Suspense fallback={<SectionLoader label={t("正在加载基础设置…")} variant="settings" />}>
            <BasicSettingsPage
              onDirtyChange={setHasUnsavedPageChanges}
              onExport={handleExport}
              onImport={handleImport}
              onRefreshSystemUpdate={() => refreshSystemUpdate(true)}
              onSave={(payload) => updateSettings("settings", payload)}
              onTriggerSystemUpdate={handleSystemUpdate}
              onValidationErrorSectionsChange={handleBasicValidationErrorSections}
              refreshingSystemUpdate={refreshingSystemUpdate}
              section={currentSection}
              settings={settings}
              startingSystemUpdate={startingSystemUpdate}
              systemUpdateInfo={systemUpdateInfo}
            />
          </Suspense>
        );
      case "ai":
        return (
          <Suspense fallback={<SectionLoader label={t("正在加载运维助手…")} variant="settings" />}>
            <AIProviderPage
              onFetchModels={(provider: string, config: AIProviderConfig | null) =>
                fetchAIModels(provider, config).then((data) => data.models || [])
              }
              onDirtyChange={setHasUnsavedPageChanges}
              onSave={(payload) => updateSettings("ai", payload)}
              onTestProvider={(provider: string, config: AIProviderConfig | null) =>
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
    currentSection,
    handleBasicValidationErrorSections,
    handleExport,
    handleImport,
    handleSystemUpdate,
    refreshingSystemUpdate,
    savingPage,
    settings,
    startingSystemUpdate,
    systemUpdateInfo,
    t,
    updateSettings,
  ]);

  const pageContent = nodePageContent ?? staticPageContent;

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
          passwordLoginEnabled={loginConfigLoaded ? loginConfig?.password_login_enabled !== false : false}
          loginConfigLoaded={loginConfigLoaded}
          retryAfterSec={loginState.retryAfterSec}
          theme={theme}
            topControls={
              <>
                <AdminLocaleSwitcher

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
        className="sr-only fixed left-4 top-4 z-[70] rounded-full bg-slate-950 px-4 py-2 text-sm font-medium text-white shadow-[var(--cm-elev-2)] focus:not-sr-only focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--label-1)] dark:bg-[var(--surface-3)] dark:text-[var(--label-1)]"
      >
        {t("跳转到主要内容")}
      </a>
      {/* A-02 侧栏：.glass + --mat-sidebar-bg + --blur-thin，宽 260px。
          0.1.1 浮动形态（仅 md 及以上）：top/bottom/left 8px、--r-xl、--shadow-3；
          右缘分隔并入投影组合（1px 0 0 hairline）；主区相应 padding-left 276px。
          手机端沿用抽屉（header 内 Sheet） */}
      <aside className="glass fixed bottom-2 left-2 top-2 z-50 hidden w-[260px] flex-col rounded-[var(--r-xl)] md:flex [--mat-bg:var(--mat-sidebar-bg)] [--mat-blur:var(--blur-thin)] [--mat-shadow:1px_0_0_var(--hairline),var(--shadow-3)]">
        <NavContent
          activeSection={currentSection}
          currentPage={currentPage}
          deployedVersionLabel={deployedVersionLabel}
          footerControls={
            <>
              <AdminLocaleSwitcher
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
          navigation={navigation}
          onLogout={() => {
            void handleUserLogout();
          }}
          onNavLinkClick={handleNavLinkClick}
          sectionErrors={sectionValidationErrors}
          siteIcon={siteIcon}
          siteTitle={siteTitle}
          t={t}
        />
      </aside>

      {/* A-03 手机端顶栏：52px .glass + --mat-bar-bg + --blur-regular，底部 hairline 分隔线（.glass 边框） */}
      <header className="glass fixed left-0 right-0 top-0 z-50 flex h-[52px] items-center px-4 md:hidden [--mat-bg:var(--mat-bar-bg)] [--mat-blur:var(--blur-regular)]">
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
          {/* A-03 抽屉：宽 min(320px, 86vw)，.glass + --mat-sheet-bg + --blur-thick + --shadow-4，
              四周 8px 浮动卡片、圆角 --r-2xl；遮罩见 index.css 的 [data-nav-drawer] 规则 */}
          <SheetContent
            className="glass w-[min(320px,86vw)] gap-0 rounded-[var(--r-2xl)] border-[var(--hairline)] p-0 [--mat-bg:var(--mat-sheet-bg)] [--mat-blur:var(--blur-thick)] [--mat-shadow:var(--shadow-4)] data-[side=left]:h-auto data-[side=left]:inset-y-2 data-[side=left]:left-2 data-[side=left]:w-[min(320px,86vw)] [&>[data-slot=sheet-close]]:top-3.5 [&>div:first-child>div:first-child]:pr-12"
            data-nav-drawer=""
            side="left"
          >
            <NavContent
              activeSection={currentSection}
              currentPage={currentPage}
              deployedVersionLabel={deployedVersionLabel}
              navigation={navigation}
              onLogout={() => {
                void handleUserLogout();
              }}
              onNavLinkClick={handleNavLinkClick}
              sectionErrors={sectionValidationErrors}
              siteIcon={siteIcon}
              siteTitle={siteTitle}
              t={t}
            />
          </SheetContent>
        </Sheet>
        <a
          aria-label={t("打开监控页")}
          className="ml-3 flex min-w-0 items-center gap-2.5 rounded-md font-semibold tracking-tight text-foreground transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]"
          href={publicMonitorPath()}
        >
          <span className="h-5 w-5 shrink-0 overflow-hidden rounded-md">
            <BrandIcon siteIcon={siteIcon} siteTitle={siteTitle} sizeClass="h-5 w-5" />
          </span>
          <span className="min-w-0 truncate text-[15px]">{siteTitle}</span>
        </a>
        <span className="data-text ml-2 hidden text-[11px] text-[var(--label-3)] min-[400px]:inline">
          {deployedVersionLabel}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <AdminLocaleSwitcher

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

      <main
        id="admin-main-content"
        className="relative flex h-screen min-w-0 flex-1 flex-col overflow-hidden pt-[53px] md:pl-[276px] md:pt-0"
      >
        <ScrollArea className="min-h-0 flex-1">
          <div className="w-full px-4 pb-12 pt-6 md:px-10 md:pb-16 md:pt-8">
            {loading ? (
              <SectionLoader label={t("正在加载数据…")} minHeightClass="min-h-[50vh]" />
            ) : loadError && settings === null ? (
              <div className="flex min-h-[50vh] items-center justify-center">
                <Card className={adminLoadingCardClass}>
                  <CardContent
                    className={`${adminLoadingCardContentClass} flex-col gap-3 py-10 text-center`}
                  >
                    <AlertTriangle className="h-6 w-6 text-amber-500 dark:text-amber-400" />
                    <p className="max-w-xs text-sm font-medium leading-relaxed text-slate-700 dark:text-neutral-200">
                      {loadError}
                    </p>
                    <Button className={adminPrimaryButtonClass} onClick={handleRetryLoad}>
                      {t("重试")}
                    </Button>
                  </CardContent>
                </Card>
              </div>
            ) : (
              pageContent
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
      {/* A-13 Toast：顶部居中玻璃胶囊。sonner 2.x 在运行时向 <head> 注入未分层样式，
          这里用 .cn-toast（sonner.tsx toastOptions 已挂载的类名）加前缀提高优先级覆盖。
          所有颜色/材质/圆角/动效均引用第 4 节令牌；prefers-reduced-motion 由 sonner 自身处理，
          prefers-reduced-transparency 由 index.css 的全局 !important 规则兜底。 */}
      <style>{`
.cn-toast[data-sonner-toast] {
  width: fit-content;
  max-width: 100%;
  font-family: var(--font-ui);
  /* A-01：fit-content 收窄后居中——绝对定位时 left/right 同时置 0 + margin-inline auto */
  left: 0;
  right: 0;
  margin-inline: auto;
  transition:
    transform var(--dur-3) var(--ease-bounce),
    opacity var(--dur-2) var(--ease-out);
}
/* 入场：从上方 translateY(-12px) 落下（未挂载态改写 sonner 的 --y） */
.cn-toast[data-sonner-toast][data-y-position='top']:not([data-mounted='true']) {
  --y: translateY(-12px);
}
.cn-toast[data-sonner-toast][data-styled='true'] {
  padding: 10px 18px;
  background: var(--mat-popover-bg);
  -webkit-backdrop-filter: var(--blur-thick);
  backdrop-filter: var(--blur-thick);
  border: 1px solid var(--hairline);
  border-radius: var(--r-full);
  color: var(--label-1);
  box-shadow: inset 0 1px 0 var(--glass-edge), var(--shadow-3);
}
.cn-toast[data-sonner-toast][data-styled='true'] [data-description] {
  color: var(--label-2);
}
/* 左侧状态图标圆（成功 / 失败 / 信息 / 警告） */
.cn-toast[data-sonner-toast][data-styled='true'] [data-icon] {
  height: 24px;
  width: 24px;
  justify-content: center;
  border-radius: var(--r-full);
}
.cn-toast[data-sonner-toast][data-type='success'] [data-icon] {
  background: var(--ok-tint);
  color: var(--ok);
}
.cn-toast[data-sonner-toast][data-type='error'] [data-icon] {
  background: var(--danger-tint);
  color: var(--danger);
}
.cn-toast[data-sonner-toast][data-type='info'] [data-icon] {
  background: var(--accent-tint);
  color: var(--accent-text);
}
.cn-toast[data-sonner-toast][data-type='warning'] [data-icon] {
  background: var(--warn-tint);
  color: var(--warn);
}
/* A-01：桌面端视口居中会偏进侧栏留白，整体右移 134px = (260 + 8) / 2，
   让 toast 在主内容区水平居中。 */
@media (min-width: 768px) {
  [data-sonner-toaster][data-x-position='center'] {
    left: calc(50% + 134px) !important;
  }
}
/* A-01：手机端 sonner 2.x 运行时会注入 left:16px / width:390px，窄屏下容器
   右溢 16px，toast 随之偏右；铺满视口宽，让 .cn-toast 的 margin-inline:auto 真正居中。 */
@media (max-width: 767.98px) {
  [data-sonner-toaster][data-x-position='center'] {
    left: 0 !important;
    width: 100vw !important;
  }
}
`}</style>
      <Toaster position="top-center" theme={theme} />
    </div>
  );
}
