import { useEffect, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import {
  AdminGroupedCard,
  AdminGroupedFieldRow,
  AdminGroupedSwitchRow,
  AdminSectionPanel,
} from "@/components/admin-section-panel";
import { AdminSaveBar } from "@/components/admin-save-bar";
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
  ChevronRight,
  Info,
  KeyRound,
  Palette,
  PlugZap,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import type {
  ConfigImportResponse,
  SettingsView,
  SystemStatusView,
  SystemUpdateInfo,
  AdminAuthSettings,
  SettingsUpdate,
} from "@/lib/admin-types";
import { draftSignature, useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { AdminApiError, adminAppLocation, fetchSystemStatus } from "@/lib/admin-api";
import {
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminInputClass,
  adminNarrowPageShellClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminTextButtonClass,
  adminTextareaClass,
} from "@/lib/admin-ui";
import { adminPageSections, resolveAdminSection } from "@/lib/admin-sections";
import {
  formatBinaryBytes,
  formatUptimeZh,
  formatVersionLabel,
  getErrorMessage,
} from "@/lib/admin-format";
import { cn } from "@/lib/utils";
import { missingSecretChannelsNotice } from "@/lib/notify-channels";

export interface BasicSettingsProps {
  settings: SettingsView | null;
  // 当前分区（settings 页 5 分区之一，由 App 依据 URL 解析后传入）。
  section?: string | null;
  onDirtyChange?: (dirty: boolean) => void;
  onSave: (payload: SettingsUpdate) => Promise<SettingsView>;
  onExport: () => Promise<void>;
  onImport: (payload: Record<string, unknown>) => Promise<ConfigImportResponse>;
  systemUpdateInfo: SystemUpdateInfo | null;
  refreshingSystemUpdate: boolean;
  startingSystemUpdate: boolean;
  onRefreshSystemUpdate: () => Promise<void>;
  onTriggerSystemUpdate: () => Promise<void>;
  // 上报存在校验错误的分区（侧栏子项红点，F3 第 4 条）；传空数组表示全部清除。
  onValidationErrorSectionsChange?: (sections: readonly string[]) => void;
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

function formatRuntimeStartedAt(startedAt?: number) {
  if (!startedAt) return "--";
  return new Date(startedAt * 1000).toLocaleString("zh-CN", { hour12: false });
}

const localeOptions = [
  { value: "zh-CN", label: "简体中文" },
  { value: "en-US", label: "English" },
];

// 资源历史保留天数（服务端只接受 1 / 7 / 30，其它值保存会被拒绝）。
const resourceHistoryDayOptions = [
  { value: "1", label: "1 天" },
  { value: "7", label: "7 天" },
  { value: "30", label: "30 天" },
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
    resourceHistoryDays: String(settings?.resource_history_days || 7),
    adminAuth: adminAuthDraft(settings),
  };
}

type BasicSettingsDraft = ReturnType<typeof basicSettingsDraft>;

type BasicSettingsStringField = {
  [K in keyof BasicSettingsDraft]: BasicSettingsDraft[K] extends string ? K : never;
}[keyof BasicSettingsDraft];

// E-01 / A-07 第 1 条：分区图标方块的图标与分区专属底色，随 h1 展示在页头左侧。
// evolution_log.md 第 4 节图标表：入口凭证 KeyRound·灰 / 安全设置 ShieldCheck·红 /
// 接入配置 PlugZap·青 / 站点展示 Palette·紫 / 系统信息 Info·绿。
const SECTION_ICON_META: Record<string, { icon: ReactNode; background: string }> = {
  credentials: {
    icon: <KeyRound className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#8e8e93] to-[#636366]",
  },
  security: {
    icon: <ShieldCheck className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#ff6b6b] to-[#e5383b]",
  },
  agent: {
    icon: <PlugZap className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#5ad6c8] to-[#1fb5a3]",
  },
  site: {
    icon: <Palette className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#a78bfa] to-[#7c5cf0]",
  },
  system: {
    icon: <Info className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#4cd98a] to-[#1fa855]",
  },
};

// F3 第 4 条：字段 → 分区映射（草稿字段名，camelCase）。
// snake_case 的 payload 字段族（admin_auth.* / login_fail_* / login_lock_* /
// turnstile_* / agent_* / admin_* / site* / home* / locale）由下方关键词表覆盖。
const basicFieldSectionMap: Record<string, string> = {
  // credentials：admin_path / admin_user / admin_pass
  adminPath: "credentials",
  adminUser: "credentials",
  adminPass: "credentials",
  // security：admin_auth.* / login_fail_* / login_lock_* / turnstile_*
  adminAuth: "security",
  loginFailLimit: "security",
  loginFailWindow: "security",
  loginLockMinutes: "security",
  turnstileSiteKey: "security",
  turnstileSecretKey: "security",
  // agent
  agentEndpoint: "agent",
  agentToken: "agent",
  // site：site* / home* / locale
  siteTitle: "site",
  siteIcon: "site",
  siteBackgroundImage: "site",
  homeTitle: "site",
  homeSubtitle: "site",
  locale: "site",
  regionGroupEnabled: "site",
};

// F3 第 4 条：服务端错误文案关键词 → 分区。文档点名的关键词为 turnstile、login_fail、
// oauth / oidc → security，agent_endpoint → agent；其余条目是同族字段在服务端实际
// 返回文案中的写法（login_lock、空格形式的 “agent endpoint” / “admin path”、
// agent_token、site_icon 等），一并收录以保证红点能落到出错字段所在的分区。
const BASIC_SERVER_ERROR_KEYWORD_SECTIONS: ReadonlyArray<readonly [string, string]> = [
  ["turnstile", "security"],
  ["login_fail", "security"],
  ["login_lock", "security"],
  ["oauth", "security"],
  ["oidc", "security"],
  ["admin_auth", "security"],
  ["agent_endpoint", "agent"],
  ["agent endpoint", "agent"],
  ["agent_token", "agent"],
  ["admin_path", "credentials"],
  ["admin path", "credentials"],
  ["admin_user", "credentials"],
  ["admin_pass", "credentials"],
  ["site_icon", "site"],
  ["site_background_image", "site"],
];

// 服务端错误文案 → 存在校验错误的分区列表；无命中的关键词则返回空数组。
function basicErrorSectionsFromMessage(message: string): string[] {
  const normalized = message.toLowerCase();
  const sections = new Set<string>();
  for (const [keyword, section] of BASIC_SERVER_ERROR_KEYWORD_SECTIONS) {
    if (normalized.includes(keyword)) {
      sections.add(section);
    }
  }
  for (const field of Object.keys(basicFieldSectionMap)) {
    if (normalized.includes(field.toLowerCase())) {
      sections.add(basicFieldSectionMap[field]);
    }
  }
  return Array.from(sections);
}

export default function BasicSettings({
  settings,
  section,
  onDirtyChange,
  onSave,
  onExport,
  onImport,
  systemUpdateInfo,
  refreshingSystemUpdate,
  startingSystemUpdate,
  onRefreshSystemUpdate,
  onTriggerSystemUpdate,
  onValidationErrorSectionsChange,
}: BasicSettingsProps) {

  const [basicDraft, setBasicDraft] = useState<BasicSettingsDraft>(() => basicSettingsDraft(settings));
  const [adminPass, setAdminPass] = useState("");
  // F3 第 4 条：保存被服务端拒绝时按错误文案映射出的出错分区（侧栏红点数据源）。
  const [validationErrorSections, setValidationErrorSections] = useState<readonly string[]>([]);
  // 「检查」请求失败标记：版本行副标题显示「检查失败」（F3 system 分区版式）。
  const [lastCheckFailed, setLastCheckFailed] = useState(false);
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
    resourceHistoryDays,
    adminAuth: adminAuthDraftValue,
  } = basicDraft;
  const [isSaving, setIsSaving] = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const isBusy = isSaving || isImporting;
  // settings 尚未加载成功时，草稿是空的；此时保存会把空值整份 PATCH 上去，清空站点与鉴权配置。
  // 沿用 ServerManagement 的 catalogLoaded 约定，settings===null 一律禁止保存。
  const settingsLoaded = settings !== null;

  const currentDraftSignature = draftSignature({ ...basicDraft, adminPass });

  const [sourceSignature, absorbSourceSignature, discardDraft] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: draftSignature({ ...basicSettingsDraft(settings), adminPass: "" }),
    isBusy,
    resetDraft: () => {
      setBasicDraft(basicSettingsDraft(settings));
      setAdminPass("");
    },
    warningText: "服务端基础设置已更新，当前未保存修改已保留。",
    onCleaned: () => {
      setIsConfirmOpen(false);
    },
  });
  // A-03：isDirty 由「草稿签名 ≠ 已吸收的服务端签名」派生——改回原值后保存条自动消失。
  const isDirty = sourceSignature !== currentDraftSignature;

  // A-03 / D-07「放弃修改」：回到服务端当前配置，并清空校验错误（侧栏红点随之清除）。
  const discardDraftChanges = () => {
    discardDraft();
    setValidationErrorSections([]);
  };

  // F3 卡片 3「运行信息」：进入 system 分区时从 F7 system/status 拉一次；
  // 失败静默（值保持「--」），401 由 apiFetch 统一登出。
  const [systemStatus, setSystemStatus] = useState<SystemStatusView | null>(null);
  useEffect(() => {
    if (resolveAdminSection("settings", section) !== "system") {
      return;
    }
    let cancelled = false;
    fetchSystemStatus()
      .then((status) => {
        if (!cancelled) {
          setSystemStatus(status);
        }
      })
      .catch(() => {

      });
    return () => {
      cancelled = true;
    };
  }, [section]);

  useDirtyNotification(onDirtyChange, isDirty);

  const updateBasicDraft = <TField extends keyof BasicSettingsDraft>(
    field: TField,
    value: BasicSettingsDraft[TField],
  ) => {
    if (isBusy) {
      return;
    }
    setBasicDraft((current) => ({ ...current, [field]: value }));
  };

  const handleTextFieldChange =
    (field: BasicSettingsStringField) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      if (isBusy) {
        return;
      }
      updateBasicDraft(field, event.target.value);
    };

  const handleTextInputChange =
    (setter: (value: string) => void) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      if (isBusy) {
        return;
      }
      setter(event.target.value);
    };

  const updateAdminAuthDraft = <TField extends keyof AdminAuthDraft>(field: TField, value: AdminAuthDraft[TField]) => {
    if (isBusy) {
      return;
    }
    setBasicDraft((current) => ({ ...current, adminAuth: { ...current.adminAuth, [field]: value } }));
  };

  const handleAdminAuthInputChange =
    <TField extends keyof AdminAuthDraft>(field: TField) =>
    (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      updateAdminAuthDraft(field, event.target.value as AdminAuthDraft[TField]);
    };

  const resetDirtyState = (closeConfirm = false) => {
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
    payload.resource_history_days = Number.parseInt(resourceHistoryDays, 10) || 7;

    return payload;
  };

  const runAction = useAsyncAction();

  // F3 第 4 条：把校验出错分区上报给侧栏红点；保存成功或本页卸载时清除。
  useEffect(() => {
    onValidationErrorSectionsChange?.(validationErrorSections);
  }, [validationErrorSections, onValidationErrorSectionsChange]);

  useEffect(() => () => onValidationErrorSectionsChange?.([]), [onValidationErrorSectionsChange]);

  const persistSettings = () => {
    if (isBusy || !settingsLoaded) {
      return;
    }
    const previousPath = settings?.admin_path || "";
    const previousUser = settings?.admin_user || "";
    const submittedAdminPass = adminPass.trim();
    void runAction({
      action: async () => {
        try {
          const next = await onSave(buildPayload());
          setValidationErrorSections([]);
          return next;
        } catch (error) {
          setValidationErrorSections(
            basicErrorSectionsFromMessage(error instanceof Error ? error.message : ""),
          );
          throw error;
        }
      },
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
        absorbSourceSignature(draftSignature({ ...canonicalDraft, adminPass: "" }));
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
        // P1：导出配置不含密钥，导入后必填项不全的渠道会静默失败；直接告知需要
        // 重新填写多少条，引导到渠道设置补全（与 App 的提示共用同一处文案）。
        const missingSecretNotice = missingSecretChannelsNotice(response.settings);
        if (missingSecretNotice) {
          messages.push(missingSecretNotice);
        }
        return messages.join("；");
      },
      onSuccess: (response) => {
        const canonicalDraft = basicSettingsDraft(response.settings ?? settings);
        setBasicDraft(canonicalDraft);
        setAdminPass("");
        absorbSourceSignature(draftSignature({ ...canonicalDraft, adminPass: "" }));
        resetDirtyState(true);
      },
      setBusy: setIsImporting,
    });
  };

  // F3 system 分区「版本」行：按五种状态推导副标题文案与配色。
  // 优先级：不支持在线更新 → 更新中/有新版本 → 正在检查 → 检查失败 → 已是最新。
  const systemUpdateUnsupported = systemUpdateInfo?.supported === false;
  const systemAlreadyLatest = Boolean(
    systemUpdateInfo?.supported !== false &&
      systemUpdateInfo?.latest_version &&
      !systemUpdateInfo.available,
  );
  const systemUpdateEntryVisible = Boolean(systemUpdateInfo?.available || systemUpdateInfo?.updating);
  const systemUpdateBusy = startingSystemUpdate || Boolean(systemUpdateInfo?.updating);
  const systemUpdateActionDisabled =
    startingSystemUpdate ||
    refreshingSystemUpdate ||
    systemUpdateInfo?.supported === false ||
    systemUpdateInfo?.updating;

  const systemVersionLabel = formatVersionLabel(
    systemUpdateInfo?.current_version || settings?.version,
  );
  const systemVersionStatus = (() => {
    if (systemUpdateUnsupported) {
      return { text: "当前部署不支持在线更新", tone: "default" as const };
    }
    // updating 优先于 refreshing：更新期间的 1.5s 轮询不应把副标题闪回「正在检查…」。
    if (systemUpdateInfo?.updating) {
      return {
        text: `发现新版本 ${formatVersionLabel(systemUpdateInfo.latest_version || "")}`,
        tone: "accent" as const,
      };
    }
    if (refreshingSystemUpdate) {
      return { text: "正在检查…", tone: "default" as const };
    }
    if (lastCheckFailed) {
      return { text: "检查失败", tone: "danger" as const };
    }
    if (systemUpdateInfo?.available) {
      return {
        text: `发现新版本 ${formatVersionLabel(systemUpdateInfo.latest_version || "")}`,
        tone: "accent" as const,
      };
    }
    if (systemAlreadyLatest) {
      return { text: "已是最新", tone: "default" as const };
    }
    return { text: "检查失败", tone: "danger" as const };
  })();
  const systemVersionStatusToneClass =
    systemVersionStatus.tone === "accent"
      ? "text-[var(--accent-text)]"
      : systemVersionStatus.tone === "danger"
        ? "text-[var(--danger-text)]"
        : "text-[var(--label-2)]";

  const handleCheckSystemUpdate = () => {
    setLastCheckFailed(false);
    onRefreshSystemUpdate()
      .then(() => {
        setLastCheckFailed(false);
      })
      .catch((error) => {
        // 检查失败仅在副标题短暂标注；错误本身仍走原有 toast 通道。
        setLastCheckFailed(true);
        reportUpdateActionError(error, "刷新服务端更新状态失败");
      });
  };

  // 与侧栏共用 ADMIN_PAGE_SECTIONS 这一份分区定义；非法 section 回落第一分区。
  const basicSections = adminPageSections("settings");
  const activeSection = resolveAdminSection("settings", section);
  const activeSectionLabel =
    basicSections.find((item) => item.id === activeSection)?.label || basicSections[0].label;
  const activeSectionIconMeta = SECTION_ICON_META[activeSection || ""];

  return (
    // E-03：设置页窄版外壳（页头、表单同宽 880px）；A-12：保存入口移入浮动保存条，
    // isDirty 为假时页头不显示保存按钮（0.1.2）。
    <div className={adminNarrowPageShellClass}>
      <AdminPageHeader
        breadcrumb={
          <>
            <span>基础设置</span>
            <ChevronRight aria-hidden="true" className="h-3 w-3" />
          </>
        }
        icon={activeSectionIconMeta?.icon}
        iconClassName={activeSectionIconMeta?.background}
        title={activeSectionLabel}
      />

      {activeSection === "credentials" ? (
        <AdminSectionPanel label="入口凭证">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="后台路径" htmlFor="admin-path">
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
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="管理员账号" htmlFor="admin-user">
              <Input
                id="admin-user"
                name="admin-user"
                className={adminInputClass}
                autoComplete="username"
                value={adminUser}
                disabled={isBusy}
                onChange={handleTextFieldChange("adminUser")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="新密码" htmlFor="admin-pass" hint="留空则不修改当前密码。">
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
            </AdminGroupedFieldRow>
          </AdminGroupedCard>
        </AdminSectionPanel>
      ) : null}

      {/* F3 security 分区：合并原 oauth / bruteforce / turnstile 三个分区，
          按序渲染三组卡片；字段 id / name 与校验逻辑保持不变，只改外层条件。 */}
      {activeSection === "security" ? (
        <div className="space-y-6">
        <AdminSectionPanel label="OAuth / OIDC 登录" className="space-y-6">
          <AdminGroupedCard>
            <AdminGroupedSwitchRow
              label="启用密码登录"
              htmlFor="password-login-enabled"
              hint="关闭后只能通过已配置的 OAuth / OIDC 提供商登录。"
            >
              <Switch
                id="password-login-enabled"
                checked={adminAuthDraftValue.passwordLoginEnabled}
                disabled={isBusy}
                onCheckedChange={(checked) => updateAdminAuthDraft("passwordLoginEnabled", Boolean(checked))}
              />
            </AdminGroupedSwitchRow>
          </AdminGroupedCard>

          <AdminSectionPanel label="GitHub OAuth" title="GitHub OAuth">
            <AdminGroupedCard>
              <AdminGroupedSwitchRow
                label="启用"
                htmlFor="github-oauth-enabled"
                hint="使用 GitHub 用户、邮箱或邮箱域名作为允许列表。"
              >
                <Switch
                  id="github-oauth-enabled"
                  checked={adminAuthDraftValue.githubEnabled}
                  disabled={isBusy}
                  onCheckedChange={(checked) => updateAdminAuthDraft("githubEnabled", Boolean(checked))}
                />
              </AdminGroupedSwitchRow>
              <AdminGroupedFieldRow label="显示名称" htmlFor="github-display-name">
                <Input
                  id="github-display-name"
                  name="github-display-name"
                  className={adminInputClass}
                  value={adminAuthDraftValue.githubDisplayName}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubDisplayName")}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="Client ID" htmlFor="github-client-id">
                <Input
                  id="github-client-id"
                  name="github-client-id"
                  autoComplete="off"
                  className={`${adminInputClass} data-text`}
                  value={adminAuthDraftValue.githubClientID}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubClientID")}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow
                label="Client Secret"
                htmlFor="github-client-secret"
                hint="重置后留空 = 保留当前 Secret，不会清空。"
              >
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
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="Scopes" htmlFor="github-scopes">
                <Textarea
                  id="github-scopes"
                  name="github-scopes"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.githubScopes}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubScopes")}
                  placeholder={"read:user\nuser:email"}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的用户名" htmlFor="github-allowed-logins">
                <Textarea
                  id="github-allowed-logins"
                  name="github-allowed-logins"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.githubAllowedLogins}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubAllowedLogins")}
                  placeholder="octocat"
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的邮箱" htmlFor="github-allowed-emails">
                <Textarea
                  id="github-allowed-emails"
                  name="github-allowed-emails"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.githubAllowedEmails}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubAllowedEmails")}
                  placeholder="admin@example.com"
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的邮箱域名" htmlFor="github-allowed-domains">
                <Textarea
                  id="github-allowed-domains"
                  name="github-allowed-domains"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.githubAllowedEmailDomains}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("githubAllowedEmailDomains")}
                  placeholder="example.com"
                />
              </AdminGroupedFieldRow>
              <AdminGroupedSwitchRow label="要求已验证邮箱" htmlFor="github-require-verified-email">
                <Switch
                  id="github-require-verified-email"
                  checked={adminAuthDraftValue.githubRequireVerifiedEmail}
                  disabled={isBusy}
                  onCheckedChange={(checked) => updateAdminAuthDraft("githubRequireVerifiedEmail", Boolean(checked))}
                />
              </AdminGroupedSwitchRow>
            </AdminGroupedCard>
          </AdminSectionPanel>

          <AdminSectionPanel label="自定义 OIDC" title="自定义 OIDC">
            <AdminGroupedCard>
              <AdminGroupedSwitchRow
                label="启用"
                htmlFor="oidc-enabled"
                hint="支持 Google、Authelia、Zitadel 或其他 OpenID Connect Issuer。"
              >
                <Switch
                  id="oidc-enabled"
                  checked={adminAuthDraftValue.oidcEnabled}
                  disabled={isBusy}
                  onCheckedChange={(checked) => updateAdminAuthDraft("oidcEnabled", Boolean(checked))}
                />
              </AdminGroupedSwitchRow>
              <AdminGroupedFieldRow label="显示名称" htmlFor="oidc-display-name">
                <Input
                  id="oidc-display-name"
                  name="oidc-display-name"
                  className={adminInputClass}
                  value={adminAuthDraftValue.oidcDisplayName}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcDisplayName")}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="Issuer URL" htmlFor="oidc-issuer-url">
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
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="Client ID" htmlFor="oidc-client-id">
                <Input
                  id="oidc-client-id"
                  name="oidc-client-id"
                  autoComplete="off"
                  className={`${adminInputClass} data-text`}
                  value={adminAuthDraftValue.oidcClientID}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcClientID")}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow
                label="Client Secret"
                htmlFor="oidc-client-secret"
                hint="重置后留空 = 保留当前 Secret，不会清空。"
              >
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
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="Scopes" htmlFor="oidc-scopes">
                <Textarea
                  id="oidc-scopes"
                  name="oidc-scopes"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.oidcScopes}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcScopes")}
                  placeholder={"openid\nemail\nprofile"}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的 Subject" htmlFor="oidc-allowed-subjects">
                <Textarea
                  id="oidc-allowed-subjects"
                  name="oidc-allowed-subjects"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.oidcAllowedSubjects}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcAllowedSubjects")}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的邮箱" htmlFor="oidc-allowed-emails">
                <Textarea
                  id="oidc-allowed-emails"
                  name="oidc-allowed-emails"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.oidcAllowedEmails}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcAllowedEmails")}
                  placeholder="admin@example.com"
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="允许的邮箱域名" htmlFor="oidc-allowed-domains">
                <Textarea
                  id="oidc-allowed-domains"
                  name="oidc-allowed-domains"
                  className={adminTextareaClass}
                  value={adminAuthDraftValue.oidcAllowedEmailDomains}
                  disabled={isBusy}
                  onChange={handleAdminAuthInputChange("oidcAllowedEmailDomains")}
                  placeholder="example.com"
                />
              </AdminGroupedFieldRow>
              <AdminGroupedSwitchRow label="要求 email_verified" htmlFor="oidc-require-email-verified">
                <Switch
                  id="oidc-require-email-verified"
                  checked={adminAuthDraftValue.oidcRequireEmailVerified}
                  disabled={isBusy}
                  onCheckedChange={(checked) => updateAdminAuthDraft("oidcRequireEmailVerified", Boolean(checked))}
                />
              </AdminGroupedSwitchRow>
            </AdminGroupedCard>
          </AdminSectionPanel>
        </AdminSectionPanel>

        <AdminSectionPanel label="防爆破策略">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="失败次数上限" htmlFor="login-fail-limit">
              <Input
                id="login-fail-limit"
                name="login-fail-limit"
                type="number"
                min={0}
                autoComplete="off"
                className={`${adminInputClass} tabular-nums`}
                value={loginFailLimit}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginFailLimit")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="统计窗口（分钟）" htmlFor="login-fail-window">
              <Input
                id="login-fail-window"
                name="login-fail-window"
                type="number"
                min={1}
                autoComplete="off"
                className={`${adminInputClass} tabular-nums`}
                value={loginFailWindow}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginFailWindow")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="锁定时长（分钟）" htmlFor="login-lock-minutes">
              <Input
                id="login-lock-minutes"
                name="login-lock-minutes"
                type="number"
                min={1}
                autoComplete="off"
                className={`${adminInputClass} tabular-nums`}
                value={loginLockMinutes}
                disabled={isBusy}
                onChange={handleTextFieldChange("loginLockMinutes")}
              />
            </AdminGroupedFieldRow>
          </AdminGroupedCard>
        </AdminSectionPanel>

        <AdminSectionPanel label="Cloudflare Turnstile">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="Site Key" htmlFor="turnstile-site-key">
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
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="Secret Key" htmlFor="turnstile-secret-key">
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
            </AdminGroupedFieldRow>
          </AdminGroupedCard>
        </AdminSectionPanel>
        </div>
      ) : null}

      {activeSection === "agent" ? (
        <AdminSectionPanel label="接入配置">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="Agent 对接地址" htmlFor="agent-endpoint">
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
                placeholder={settings?.agent_endpoint_suggestion || "例如：https://monitor.example.com…"}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow
              label="Agent Token"
              htmlFor="agent-token"
              hint={
                settings?.agent_token_set
                  ? "当前 Token 已回显，可选中复制；输入新值并保存即完成更换，更换后新接入 Agent 需使用新 Token。"
                  : "建议使用高强度随机 Token，修改后新接入 Agent 需使用新 Token。"
              }
            >
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
            </AdminGroupedFieldRow>
          </AdminGroupedCard>
        </AdminSectionPanel>
      ) : null}

      {activeSection === "site" ? (
        <AdminSectionPanel label="站点展示">
          <AdminGroupedCard>
            <AdminGroupedFieldRow label="站点 Title" htmlFor="site-title">
              <Input
                id="site-title"
                name="site-title"
                autoComplete="off"
                className={adminInputClass}
                value={siteTitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("siteTitle")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="站点 Icon" htmlFor="site-icon">
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
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="首页背景图" htmlFor="site-background-image">
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
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="首页标题" htmlFor="home-title">
              <Input
                id="home-title"
                name="home-title"
                autoComplete="off"
                className={adminInputClass}
                value={homeTitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("homeTitle")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="首页副标题" htmlFor="home-subtitle">
              <Input
                id="home-subtitle"
                name="home-subtitle"
                autoComplete="off"
                className={adminInputClass}
                value={homeSubtitle}
                disabled={isBusy}
                onChange={handleTextFieldChange("homeSubtitle")}
              />
            </AdminGroupedFieldRow>
            <AdminGroupedFieldRow label="界面语言" htmlFor="site-locale">
              <Select
                value={locale}
                disabled={isBusy}
                onValueChange={(value) => {
                  if (isBusy) {
                    return;
                  }
                  updateBasicDraft("locale", normalizeLocaleValue(value || undefined));
                }}
              >
                <SelectTrigger id="site-locale" size="sm" className={cn(adminSelectTriggerClass, "w-full sm:w-56")}>
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
            </AdminGroupedFieldRow>
            <AdminGroupedSwitchRow
              label="国家地区分组导航"
              htmlFor="region-group-enabled"
              hint="展示页按节点地区代码（C&R）二级分组。"
            >
              <Switch
                id="region-group-enabled"
                checked={regionGroupEnabled}
                disabled={isBusy}
                onCheckedChange={(checked) => {
                  if (isBusy) {
                    return;
                  }
                  updateBasicDraft("regionGroupEnabled", Boolean(checked));
                }}
              />
            </AdminGroupedSwitchRow>
          </AdminGroupedCard>
        </AdminSectionPanel>
      ) : null}

      {/* F3 system 分区：原「服务端更新」「配置备份」两分区合并。卡片 1「版本」改为
          截图样式的一行版式（主标题 + 状态副标题 + 右侧当前版本号与操作），不再有
          「当前版本 / 最新版本」两行悬浮小框与卡外横排按钮；卡片 3「运行信息」
          数据来自 F7 system/status。 */}
      {activeSection === "system" ? (
        <AdminSectionPanel label="系统信息" className="space-y-6">
          <AdminGroupedCard>
            <AdminGroupedFieldRow
              label={
                <span className="block">
                  <span className="block text-[15px] font-semibold leading-5 text-[var(--label-1)]">
                    版本
                  </span>
                  <span
                    className={`mt-1 block text-[13px] leading-5 ${systemVersionStatusToneClass}`}
                  >
                    {systemVersionStatus.text}
                  </span>
                </span>
              }
            >
              <div className="flex w-full flex-wrap items-center justify-end gap-x-3 gap-y-1.5 sm:w-auto">
                <span className="data-text text-[15px] leading-none text-[var(--label-2)]">
                  {systemVersionLabel}
                </span>
                {systemUpdateEntryVisible && systemUpdateInfo?.html_url ? (
                  <a
                    className={adminTextButtonClass}
                    href={systemUpdateInfo.html_url}
                    rel="noreferrer"
                    target="_blank"
                  >
                    发布说明
                  </a>
                ) : null}
                {systemUpdateEntryVisible ? (
                  <Button
                    type="button"
                    className={cn(adminPrimaryButtonClass, "h-[30px] min-w-0 px-4")}
                    disabled={systemUpdateActionDisabled}
                    onClick={() => {
                      onTriggerSystemUpdate().catch((error) => {
                        reportUpdateActionError(error, "服务端更新操作失败");
                      });
                    }}
                  >
                    {systemUpdateBusy ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : null}
                    {systemUpdateBusy ? "更新中…" : "更新"}
                  </Button>
                ) : (
                  <button
                    type="button"
                    className={adminTextButtonClass}
                    disabled={
                      refreshingSystemUpdate ||
                      startingSystemUpdate ||
                      Boolean(systemUpdateInfo?.updating)
                    }
                    onClick={handleCheckSystemUpdate}
                  >
                    检查
                  </button>
                )}
              </div>
            </AdminGroupedFieldRow>
          </AdminGroupedCard>

          <AdminSectionPanel label="配置备份" title="配置备份">
            <AdminGroupedCard>
              <AdminGroupedFieldRow label="导出配置" hint="下载当前配置（不含密钥）">
                <button
                  type="button"
                  className={adminTextButtonClass}
                  onClick={() => {
                    void onExport();
                  }}
                >
                  导出
                </button>
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="导入配置" hint="从备份文件恢复，密钥保持不变">
                <AlertDialog>
                  <AlertDialogTrigger className={adminTextButtonClass} type="button" disabled={isBusy}>
                    导入…
                  </AlertDialogTrigger>
                  <AlertDialogContent className={adminDialogContentClass} variant="danger">
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
              </AdminGroupedFieldRow>
            </AdminGroupedCard>

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
          </AdminSectionPanel>

          {/* 资源历史保留：节点 CPU / 内存 / 网络每 30 秒记录一个点，仅供 AI 运维助手分析；改设置即时生效。 */}
          <AdminSectionPanel label="资源历史" title="资源历史">
            <AdminGroupedCard>
              <AdminGroupedFieldRow
                label="资源历史保留"
                htmlFor="resource-history-days"
                hint="每 30 秒记录节点 CPU、内存、网络，供 AI 运维助手分析历史；修改后立即生效，缩短保留期会删除更早的数据。"
              >
                <Select
                  value={resourceHistoryDays}
                  disabled={isBusy}
                  onValueChange={(value) => {
                    if (isBusy) {
                      return;
                    }
                    updateBasicDraft("resourceHistoryDays", String(value || "7"));
                  }}
                >
                  <SelectTrigger
                    id="resource-history-days"
                    size="sm"
                    className={cn(adminSelectTriggerClass, "w-full sm:w-40")}
                  >
                    <SelectValue placeholder="选择保留期…">
                      {resourceHistoryDayOptions.find((item) => item.value === resourceHistoryDays)?.label ||
                        resourceHistoryDays}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent className={adminSelectContentClass}>
                    {resourceHistoryDayOptions.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </AdminGroupedFieldRow>
            </AdminGroupedCard>
          </AdminSectionPanel>

          {/* F3 卡片 3「运行信息」：每行左侧标签、右侧值（data-text 右对齐）；
              数据来自 F7 system/status。 */}
          <AdminSectionPanel label="运行信息" title="运行信息">
            <AdminGroupedCard>
              {[
                { label: "启动时间", value: formatRuntimeStartedAt(systemStatus?.started_at) },
                { label: "运行时长", value: formatUptimeZh(systemStatus?.uptime_sec) },
                {
                  label: "数据目录占用",
                  value: formatBinaryBytes(
                    (systemStatus?.data_dir?.state_bytes || 0) +
                      (systemStatus?.data_dir?.tsdb_bytes || 0),
                  ),
                },
              ].map((row) => (
                <AdminGroupedFieldRow key={row.label} label={row.label}>
                  <span className="data-text text-[13px] leading-5 text-[var(--label-1)]">
                    {row.value}
                  </span>
                </AdminGroupedFieldRow>
              ))}
            </AdminGroupedCard>
          </AdminSectionPanel>
        </AdminSectionPanel>
      ) : null}

      {isDirty ? (
        // A-12：保存入口移入浮动保存条；确认弹窗与禁用条件复用原有逻辑，只改呈现位置。
        // A-03：左侧「放弃修改」带二次确认（D-07），确认后回到服务端当前配置。
        <AdminSaveBar
          saving={isSaving}
          disabled={isBusy || !settingsLoaded}
          onSave={() => setIsConfirmOpen(true)}
          onDiscard={discardDraftChanges}
        />
      ) : null}

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
    </div>
  );
}
