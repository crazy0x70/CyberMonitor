import type { MouseEvent } from "react";
import {
  Activity,
  AlertCircle,
  Bell,
  Bot,
  ChevronRight,
  FolderTree,
  LayoutList,
  Server,
  Settings,
  ShieldAlert,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  adminCompactActionButtonClass,
  adminQuickActionButtonClass,
  adminMutedTextClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminSurfaceCardClass,
  adminSectionHeaderClass,
  adminStatCardClass,
  adminStatCardHeaderClass,
  adminStatEyebrowClass,
  adminStatIconChipClass,
  adminStatIconChipClassByTone,
  adminStatSurfaceClassByTone,
  adminStatValueToneClassByTone,
  adminSummaryIconChipClass,
  adminSummaryIconToneClassByTone,
  adminSummaryRowClass,
  adminSummaryWarningIconChipClass,
  adminSummaryWarningRowClass,
  adminSummaryWarningTextClass,
  adminSummaryWarningTitleClass,
  adminWarningOutlineButtonClass,
} from "@/lib/admin-ui";
import type { NodeView, SettingsView } from "@/lib/admin-types";
import { cn } from "@/lib/utils";

type Page = "dashboard" | "servers" | "groups" | "probes" | "settings" | "alerts" | "ai";

export interface DashboardProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  onNavigate: (page: Page) => void;
}

function dashboardPageHref(page: Page) {
  if (typeof window === "undefined") {
    return page === "dashboard" ? "/" : `/?page=${page}`;
  }
  const nextURL = new URL(window.location.href);
  if (page === "dashboard") {
    nextURL.searchParams.delete("page");
  } else {
    nextURL.searchParams.set("page", page);
  }
  return `${nextURL.pathname}${nextURL.search}${nextURL.hash}`;
}

function shouldHandleDashboardNavigation(event: MouseEvent<HTMLAnchorElement>) {
  return !(
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  );
}

function summarizeChannels(settings: SettingsView | null) {
  const telegram = settings?.alert_telegram_token ? "TG 已配" : "TG 未配";
  const webhook = settings?.alert_webhook ? "飞书已配" : "飞书未配";
  return `${telegram}，${webhook}`;
}

function readProviderLabel(settings: SettingsView | null, provider: string) {
  if (!provider) return "未配置";
  if (provider === "openai") return "OpenAI";
  if (provider === "gemini") return "Gemini";
  if (provider === "volcengine") return "Volcengine";
  if (provider.startsWith("openai_compatible:")) {
    const id = provider.split(":")[1] || "";
    const match = settings?.ai_settings?.openai_compatibles?.find((item) => item.id === id);
    return match?.name || "兼容服务商";
  }
  return provider;
}

function summarizeAI(settings: SettingsView | null) {
  const ai = settings?.ai_settings;
  if (!ai) return "未配置";
  return readProviderLabel(settings, ai.command_provider || ai.default_provider || "openai");
}

function countUngrouped(nodes: NodeView[]) {
  return nodes.filter((node) => !(node.groups && node.groups.length > 0) && !node.group).length;
}

export default function Dashboard({ settings, nodes, onNavigate }: DashboardProps) {
  const total = nodes.length;
  const online = nodes.filter((node) => node.status === "online").length;
  const offline = total - online;
  const ungrouped = countUngrouped(nodes);
  const adminPathRisk = settings?.admin_path === "/admin";

  const metrics = [
    {
      title: "总节点数",
      value: total,
      icon: Server,
      tone: "neutral",
    },
    {
      title: "在线节点",
      value: online,
      icon: Activity,
      tone: "success",
    },
    {
      title: "离线节点",
      value: offline,
      icon: AlertCircle,
      tone: "danger",
    },
    {
      title: "未分组节点",
      value: ungrouped,
      icon: FolderTree,
      tone: "warning",
    },
  ] as const;

  const summaryCards = [
    {
      title: "告警渠道",
      description: summarizeChannels(settings),
      icon: Bell,
      page: "alerts" as const,
      tone: "success" as const,
      actionLabel: "通知告警",
    },
    {
      title: "AI 服务商",
      description: summarizeAI(settings),
      icon: Bot,
      page: "ai" as const,
      tone: "info" as const,
      actionLabel: "AI 服务商",
    },
  ];

  const handleNavigateLink = (event: MouseEvent<HTMLAnchorElement>, page: Page) => {
    if (!shouldHandleDashboardNavigation(event)) {
      return;
    }
    event.preventDefault();
    onNavigate(page);
  };

  return (
    <div className={adminPageShellClass}>
      <section className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>首页</h1>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((item) => {
          const Icon = item.icon;
          return (
            <Card
              key={item.title}
              className={`${adminStatCardClass} ${adminStatSurfaceClassByTone[item.tone]}`}
            >
              <CardHeader className={adminStatCardHeaderClass}>
                <div>
                  <CardDescription className={adminStatEyebrowClass}>
                    {item.title}
                  </CardDescription>
                  <CardTitle className={`mt-3 text-3xl font-black tracking-tighter ${adminStatValueToneClassByTone[item.tone]}`}>
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
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr] animate-in fade-in slide-in-from-bottom-8 duration-1000 delay-300 fill-mode-both">
        <Card className={`overflow-hidden border-none ${adminSurfaceCardClass}`}>
          <CardHeader className={adminSectionHeaderClass}>
            <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/10 text-sky-500">
                <Settings className="h-5 w-5" />
              </div>
              核心配置
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 p-6">
            {summaryCards.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.title} className={`${adminSummaryRowClass} group hover:bg-slate-50/50 dark:hover:bg-slate-900/50`}>
                  <div className="flex min-w-0 items-center gap-4">
                    <div
                      className={`${adminSummaryIconChipClass} ${adminSummaryIconToneClassByTone[item.tone]} group-hover:scale-110 transition-transform`}
                    >
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <h4 className="font-bold text-slate-900 dark:text-slate-100">{item.title}</h4>
                      <p className={`mt-1 line-clamp-1 text-[13px] font-medium leading-relaxed ${adminMutedTextClass}`}>{item.description}</p>
                    </div>
                  </div>
                  <a
                    href={dashboardPageHref(item.page)}
                    className={cn(adminCompactActionButtonClass, "self-start sm:self-auto hover:bg-white dark:hover:bg-slate-950")}
                    onClick={(event) => handleNavigateLink(event, item.page)}
                  >
                    管理 <ChevronRight className="ml-1 h-4 w-4" />
                  </a>
                </div>
              );
            })}

            <div className={adminPathRisk ? adminSummaryWarningRowClass : adminSummaryRowClass}>
              <div className="flex min-w-0 items-center gap-4">
                <div
                  className={
                    adminPathRisk
                      ? adminSummaryWarningIconChipClass
                      : `${adminSummaryIconChipClass} ${adminSummaryIconToneClassByTone.neutral}`
                  }
                >
                  <ShieldAlert className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <h4
                    className={
                      adminPathRisk
                        ? adminSummaryWarningTitleClass
                        : "font-bold text-slate-900 dark:text-slate-100"
                    }
                  >
                    安全入口
                  </h4>
                  <p
                    className={
                      adminPathRisk
                        ? `mt-1 line-clamp-1 text-[13px] font-medium leading-relaxed ${adminSummaryWarningTextClass}`
                        : `mt-1 line-clamp-1 text-[13px] font-medium leading-relaxed ${adminMutedTextClass}`
                    }
                  >
                    路径: {settings?.admin_path || "/admin"}
                  </p>
                </div>
              </div>
              <a
                href={dashboardPageHref("settings")}
                className={
                  adminPathRisk
                    ? `${adminWarningOutlineButtonClass} self-start h-10 px-5 sm:self-auto`
                    : cn(adminCompactActionButtonClass, "self-start sm:self-auto hover:bg-white dark:hover:bg-slate-950")
                }
                onClick={(event) => handleNavigateLink(event, "settings")}
              >
                配置 <ChevronRight className="ml-1 h-4 w-4" />
              </a>
            </div>
          </CardContent>
        </Card>

        <Card className={`overflow-hidden border-none ${adminSurfaceCardClass}`}>
          <CardHeader className={adminSectionHeaderClass}>
            <CardTitle className="flex items-center gap-3 text-lg font-black tracking-tight">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-500">
                <LayoutList className="h-5 w-5" />
              </div>
              快捷入口
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 p-6">
            <a
              href={dashboardPageHref("probes")}
              className={`${adminQuickActionButtonClass} group`}
              onClick={(event) => handleNavigateLink(event, "probes")}
            >
              <Activity className="mr-3 h-5 w-5 text-emerald-500 transition-transform group-hover:scale-110" />
              探测设置
            </a>
            <a
              href={dashboardPageHref("groups")}
              className={`${adminQuickActionButtonClass} group`}
              onClick={(event) => handleNavigateLink(event, "groups")}
            >
              <FolderTree className="mr-3 h-5 w-5 text-amber-500 transition-transform group-hover:scale-110" />
              分组管理
            </a>
            <a
              href={dashboardPageHref("alerts")}
              className={`${adminQuickActionButtonClass} group`}
              onClick={(event) => handleNavigateLink(event, "alerts")}
            >
              <Bell className="mr-3 h-5 w-5 text-sky-500 transition-transform group-hover:scale-110" />
              通知告警
            </a>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
