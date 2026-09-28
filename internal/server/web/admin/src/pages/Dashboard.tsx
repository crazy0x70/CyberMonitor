import { Fragment, type MouseEvent, type ReactNode } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import {
  adminMutedTextClass,
  adminPageShellClass,
} from "@/lib/admin-ui";
import type { NodeView, SettingsView } from "@/lib/admin-types";
import {
  adminPageHref,
  resolveNodeSelections,
  shouldHandleAdminNavigation,
  type AdminPage,
} from "@/lib/admin-format";
import { cn } from "@/lib/utils";

type Page = AdminPage;

export interface DashboardProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  onNavigate: (page: Page) => void;
}

type ChannelStatus = {
  label: string;
  configured: boolean;
};

type ConfigRow = {
  key: string;
  label: string;
  value: ReactNode;
  page: Page;
};

function channelStatuses(settings: SettingsView | null): ChannelStatus[] {
  return [
    { label: "Telegram", configured: Boolean(settings?.alert_telegram_token_set) },
    { label: "飞书", configured: Boolean(settings?.alert_webhook_set) },
  ];
}

function readProviderLabel(settings: SettingsView | null, provider: string) {
  if (!provider) return "未配置";
  if (provider === "openai") return "OpenAI";
  if (provider.startsWith("openai_compatible:")) {
    const id = provider.split(":")[1] || "";
    const match = settings?.ai_settings?.openai_compatibles?.find((item) => item.id === id);
    return match?.name || "兼容服务商";
  }
  if (provider === "openai_compatible") {
    return "OpenAI 兼容";
  }
  return provider;
}

function summarizeAI(settings: SettingsView | null) {
  const ai = settings?.ai_settings;
  if (!ai) return "";
  return readProviderLabel(settings, ai.command_provider || "openai");
}

function countUngrouped(nodes: NodeView[]) {

  return nodes.filter((node) => resolveNodeSelections(node).length === 0).length;
}

function renderChannelValue(settings: SettingsView | null) {
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-3 gap-y-1">
      {channelStatuses(settings).map((channel, index) => (
        <Fragment key={channel.label}>
          {index > 0 ? (
            <span aria-hidden="true" className="text-[var(--label-3)]">
              ·
            </span>
          ) : null}
          <span className="inline-flex items-baseline whitespace-nowrap">
            <span
              className={cn(
                "mr-1.5 inline-block h-1.5 w-1.5 rounded-full",
                channel.configured ? "bg-emerald-500" : "bg-slate-300 dark:bg-neutral-600",
              )}
            />
            {channel.label} {channel.configured ? "已配置" : "未配置"}
          </span>
        </Fragment>
      ))}
    </span>
  );
}

export default function Dashboard({ settings, nodes, onNavigate }: DashboardProps) {
  const total = nodes.length;
  const online = nodes.filter((node) => node.status === "online").length;
  const offline = total - online;
  const ungrouped = countUngrouped(nodes);

  const metrics = [
    { label: "总节点数", value: total },
    { label: "在线节点", value: online },
    { label: "离线节点", value: offline },
    { label: "未分组节点", value: ungrouped },
  ] as const;

  const aiProvider = summarizeAI(settings);

  const handleNavigateLink = (event: MouseEvent<HTMLAnchorElement>, page: Page) => {
    if (!shouldHandleAdminNavigation(event)) {
      return;
    }
    event.preventDefault();
    onNavigate(page);
  };

  const configRows: ConfigRow[] = [
    {
      key: "channels",
      label: "告警渠道",
      value: renderChannelValue(settings),
      page: "alerts",
    },
    {
      key: "ai-provider",
      label: "AI 服务商",
      value: aiProvider ? (
        <span className="text-slate-800 dark:text-neutral-100">{aiProvider}</span>
      ) : (
        <span className={`text-[13px] ${adminMutedTextClass}`}>未配置</span>
      ),
      page: "ai",
    },
    {
      key: "entrance",
      label: "安全入口",
      value: <span className="data-text">{settings?.admin_path || "/admin"}</span>,
      page: "settings",
    },
  ];

  const quickLinks: ReadonlyArray<{ title: string; page: Page }> = [
    { title: "探测设置", page: "probes" },
    { title: "分组管理", page: "groups" },
    { title: "通知告警", page: "alerts" },
  ];

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader as="section" title="首页" />

      <AdminMetricStrip ariaLabel="节点统计" items={metrics} />

      { }
      <AdminPanel title="核心配置">
          <dl aria-label="核心配置" className="text-slate-700 dark:text-neutral-200">
            {configRows.map((row) => (
              <div
                key={row.key}
                className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-[var(--separator)] py-3 first:pt-2.5 last:border-b-0"
              >
                <dt className="text-[13px] font-medium leading-5 text-[var(--label-2)]">
                  {row.label}
                </dt>
                <dd className="flex min-w-0 flex-wrap items-baseline justify-end gap-x-3 gap-y-1 text-[13px] leading-5">
                  {row.value}
                  <a
                    href={adminPageHref(row.page)}
                    className="whitespace-nowrap font-medium text-primary transition-colors hover:underline focus-visible:underline"
                    onClick={(event) => handleNavigateLink(event, row.page)}
                  >
                    前往 →
                    <span className="sr-only">{row.label}</span>
                  </a>
                </dd>
              </div>
            ))}
        </dl>
      </AdminPanel>

      <section aria-label="快捷入口" className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
        {quickLinks.map((item) => (
          <a
            key={item.page}
            href={adminPageHref(item.page)}
            className="whitespace-nowrap text-[13px] font-medium text-slate-500 outline-none transition-colors hover:text-primary focus-visible:underline dark:text-neutral-400"
            onClick={(event) => handleNavigateLink(event, item.page)}
          >
            {item.title} <span aria-hidden="true">→</span>
          </a>
        ))}
      </section>
    </div>
  );
}
