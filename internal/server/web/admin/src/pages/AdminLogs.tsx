import { useEffect, useMemo, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { fetchAdminLogs } from "@/lib/admin-api";
import type { AdminLogEntry, AdminLogLevel } from "@/lib/admin-types";
import { getErrorMessage } from "@/lib/admin-format";
import {
  adminCompactActionButtonClass,
  adminDangerBadgeClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminPageShellClass,
  adminSuccessBadgeClass,
  adminWarningBadgeClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";
import { Radio } from "lucide-react";
import { toast } from "sonner";

const LOG_LIMIT = 300;
const LOG_POLL_INTERVAL_MS = 2000;

const levelOptions: Array<{ value: AdminLogLevel; label: string }> = [
  { value: "all", label: "全部" },
  { value: "info", label: "信息" },
  { value: "warning", label: "警告" },
  { value: "error", label: "错误" },
  { value: "debug", label: "调试" },
];

const levelLabels: Record<Exclude<AdminLogLevel, "all">, string> = {
  info: "信息",
  warning: "警告",
  error: "错误",
  debug: "调试",
  silent: "静默",
};

function levelBadgeClass(level: AdminLogEntry["level"]) {
  switch (level) {
    case "error":
      return adminDangerBadgeClass;
    case "warning":
      return adminWarningBadgeClass;
    case "debug":
    case "silent":
      return adminNeutralBadgeClass;
    default:
      return adminSuccessBadgeClass;
  }
}

function formatLogTime(entry: AdminLogEntry) {
  const date = new Date(entry.timestamp * 1000);
  if (Number.isNaN(date.getTime())) {
    return entry.time || "--";
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

const logTableColumns: ReadonlyArray<AdminDataTableColumn<AdminLogEntry>> = [
  {
    key: "time",
    label: "时间",
    width: "180px",
    mono: true,
    render: (entry) => (
      <span className="text-xs text-slate-500 dark:text-neutral-400">
        {formatLogTime(entry)}
      </span>
    ),
  },
  {
    key: "source",
    label: "来源",
    width: "120px",
    render: (entry) => entry.source || "server",
  },
  {
    key: "level",
    label: "等级",
    width: "110px",
    render: (entry) => <Badge className={levelBadgeClass(entry.level)}>{levelLabels[entry.level]}</Badge>,
  },
  {
    key: "message",
    label: "消息",
    align: "left",
    width: "auto",
    render: (entry) => (
      <span className="block truncate text-left" title={entry.message}>
        {entry.message}
      </span>
    ),
  },
];

export default function AdminLogs() {
  const [level, setLevel] = useState<AdminLogLevel>("all");
  const [detailEntry, setDetailEntry] = useState<AdminLogEntry | null>(null);
  const [entries, setEntries] = useState<AdminLogEntry[]>([]);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);

  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      counts[entry.level] = (counts[entry.level] || 0) + 1;
    }
    return counts;
  }, [entries]);

  const orderedEntries = useMemo(() => [...entries].reverse(), [entries]);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let errorNotified = false;

    async function loadLogs() {
      if (inFlight) {
        return;
      }
      inFlight = true;
      try {
        const data = await fetchAdminLogs(level, LOG_LIMIT);
        if (!active) {
          return;
        }
        setEntries(data.entries || []);
        setLoadedAt(Date.now());
        errorNotified = false;
      } catch (error) {
        if (active && !errorNotified) {
          toast.error(getErrorMessage(error, "加载日志失败"));
          errorNotified = true;
        }
      } finally {
        inFlight = false;
      }
    }

    void loadLogs();
    const timer = window.setInterval(() => {
      void loadLogs();
    }, LOG_POLL_INTERVAL_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [level]);

  const metricItems = (["info", "warning", "error", "debug"] as const).map((item) => ({
    label: levelLabels[item],
    value: levelCounts[item] || 0,
  }));

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        title="日志查看"
        description={
          loadedAt ? `实时同步 ${new Date(loadedAt).toLocaleTimeString("zh-CN", { hour12: false })}` : "实时同步中"
        }
      />

      <AdminMetricStrip ariaLabel="等级统计" items={metricItems} />

      <AdminPanel
        title="运行日志"
        icon={<Radio className="h-4 w-4 text-[var(--label-3)]" />}
        actions={
          <div className="grid grid-cols-3 gap-2 sm:flex sm:flex-wrap">
            {levelOptions.map((item) => (
              <Button
                key={item.value}
                className={cn(
                  "h-9 min-w-[76px] px-3 text-xs font-medium",
                  level === item.value
                    ? "bg-slate-900 text-white hover:bg-slate-800 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white"
                    : adminCompactActionButtonClass,
                )}
                onClick={() => setLevel(item.value)}
                type="button"
                variant={level === item.value ? "default" : "outline"}
              >
                {item.label}
              </Button>
            ))}
          </div>
        }
      >
        <p className={cn("pb-4 text-xs", adminMutedTextClass)}>
          仅展示最近 {LOG_LIMIT} 条日志；计数为当前过滤窗口内的分布。
        </p>
        <AdminDataTable
          ariaLabel="运行日志"
          columns={logTableColumns}
          rows={orderedEntries}
          rowKey={(entry) => String(entry.id)}
          onRowClick={(entry) => setDetailEntry(entry)}
          emptyLabel="暂无日志"

          className="[&>table>tbody>tr]:[content-visibility:auto] [&>table>tbody>tr]:[contain-intrinsic-size:auto_41px]"
        />
      </AdminPanel>

      { }
      <AdminDrawer
        open={detailEntry !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDetailEntry(null);
          }
        }}
        title={detailEntry ? levelLabels[detailEntry.level] || "日志" : "日志"}
        description={
          detailEntry
            ? `${new Date(detailEntry.timestamp * 1000).toLocaleString("zh-CN", { hour12: false })} · ${detailEntry.source}`
            : undefined
        }
      >
        {detailEntry ? (
          <section>
            <h3 className="text-sm font-medium text-slate-900 dark:text-neutral-50">完整消息</h3>
            <p className="data-text mt-3 select-text break-words whitespace-pre-wrap text-sm leading-relaxed text-slate-700 dark:text-neutral-200">
              {detailEntry.message}
            </p>
          </section>
        ) : null}
      </AdminDrawer>
    </div>
  );
}
