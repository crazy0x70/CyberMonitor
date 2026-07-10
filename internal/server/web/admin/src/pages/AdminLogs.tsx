import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchAdminLogs } from "@/lib/admin-api";
import type { AdminLogEntry, AdminLogLevel } from "@/lib/admin-types";
import { getErrorMessage } from "@/lib/admin-format";
import {
  adminActionButtonClass,
  adminDangerBadgeClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminStatEyebrowClass,
  adminSuccessBadgeClass,
  adminSurfaceCardClass,
  adminWarningBadgeClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";
import { Bug, Info, ScrollText, TriangleAlert } from "lucide-react";
import { toast } from "sonner";

const LOG_LIMIT = 300;
const LOG_POLL_INTERVAL_MS = 2000;

const levelOptions: Array<{ value: AdminLogLevel; label: string }> = [
  { value: "all", label: "全部" },
  { value: "info", label: "信息" },
  { value: "warning", label: "警告" },
  { value: "error", label: "错误" },
  { value: "debug", label: "调试" },
  { value: "silent", label: "静默" },
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

function levelIcon(level: AdminLogEntry["level"]) {
  switch (level) {
    case "error":
      return <TriangleAlert className="h-4 w-4 text-rose-500 dark:text-rose-300" />;
    case "warning":
      return <TriangleAlert className="h-4 w-4 text-amber-500 dark:text-amber-300" />;
    case "debug":
      return <Bug className="h-4 w-4 text-slate-500 dark:text-slate-300" />;
    default:
      return <Info className="h-4 w-4 text-sky-500 dark:text-sky-300" />;
  }
}

function formatLogTime(entry: AdminLogEntry) {
  const date = new Date(entry.timestamp * 1000);
  if (Number.isNaN(date.getTime())) {
    return entry.time || "--";
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

export default function AdminLogs() {
  const [level, setLevel] = useState<AdminLogLevel>("all");
  const [entries, setEntries] = useState<AdminLogEntry[]>([]);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);

  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      counts[entry.level] = (counts[entry.level] || 0) + 1;
    }
    return counts;
  }, [entries]);

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

  return (
    <div className={adminPageShellClass}>
      <div className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>日志查看</h1>
          <p className={cn("mt-2 text-sm", adminMutedTextClass)}>
            {loadedAt ? `实时同步 ${new Date(loadedAt).toLocaleTimeString("zh-CN", { hour12: false })}` : "实时同步中"}
          </p>
        </div>
      </div>

      <Card className={adminSurfaceCardClass}>
        <CardHeader className="border-b px-6 py-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <CardTitle className="flex items-center gap-2">
              <ScrollText className="h-5 w-5 text-sky-500 dark:text-sky-300" />
              运行日志
            </CardTitle>
            <div className="grid grid-cols-3 gap-2 sm:flex sm:flex-wrap sm:justify-end">
              {levelOptions.map((item) => (
                <Button
                  key={item.value}
                  className={cn(
                    "h-9 px-3 text-xs font-bold",
                    level === item.value ? adminPrimaryButtonClass : adminActionButtonClass,
                  )}
                  onClick={() => setLevel(item.value)}
                  type="button"
                  variant={level === item.value ? "default" : "outline"}
                >
                  {item.label}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="px-0 py-0">
          <div className="grid grid-cols-2 gap-px border-b bg-border sm:grid-cols-4">
            {(["info", "warning", "error", "debug"] as const).map((item) => (
              <div key={item} className="bg-background px-6 py-4">
                <p className={adminStatEyebrowClass}>{levelLabels[item]}</p>
                <p className="mt-2 text-2xl font-semibold text-foreground">{levelCounts[item] || 0}</p>
              </div>
            ))}
          </div>

          {entries.length === 0 ? (
            <div className="flex min-h-[280px] items-center justify-center px-6 py-12 text-sm text-muted-foreground">
              {level === "silent" ? "静默" : "暂无日志"}
            </div>
          ) : (
            <div className="max-h-[62vh] overflow-auto">
              <div className="min-w-[760px] divide-y divide-border">
                {entries.map((entry) => (
                  <div key={entry.id} className="grid grid-cols-[180px_92px_110px_1fr] gap-4 px-6 py-4 text-sm">
                    <div className="font-mono text-xs text-muted-foreground">{formatLogTime(entry)}</div>
                    <div>
                      <Badge className={levelBadgeClass(entry.level)}>{levelLabels[entry.level]}</Badge>
                    </div>
                    <div className="font-mono text-xs uppercase tracking-[0.14em] text-muted-foreground">
                      {entry.source || "server"}
                    </div>
                    <div className="flex min-w-0 items-start gap-3">
                      <span className="mt-0.5 shrink-0">{levelIcon(entry.level)}</span>
                      <p className="min-w-0 break-words leading-6 text-foreground">{entry.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
