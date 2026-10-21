import { useEffect, useMemo, useState, type ReactNode } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import {
  AdminDataTable,
  type AdminDataTableColumn,
  adminStatusBadgeClass,
  type AdminStatusBadgeTone,
} from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { Button } from "@/components/ui/button";
import { fetchAdminLogs } from "@/lib/admin-api";
import type { AdminLogEntry, AdminLogLevel } from "@/lib/admin-types";
import { getErrorMessage } from "@/lib/admin-format";
import {
  adminHelpTextClass,
  adminPageShellClass,
  adminSegmentedItemActiveClass,
  adminSegmentedItemClass,
  adminSegmentedItemInactiveClass,
  adminSegmentedTrackClass,
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

// A-18：日志等级徽标由 A-09 统一规格渲染（adminStatusBadgeClass，无边框 + 前置圆点），
// 颜色映射按 A-09 第 6 条：信息 accent / 警告 warn / 错误 danger / 调试·静默中性。
function levelBadgeTone(level: AdminLogEntry["level"]): AdminStatusBadgeTone {
  switch (level) {
    case "error":
      return "danger";
    case "warning":
      return "warn";
    case "info":
      return "accent";
    default:
      return "neutral";
  }
}

// A-18 第 5 条：时间列拆「日期 --label-3 / 时间 --label-1」两个 span，仅拆显示不改数据。
// 用与旧渲染同一个 toLocaleString 的结果在最后一个空格处切分，保证字符串逐字符一致。
function renderLogTime(entry: AdminLogEntry) {
  const date = new Date(entry.timestamp * 1000);
  if (Number.isNaN(date.getTime())) {
    return <span className="text-[var(--label-3)]">{entry.time || "--"}</span>;
  }
  const full = date.toLocaleString("zh-CN", { hour12: false });
  const separatorIndex = full.lastIndexOf(" ");
  if (separatorIndex < 0) {
    return <span className="text-[var(--label-1)]">{full}</span>;
  }
  return (
    <span>
      <span className="text-[var(--label-3)]">{full.slice(0, separatorIndex)}</span>{" "}
      <span className="text-[var(--label-1)]">{full.slice(separatorIndex + 1)}</span>
    </span>
  );
}

// A-18 第 4 条：node=lax-04 这类键值对用数据字体（.num 在后台的等价实现为 .data-text，
// 见 E-06）。仅拆分显示，不改消息文本；[CyberMonitor] 前缀弱化按 0.1.2 不做。
function renderLogMessage(message: string) {
  const keyValuePairPattern = /[A-Za-z_][\w.-]*=(?:"[^"]*"|'[^']*'|\S+)/g;
  const segments: ReactNode[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = keyValuePairPattern.exec(message)) !== null) {
    if (match.index > cursor) {
      segments.push(message.slice(cursor, match.index));
    }
    segments.push(
      <span key={`kv-${match.index}`} className="data-text">
        {match[0]}
      </span>,
    );
    cursor = match.index + match[0].length;
  }
  if (cursor < message.length) {
    segments.push(message.slice(cursor));
  }
  return segments;
}

const logTableColumns: ReadonlyArray<AdminDataTableColumn<AdminLogEntry>> = [
  {
    key: "time",
    label: "时间",
    width: "180px",
    mono: true,
    render: (entry) => renderLogTime(entry),
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
    width: "96px",
    render: (entry) => (
      <span className={adminStatusBadgeClass(levelBadgeTone(entry.level))}>
        {levelLabels[entry.level]}
      </span>
    ),
  },
  {
    key: "message",
    label: "消息",
    align: "left",
    // P2：单行省略依赖固定表单宽，列宽交给 AdminDataTable 的 fixed 布局（table-fixed）
    // 计算——消息列占满剩余宽度，其余列宽不被挤压。
    render: (entry) => (
      <span className="block truncate text-left" title={entry.message}>
        {renderLogMessage(entry.message)}
      </span>
    ),
  },
];

export default function AdminLogs() {
  const [level, setLevel] = useState<AdminLogLevel>("all");
  const [detailEntry, setDetailEntry] = useState<AdminLogEntry | null>(null);
  const [entries, setEntries] = useState<AdminLogEntry[]>([]);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  // 轮询失败标记：失败时页头不能继续显示绿色「实时同步」，成功一次即恢复。
  const [syncFailed, setSyncFailed] = useState(false);

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
    // 2s 轮询内容未变（长度+首尾 id 一致）时跳过 setEntries/setLoadedAt，
    // 避免每 2s 全表重渲染。id 递增且窗口固定取最新 N 条，签名足够可靠。
    let lastSignature = "";

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
        errorNotified = false;
        setSyncFailed(false);
        const nextEntries = data.entries || [];
        const nextSignature = `${nextEntries.length}:${nextEntries[0]?.id ?? ""}:${
          nextEntries[nextEntries.length - 1]?.id ?? ""
        }`;
        if (nextSignature === lastSignature) {
          return;
        }
        lastSignature = nextSignature;
        setEntries(nextEntries);
        setLoadedAt(Date.now());
      } catch (error) {
        if (active) {
          setSyncFailed(true);
          if (!errorNotified) {
            toast.error(getErrorMessage(error, "加载日志失败"));
            errorNotified = true;
          }
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
      {/* M-05 呼吸绿点（A-18 第 2 条）：box-shadow 由 0 扩散到 6px、透明度 .35→0、2.4s 无限循环；
          prefers-reduced-motion 下为静态点（第 7 节通用约束）。任务只允许改本文件，样式随组件内联。 */}
      <style>{`
@keyframes cm-log-live-dot-breath {
  from {
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 35%, transparent);
  }
  to {
    box-shadow: 0 0 0 6px transparent;
  }
}
.cm-log-live-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: var(--r-full, 9999px);
  background: var(--ok);
}
@media (prefers-reduced-motion: no-preference) {
  .cm-log-live-dot {
    animation: cm-log-live-dot-breath 2.4s ease-out infinite;
  }
}
`}</style>
      <AdminPageHeader
        title="日志查看"
        description={
          <span className="inline-flex items-center gap-2">
            {syncFailed ? (
              // 失败态：琥珀静态点（不做呼吸动画），文字说明重试中 / 展示旧数据。
              <span
                aria-hidden="true"
                className="size-1.5 shrink-0 rounded-full bg-[var(--warn)]"
              />
            ) : (
              <span aria-hidden="true" className="cm-log-live-dot shrink-0" />
            )}
            {syncFailed
              ? entries.length > 0
                ? "同步失败，显示最后一次成功获取的日志"
                : "同步失败，正在重试"
              : loadedAt
                ? `实时同步 ${new Date(loadedAt).toLocaleTimeString("zh-CN", { hour12: false })}`
                : "实时同步中"}
          </span>
        }
      />

      <AdminMetricStrip ariaLabel="等级统计" items={metricItems} />

      <AdminPanel
        title="运行日志"
        icon={<Radio className="h-4 w-4 text-[var(--label-3)]" />}
        actions={
          <div className={cn(adminSegmentedTrackClass, "sm:w-auto")}>
            {levelOptions.map((item) => (
              <Button
                key={item.value}
                className={cn(
                  adminSegmentedItemClass,
                  "sm:min-w-[52px] sm:flex-none",
                  level === item.value
                    ? adminSegmentedItemActiveClass
                    : adminSegmentedItemInactiveClass,
                )}
                onClick={() => setLevel(item.value)}
                type="button"
                variant={null}
              >
                {item.label}
              </Button>
            ))}
          </div>
        }
      >
        <p className={cn("pb-4", adminHelpTextClass)}>
          仅展示最近 {LOG_LIMIT} 条日志；计数为当前过滤窗口内的分布。
        </p>
        <AdminDataTable
          ariaLabel="运行日志"
          columns={logTableColumns}
          // P2：fixed（table-fixed）把表格宽度约束在卡片内，消息列才能单行省略；
          // 窄屏下由表格自身的横向滚动容器承接最小宽度（44rem），不撑破页面。
          fixed
          rows={orderedEntries}
          rowKey={(entry) => String(entry.id)}
          onRowClick={(entry) => setDetailEntry(entry)}
          emptyLabel="暂无日志"
          className="[&>table>tbody>tr]:[content-visibility:auto] [&>table>tbody>tr]:[contain-intrinsic-size:auto_41px]"
        />
      </AdminPanel>

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
            <h3 className="text-sm font-medium text-[var(--label-1)]">完整消息</h3>
            <p className="data-text mt-3 select-text break-words whitespace-pre-wrap text-sm leading-relaxed text-[var(--label-1)]">
              {detailEntry.message}
            </p>
          </section>
        ) : null}
      </AdminDrawer>
    </div>
  );
}
