import { useEffect, useMemo, useState, type ReactNode } from "react";
import { RefreshCw, Server } from "lucide-react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import {
  adminGroupedCardClass,
  adminGroupedCardRowClass,
} from "@/components/admin-section-panel";
import { Button } from "@/components/ui/button";
import {
  adminSegmentedItemActiveClass,
  adminSegmentedItemClass,
  adminSegmentedItemInactiveClass,
  adminSegmentedTrackClass,
} from "@/lib/admin-ui";
import {
  fetchProbesOverview,
  fetchSystemStatus,
  type AdminSocketStatus,
} from "@/lib/admin-api";
import type {
  NodeView,
  ProbeNodeOverview,
  ProbeOverviewRange,
  ProbesOverviewResponse,
  SettingsView,
  SystemStatusView,
} from "@/lib/admin-types";
import {
  formatBinaryBytes,
  formatUptimeZh,
  formatVersionLabel,
  nodeDiskPercent,
  resolveNodeId,
  resolveNodeName,
  type AdminPage,
  compareNodeDisplayName,
} from "@/lib/admin-format";
import { cn } from "@/lib/utils";

type Page = AdminPage;

export interface DashboardProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  // 是否已拿到一次权威节点结果；false 时不显示零节点引导，避免已有节点时闪现。
  nodesLoaded: boolean;
  onNavigate: (page: Page, section?: string | null) => void;
  // 实时连接状态由 App 的 connectAdminSocket onStatus 驱动；页头「实时」指示
  // 与断线时的降级文案都按它渲染，否则断线时会继续显示健康态。
  liveStatus: AdminSocketStatus;
}

// F7 刷新策略（evolution_log §5 F7 第 5 条）：system/status 每 10s、probes/overview
// 每 60s；document.hidden 时暂停，切回前台立即补拉一次。
const SYSTEM_STATUS_POLL_MS = 10_000;
const PROBES_OVERVIEW_POLL_MS = 60_000;

// F7 首页行距：与 adminPageShellClass 同宽限，行距收紧到 24px（信息密度高于设置页）。
const dashboardShellClass =
  "mx-auto w-full max-w-[1200px] space-y-6 text-slate-900 dark:text-neutral-100";

// 内联文字链按钮（与设置页同一规格）：用于从表格尾部/空态跳到探测设置页。
const probeInlineLinkClass =
  "inline rounded-[var(--r-sm)] font-medium text-[var(--accent-text)] underline decoration-[color-mix(in_srgb,var(--accent-text)_45%,transparent)] underline-offset-2 transition-colors duration-150 hover:text-[var(--accent)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]";

// =====================================================================
// F7 前端派生（纯函数，evolution_log §5 F7 测试第 3 条）：
// 全部不触碰组件状态，输入 nodes / targets 快照即可复算。
// =====================================================================

export interface DashboardNodeKpis {
  total: number;
  online: number;
  onlineRatePct: number | null;
}

// 在线率：无节点时比率为 null（界面显示「--」）。A-10：「离线率」与在线率互为
// 补数、信息重复，已删除（含其计算字段）。
export function deriveDashboardNodeKpis(nodes: readonly NodeView[]): DashboardNodeKpis {
  const total = nodes.length;
  const online = nodes.filter((node) => node.status === "online").length;
  return {
    total,
    online,
    onlineRatePct: total > 0 ? (online / total) * 100 : null,
  };
}

export interface DashboardProbeKpis {
  samples: number;
  okSamples: number;
  availabilityPct: number | null;
  avgLatencyMs: number | null;
}

// 探测可用率：所有节点 × 探测目标中 status=="ok" 的占比；平均延迟取有效样本均值。
export function deriveDashboardProbeKpis(nodes: readonly NodeView[]): DashboardProbeKpis {
  let samples = 0;
  let okSamples = 0;
  let latencySum = 0;
  let latencyCount = 0;
  for (const node of nodes) {
    const tests = node.stats?.network_tests;
    if (!Array.isArray(tests)) {
      continue;
    }
    for (const test of tests) {
      if (!test) {
        continue;
      }
      samples += 1;
      if (test.status === "ok") {
        okSamples += 1;
      }
      const latency = test.latency_ms;
      if (typeof latency === "number" && Number.isFinite(latency) && latency >= 0) {
        latencySum += latency;
        latencyCount += 1;
      }
    }
  }
  return {
    samples,
    okSamples,
    availabilityPct: samples > 0 ? (okSamples / samples) * 100 : null,
    avgLatencyMs: latencyCount > 0 ? latencySum / latencyCount : null,
  };
}

export type DashboardResourceMetric = "cpu" | "mem" | "disk";

export interface DashboardResourceHotspot {
  nodeId: string;
  nodeName: string;
  metric: DashboardResourceMetric;
  valuePct: number;
}

// 资源热点：CPU / 内存 / 磁盘（B-06 D-02：磁盘 = Σ已用 / Σ总量，服务器总硬盘
// 口径）使用率 ≥ threshold 的指标各占一行，按当前值降序；数据从节点快照派生
// （离线节点按最后一次上报值参与）。
export function deriveDashboardResourceHotspots(
  nodes: readonly NodeView[],
  threshold = 80,
): DashboardResourceHotspot[] {
  const hotspots: DashboardResourceHotspot[] = [];
  for (const node of nodes) {
    const stats = node.stats;
    if (!stats) {
      continue;
    }
    const nodeId = stats.node_id || stats.node_name || "";
    const nodeName = resolveNodeName(node) || nodeId;
    const cpuPct = Number(stats.cpu?.usage_percent);
    if (Number.isFinite(cpuPct) && cpuPct >= threshold) {
      hotspots.push({ nodeId, nodeName, metric: "cpu", valuePct: cpuPct });
    }
    const memPct = Number(stats.memory?.used_percent);
    if (Number.isFinite(memPct) && memPct >= threshold) {
      hotspots.push({ nodeId, nodeName, metric: "mem", valuePct: memPct });
    }
    // B-06：磁盘改用总硬盘口径（nodeDiskPercent），不再取最满分区。
    const diskPct = nodeDiskPercent(stats);
    if (diskPct != null && diskPct >= threshold) {
      hotspots.push({ nodeId, nodeName, metric: "disk", valuePct: diskPct });
    }
  }
  return hotspots.sort(
    (a, b) =>
      b.valuePct - a.valuePct ||
      a.nodeId.localeCompare(b.nodeId) ||
      a.metric.localeCompare(b.metric),
  );
}

export interface ProbeNodeRow {
  nodeId: string;
  nodeName: string;
  online: boolean;
  targets: number;
  samples: number;
  availabilityPct?: number;
  avgLatencyMs?: number | null;
  p95LatencyMs?: number | null;
  avgLossPct?: number | null;
}

// nodeHasProbeConfig 判定节点是否配置了探测：手动下发（test_selections）或范围
// 下发（scoped_test_ids）任一非空。口径与 ProbeSettings 的 countManualProbeNodes /
// 节点抽屉「探测下发策略」一致。
export function nodeHasProbeConfig(node: NodeView): boolean {
  return (node.test_selections?.length ?? 0) > 0 || (node.scoped_test_ids?.length ?? 0) > 0;
}

// 配置的探测目标数（P3）：手动下发与范围下发的目标去重计数，口径与节点抽屉的
// 「探测下发策略」一致（同一目录项只算一个，手动选择优先、范围下发项不重复）。
// 服务端 overview 的 targets 只统计窗口内有采样点的目标，窗口内无数据的节点会
// 得到 0；这类行改用本函数，避免「已配置探测却显示 0 个目标」的自相矛盾。
export function countConfiguredProbeTargets(node: NodeView): number {
  const targets = new Set<string>();
  for (const selection of node.test_selections || []) {
    const id = (selection?.test_id || "").trim();
    if (id) {
      targets.add(id);
    }
  }
  for (const id of node.scoped_test_ids || []) {
    const trimmed = (id || "").trim();
    if (trimmed) {
      targets.add(trimmed);
    }
  }
  return targets.size;
}

// deriveProbeNodeRows 生成探测表行。入表条件按配置判定，不按窗口内是否采样：
// 离线时长 ≥ 所选范围、刚接入或历史查询失败的节点在窗口内没有数据，但它们恰恰
// 最该被看到。因此：
// - 配置了探测的节点一律入表（无数据时 targets 取配置的目标数、samples=0，并排到
//   后面）；
// - 没配置但窗口内有数据（服务端已聚合出探测目标/样本）的节点防御性保留；
// - 两者皆无的节点由调用方汇总成「另有 N 个节点未配置探测目标」。
// includeConfiguredWithoutData 为 false（探测数据尚未就绪）时不补无数据行，避免
// 把加载中的 0 当成事实显示。
export function deriveProbeNodeRows(
  overviewNodes: readonly ProbeNodeOverview[],
  nodes: readonly NodeView[],
  options: { includeConfiguredWithoutData?: boolean } = {},
): ProbeNodeRow[] {
  const overviewById = new Map(overviewNodes.map((item) => [item.node_id, item]));
  const rows: ProbeNodeRow[] = [];
  for (const node of nodes) {
    const nodeId = resolveNodeId(node);
    if (!nodeId) {
      continue;
    }
    const overview = overviewById.get(nodeId);
    const hasWindowData = Boolean(overview && (overview.targets > 0 || overview.samples > 0));
    const configured = nodeHasProbeConfig(node);
    if (!hasWindowData && !(configured && options.includeConfiguredWithoutData)) {
      continue;
    }
    rows.push({
      nodeId,
      nodeName: resolveNodeName(node),
      online: node.status === "online",
      // P3：窗口内无数据时用配置的目标数（去重后），不用服务端的采样口径 targets
      // （只会统计有采样点的目标），否则「已配置探测」会显示成 0 个目标。
      targets: hasWindowData ? (overview?.targets ?? 0) : countConfiguredProbeTargets(node),
      samples: overview?.samples ?? 0,
      availabilityPct: overview?.availability_pct,
      avgLatencyMs: overview?.avg_latency_ms,
      p95LatencyMs: overview?.p95_latency_ms,
      avgLossPct: overview?.avg_loss_pct,
    });
  }
  return rows.sort((a, b) => {
    const aEmpty = a.samples === 0;
    const bEmpty = b.samples === 0;
    if (aEmpty !== bEmpty) {
      return aEmpty ? 1 : -1;
    }
    const availabilityDiff = (a.availabilityPct ?? 0) - (b.availabilityPct ?? 0);
    if (availabilityDiff !== 0) {
      return availabilityDiff;
    }
    const lossDiff = (b.avgLossPct ?? 0) - (a.avgLossPct ?? 0);
    if (lossDiff !== 0) {
      return lossDiff;
    }
    const latencyDiff = (b.avgLatencyMs ?? 0) - (a.avgLatencyMs ?? 0);
    if (latencyDiff !== 0) {
      return latencyDiff;
    }
    return compareNodeDisplayName(a.nodeName, b.nodeName);
  });
}

// =====================================================================
// 显示格式化（纯函数）
// =====================================================================

// 百分比：保留一位小数，整数值省略小数位（100%、99.5%）；无数据显示「--」。
export function formatDashboardPercent(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) {
    return "--";
  }
  return `${Number(value.toFixed(1))}%`;
}

function formatDashboardClock(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function formatProbeMs(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value)
    ? `${Math.round(value)} ms`
    : "—";
}

function formatProbeLoss(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value)
    ? `${Number(value.toFixed(1))}%`
    : "—";
}

// 可用率配色（F7：<95% danger，<99% warn，≥99% 常规）。
function availabilityToneClass(value: number | undefined) {
  if (value == null || !Number.isFinite(value)) {
    return "text-[var(--label-1)]";
  }
  if (value < 95) {
    return "text-[var(--danger-text)]";
  }
  if (value < 99) {
    return "text-[var(--warn-text)]";
  }
  return "text-[var(--label-1)]";
}

// =====================================================================
// 资源热点进度条：同前台 .summary-bar / .summary-fill 样式（styles.css P-08/P-04）
// —— 6px 轨道 --meter-track、左圆右平切填充、按指标取 --meter-* 渐变、≥90% 转
// --meter-hot，末端丝带拖尾 + 流动高光（prefers-reduced-motion 时静止）。
// =====================================================================

const DASHBOARD_METER_STYLE = `
.cm-dashboard-meter {
  position: relative;
  height: 6px;
  border-radius: var(--r-full);
  background: var(--meter-track);
  overflow: hidden;
}
.cm-dashboard-meter-fill {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  border-radius: 999px 2px 2px 999px;
  transition: width var(--dur-5) var(--ease-spring);
}
.cm-dashboard-meter-fill::after {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  right: -12px;
  width: 12px;
  border-radius: 0 999px 999px 0;
  background: linear-gradient(90deg, color-mix(in srgb, currentColor 50%, transparent), transparent);
  pointer-events: none;
}
.cm-dashboard-meter-fill::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  background: linear-gradient(100deg, transparent 0%, transparent 38%, rgba(255, 255, 255, 0.42) 50%, transparent 62%, transparent 100%);
  background-size: 250% 100%;
  background-position: 100% 0;
  opacity: 0;
  pointer-events: none;
}
@media (prefers-reduced-motion: no-preference) {
  .cm-dashboard-meter-fill::before {
    opacity: 1;
    animation: cm-dashboard-ribbon-sheen 3.2s var(--ease-in-out, cubic-bezier(0.4, 0, 0.2, 1)) infinite;
  }
}
@keyframes cm-dashboard-ribbon-sheen {
  from { background-position: 100% 0; }
  to { background-position: 0% 0; }
}
.dark .cm-dashboard-meter-fill::before {
  background: linear-gradient(100deg, transparent 0%, transparent 38%, rgba(255, 255, 255, 0.22) 50%, transparent 62%, transparent 100%);
}
`;

// 与前台 P-04 第 3 条同源：渐变末端色作为丝带拖尾的 currentColor；≥90% hot（前台 data-level 语义）。
const RESOURCE_METRIC_META: Record<
  DashboardResourceMetric,
  { label: string; meter: string; endColor: string }
> = {
  cpu: { label: "CPU", meter: "var(--meter-cpu)", endColor: "#0a64ff" },
  mem: { label: "内存", meter: "var(--meter-mem)", endColor: "#1fa855" },
  disk: { label: "磁盘", meter: "var(--meter-disk)", endColor: "#ff8a1f" },
};

const PROBE_HOT_LEVEL_PCT = 90;

const PROBE_RANGE_OPTIONS: ReadonlyArray<{ value: ProbeOverviewRange; label: string }> = [
  { value: "1h", label: "1 小时" },
  { value: "24h", label: "24 小时" },
];

// =====================================================================
// KPI 卡（F7 第一行）：数字 22px/600 UI 字体 + tabular-nums（A-08 规则，
// 计数和百分比不用 data-text）；在线率 / 离线率下方带 3px 细条。
// =====================================================================

function DashboardKpiCard({
  label,
  value,
  sub,
  barTone,
  barPct,
  valueClassName,
  onClick,
  className,
}: {
  label: string;
  value: string;
  sub: ReactNode;
  barTone?: "ok" | "danger";
  barPct?: number | null;
  // A-10：数字颜色覆盖（如「告警中」数值 > 0 时用 --danger）。
  valueClassName?: string;
  // A-10：整卡可点击（如跳转告警策略页）。传入时按按钮语义渲染（键盘 Enter /
  // 空格触发），模式与渠道列表行一致。
  onClick?: () => void;
  className?: string;
}) {
  const clickable = Boolean(onClick);
  return (
    <div
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={onClick}
      onKeyDown={
        clickable
          ? (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onClick?.();
              }
            }
          : undefined
      }
      className={cn(
        // 卡片配方与 AdminMetricStrip 同源：--surface-raised + 上沿内高光 + --shadow-1
        "flex min-w-0 flex-col gap-2 rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] px-4 py-[14px] shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-1)]",
        clickable &&
          "cursor-pointer outline-none transition-colors duration-[var(--dur-2)] hover:border-[var(--hairline-strong)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]",
        className,
      )}
    >
      <span className="truncate text-[var(--label-3)] [font:var(--t-caption)] tracking-[var(--t-caption-ls)]">
        {label}
      </span>
      <span
        className={cn(
          "text-[22px] font-semibold leading-none tracking-[-0.015em] tabular-nums text-[var(--label-1)] [font-family:var(--font-ui)]",
          valueClassName,
        )}
      >
        {value}
      </span>
      {barTone ? (
        <span className="h-[3px] w-full overflow-hidden rounded-full bg-[var(--meter-track)]">
          <span
            className="block h-full rounded-full [transition:width_var(--dur-2)]"
            style={{
              width: `${Math.min(100, Math.max(0, barPct ?? 0))}%`,
              background: barTone === "ok" ? "var(--ok)" : "var(--danger)",
            }}
          />
        </span>
      ) : null}
      <span className="text-xs leading-relaxed text-[var(--label-3)] tabular-nums">{sub}</span>
    </div>
  );
}

// =====================================================================
// 网络连通性表（F7 第二行左，M-01 D-05）：节点 | 探测目标 | 可用率 | 平均延迟
// | P95 | 丢包。samples=0 的行后四列显示「—」。
// =====================================================================

const probeTableColumns: ReadonlyArray<AdminDataTableColumn<ProbeNodeRow>> = [
  {
    key: "node",
    label: "节点",
    render: (row) => (
      <span className="flex min-w-0 items-center gap-2 text-sm font-medium text-[var(--label-1)]">
        <span
          aria-hidden="true"
          className={cn(
            "size-1.5 shrink-0 rounded-full",
            row.online ? "bg-[var(--ok)]" : "bg-[var(--label-4)]",
          )}
        />
        <span className="truncate">{row.nodeName}</span>
      </span>
    ),
  },
  {
    key: "targets",
    label: "探测目标",
    align: "right",
    render: (row) => (
      <span className="text-[13px] tabular-nums text-[var(--label-2)]">{row.targets}</span>
    ),
  },
  {
    key: "availability",
    label: "可用率",
    align: "right",
    render: (row) => (
      <span
        className={cn(
          "text-[13px] font-semibold tabular-nums",
          availabilityToneClass(row.samples === 0 ? undefined : row.availabilityPct),
        )}
      >
        {row.samples === 0 ? "—" : formatDashboardPercent(row.availabilityPct)}
      </span>
    ),
  },
  {
    key: "avg_latency",
    label: "平均延迟",
    align: "right",
    render: (row) => (
      <span className="text-[13px] tabular-nums text-[var(--label-2)]">
        {formatProbeMs(row.avgLatencyMs)}
      </span>
    ),
  },
  {
    key: "p95_latency",
    label: "P95",
    align: "right",
    render: (row) => (
      <span className="text-[13px] tabular-nums text-[var(--label-2)]">
        {formatProbeMs(row.p95LatencyMs)}
      </span>
    ),
  },
  {
    key: "loss",
    label: "丢包",
    align: "right",
    render: (row) => (
      <span className="text-[13px] tabular-nums text-[var(--label-2)]">
        {formatProbeLoss(row.avgLossPct)}
      </span>
    ),
  },
];

export default function Dashboard({ liveStatus, nodes, nodesLoaded, onNavigate, settings }: DashboardProps) {
  const [clockText, setClockText] = useState(() => formatDashboardClock(new Date()));
  const [systemStatus, setSystemStatus] = useState<SystemStatusView | null>(null);
  // system/status 失败标记：保留最后一次成功数据的同时标记「可能已过期」；
  // reloadKey 用于「主控状态」面板的重试按钮触发重新拉取。
  const [systemStatusError, setSystemStatusError] = useState(false);
  const [systemStatusReloadKey, setSystemStatusReloadKey] = useState(0);
  const [probeRange, setProbeRange] = useState<ProbeOverviewRange>("1h");
  const [probesOverview, setProbesOverview] = useState<ProbesOverviewResponse | null>(null);
  // probes/overview 失败标记 + 重试 key：失败时清空数据，避免旧范围数据留在新选择下。
  const [probesError, setProbesError] = useState(false);
  const [probesReloadKey, setProbesReloadKey] = useState(0);

  // 页头「实时 · HH:mm:ss」时钟，每秒一跳。
  useEffect(() => {
    const timer = window.setInterval(() => {
      setClockText(formatDashboardClock(new Date()));
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  // system/status：每 10s；document.hidden 时暂停，切回前台补拉。
  useEffect(() => {
    let cancelled = false;
    // 请求序号：轮询 / visibilitychange / 重试可能重叠，只允许最新请求提交结果，
    // 避免旧的失败晚到后把刚恢复的界面重新清空或标错。
    let latestRequest = 0;
    const load = () => {
      if (document.hidden) {
        return;
      }
      const requestID = ++latestRequest;
      fetchSystemStatus()
        .then((status) => {
          if (!cancelled && requestID === latestRequest) {
            setSystemStatus(status);
            setSystemStatusError(false);
          }
        })
        .catch(() => {
          // 轮询错误保留上一份数据，但标记为可能已过期（401 已由 apiFetch 统一登出）。
          if (!cancelled && requestID === latestRequest) {
            setSystemStatusError(true);
          }
        });
    };
    load();
    const timer = window.setInterval(load, SYSTEM_STATUS_POLL_MS);
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        load();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [systemStatusReloadKey]);

  // probes/overview：每 60s，切换分段或点「重试」立即重拉；document.hidden 时同样暂停。
  // effect 开始时先清空上一轮数据：切范围 / 重试都不把旧范围数据显示在新选择下。
  useEffect(() => {
    let cancelled = false;
    let latestRequest = 0;
    setProbesOverview(null);
    setProbesError(false);
    const load = () => {
      if (document.hidden) {
        return;
      }
      const requestID = ++latestRequest;
      fetchProbesOverview(probeRange)
        .then((overview) => {
          if (!cancelled && requestID === latestRequest) {
            setProbesOverview(overview);
            setProbesError(false);
          }
        })
        .catch(() => {
          // 失败时不保留旧数据，改为显式错误态 + 重试入口。
          if (!cancelled && requestID === latestRequest) {
            setProbesOverview(null);
            setProbesError(true);
          }
        });
    };
    load();
    const timer = window.setInterval(load, PROBES_OVERVIEW_POLL_MS);
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        load();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [probeRange, probesReloadKey]);

  const nodeKpis = useMemo(() => deriveDashboardNodeKpis(nodes), [nodes]);
  const probeKpis = useMemo(() => deriveDashboardProbeKpis(nodes), [nodes]);
  // 零节点是“尚未接入”而不是“健康”：确认节点列表为空后显示接入引导；
  // 节点数据尚未就绪时保持原仪表盘，避免已有节点时闪现引导卡。
  const isEmptyNodes = nodeKpis.total === 0;
  const showOnboarding = nodesLoaded && isEmptyNodes;
  // 推断地址同样算「可接入」：未配置时服务端会按当前访问地址给出合法 URL。
  const endpointReady = Boolean(
    settings?.agent_endpoint?.trim() || settings?.agent_endpoint_suggestion?.trim(),
  );
  const hotspots = useMemo(() => deriveDashboardResourceHotspots(nodes), [nodes]);
  const probesReady = probesOverview !== null && !probesError;
  const activeProbeRows = useMemo(
    () =>
      deriveProbeNodeRows(probesOverview?.nodes || [], nodes, {
        includeConfiguredWithoutData: probesReady,
      }),
    [probesOverview, nodes, probesReady],
  );
  // 入表按节点配置判定（见 deriveProbeNodeRows）：配置了探测但没有窗口数据的节点
  // 仍保留一行 0 / —；既无配置也无数据的节点不进表，汇总成表下方那一行入口。
  const probeUnconfiguredCount = useMemo(() => {
    if (!probesReady) {
      return 0;
    }
    const activeIds = new Set(activeProbeRows.map((row) => row.nodeId));
    // 无 ID 的节点不进探测表（deriveProbeNodeRows 同样跳过），也不计入「未配置
    // 探测目标」：它们不是配置缺失，而是无从归属。
    return nodes.filter((node) => {
      const nodeId = resolveNodeId(node);
      return nodeId !== "" && !activeIds.has(nodeId);
    }).length;
  }, [activeProbeRows, nodes, probesReady]);

  const loadKpiSub = systemStatus
    ? `内存 ${formatBinaryBytes(systemStatus.mem?.alloc)} · 运行 ${formatUptimeZh(
        systemStatus.uptime_sec,
      )}`
    : "--";

  // 主控状态行式列表（F7 第二行右）：版本 / 运行时长 / Goroutines / 内存 /
  // WS 连接（后台 / 前台）/ 数据目录占用。版本号为机器字符串用 data-text，
  // 计数与时长按 A-08 用 UI 字体 tabular-nums。
  const statusRows: ReadonlyArray<{ label: string; value: string; mono?: boolean }> = [
    { label: "版本", value: formatVersionLabel(systemStatus?.version), mono: true },
    { label: "运行时长", value: formatUptimeZh(systemStatus?.uptime_sec) },
    {
      label: "Goroutines",
      value: systemStatus ? String(systemStatus.goroutines ?? 0) : "--",
    },
    {
      label: "内存",
      value: formatBinaryBytes(systemStatus?.mem?.alloc),
    },
    {
      label: "WS 连接（后台 / 前台）",
      value: systemStatus
        ? `${systemStatus.ws_clients?.admin ?? 0} / ${systemStatus.ws_clients?.public ?? 0}`
        : "--",
    },
    {
      label: "数据目录占用",
      value: formatBinaryBytes(
        (systemStatus?.data_dir?.state_bytes || 0) + (systemStatus?.data_dir?.tsdb_bytes || 0),
      ),
    },
  ];

  // 页头实时指示严格由 WS 连接状态驱动：断线 / 建连中不再显示健康态。
  const liveIndicator =
    liveStatus === "open"
      ? { dotClass: "bg-[var(--ok)] animate-pulse", label: "实时" }
      : liveStatus === "connecting"
        ? { dotClass: "bg-[var(--label-4)]", label: "连接中" }
        : { dotClass: "bg-[var(--warn)]", label: "连接中断" };

  // 「告警中」KPI：无数据时不能显示 0 / 「一切正常」；接口失败时降级为「数据
  // 可能已过期」。数据来自 system/status 的 REST 轮询（与 WS 无关），WS 断开的
  // 降级只作用于依赖 WS 快照的数据（顶部断线横幅已覆盖），这里不能跟着误报。
  const statusStale = systemStatusError;
  const staleLabel = <span className="text-[var(--warn-text)]">数据可能已过期</span>;
  const firingCount = systemStatus?.alerts?.firing ?? 0;
  const alertingValue = systemStatus ? String(firingCount) : "--";
  const alertingSub: ReactNode = systemStatus
    ? statusStale
      ? staleLabel
      : firingCount > 0
        ? `涉及 ${systemStatus.alerts?.nodes ?? 0} 台节点`
        : "一切正常"
    : statusStale
      ? <span className="text-[var(--warn-text)]">状态不可用</span>
      : "加载中…";

  return (
    <div className={dashboardShellClass}>
      <style>{DASHBOARD_METER_STYLE}</style>

      {/* F7 页头：h1「首页」+ 右侧「实时 · 时间」（6px 呼吸绿点）；断线 / 建连中
          切换为琥珀 / 中性静态点，时钟保留。 */}
      <AdminPageHeader
        as="section"
        title="首页"
        actions={
          <span className="flex items-center gap-2 text-[13px] text-[var(--label-3)]">
            <span
              aria-hidden="true"
              className={cn("size-1.5 shrink-0 rounded-full", liveIndicator.dotClass)}
            />
            <span>{liveIndicator.label}</span>
            <span aria-hidden="true">·</span>
            <span className="data-text tabular-nums">{clockText}</span>
          </span>
        }
      />

      {/* 零节点首次使用：说明当前处于“尚未接入”状态，并给出一条可执行的下一步。 */}
      {showOnboarding ? (
        <section
          aria-label="接入引导"
          className="flex flex-wrap items-center gap-4 rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] px-4 py-4 shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-1)] sm:px-5"
        >
          <span
            aria-hidden="true"
            className="flex size-10 shrink-0 items-center justify-center rounded-full bg-[var(--accent-tint)] text-[var(--accent-text)]"
          >
            <Server className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-[var(--label-1)]">还没有节点接入</p>
            <p className="mt-1 text-[13px] leading-relaxed text-[var(--label-2)]">
              {endpointReady
                ? "在「节点管理」复制接入命令，到目标服务器运行即可完成接入。"
                : "先在「基础设置 → 接入配置」填写 Agent 对接地址，再复制接入命令。"}
            </p>
          </div>
          <Button
            className="h-11 w-full shrink-0 bg-[#0057e6] hover:bg-[#0048c2] sm:h-9 sm:w-auto dark:bg-[#0057e6] dark:hover:bg-[#0048c2]"
            onClick={() =>
              onNavigate(endpointReady ? "servers" : "settings", endpointReady ? null : "agent")
            }
          >
            {endpointReady ? "去接入节点" : "填写对接地址"}
          </Button>
        </section>
      ) : null}

      {/* 零节点时隐藏 KPI / 连通性 / 资源热点：它们此时全是空占位，会把真正的
          接入引导挤到首屏之外；只保留引导卡与主控状态。 */}
      {/* 第一行：4 张 KPI 卡（12 列网格、每张 3 列；手机单列）。 */}
      {!showOnboarding ? (
      <section
        aria-label="总览"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-12"
      >
        <DashboardKpiCard
          className="lg:col-span-3"
          label="在线率"
          value={formatDashboardPercent(nodeKpis.onlineRatePct)}
          sub={`${nodeKpis.online} / ${nodeKpis.total} 在线`}
          barTone="ok"
          barPct={nodeKpis.onlineRatePct}
        />
        {/* A-10：第二张 KPI 改为「告警中」（原「离线率」与在线率互为补数，已删除）。
            数值来自 system/status 的 alerts 聚合；> 0 时数字用 --danger，整卡
            可点击跳转告警策略页。 */}
        <DashboardKpiCard
          className="lg:col-span-3"
          label="告警中"
          value={alertingValue}
          sub={alertingSub}
          valueClassName={firingCount > 0 ? "text-[var(--danger-text)]" : undefined}
          onClick={() => onNavigate("alerts", "policy")}
        />
        <DashboardKpiCard
          className="lg:col-span-3"
          label="探测可用率"
          value={formatDashboardPercent(probeKpis.availabilityPct)}
          sub={
            probeKpis.avgLatencyMs != null
              ? `平均延迟 ${Math.round(probeKpis.avgLatencyMs)} ms`
              : "暂无探测数据"
          }
        />
        <DashboardKpiCard
          className="lg:col-span-3"
          label="主控负载"
          value={formatDashboardPercent(systemStatus?.process?.cpu_percent)}
          sub={loadKpiSub}
        />
      </section>
      ) : null}

      {/* 第二行：左 8 列「网络连通性」+ 右 4 列「主控状态」。
          A-05 / M-02：lg 起「网络连通性」lg:absolute 于 col-span-8 外层内
          （不参与行高计算），行高只由「主控状态」决定，两卡等高、表内滚动、
          表头固定；<lg 自然撑开，滚动容器限高 420px。 */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12 lg:items-stretch">
        {!showOnboarding ? (
        <div className="relative min-w-0 lg:col-span-8">
        <AdminPanel
          className="flex min-w-0 flex-col lg:absolute lg:inset-0"
          bodyClassName="min-h-0 flex-1 flex flex-col"
          headerClassName="min-h-[52px] flex-wrap gap-y-2"
          title="网络连通性"
          actions={
            <div
              role="group"
              aria-label="时间范围"
              className={cn(adminSegmentedTrackClass, "sm:w-auto")}
            >
              {PROBE_RANGE_OPTIONS.map((item) => (
                <Button
                  key={item.value}
                  type="button"
                  variant={null}
                  className={cn(
                    adminSegmentedItemClass,
                    "sm:min-w-[64px] sm:flex-none",
                    probeRange === item.value
                      ? adminSegmentedItemActiveClass
                      : adminSegmentedItemInactiveClass,
                  )}
                  onClick={() => setProbeRange(item.value)}
                >
                  {item.label}
                </Button>
              ))}
            </div>
          }
        >
          {/* 加载失败时在表格上方给出可见原因 + 重试入口（不再默默显示空表）。
              错误行 shrink-0、表格改 min-h-0 flex-1，避免行高把卡片顶出溢出。 */}
          {probesError ? (
            <div className="flex shrink-0 flex-wrap items-center gap-3 px-4 pb-2 text-[13px] text-[var(--label-2)]">
              <span role="status">探测数据加载失败，请重试</span>
              <Button
                aria-label="重试加载探测数据"
                className="h-7 px-2.5 text-xs dark:border-[var(--hairline-strong)] dark:bg-[rgba(255,255,255,0.12)]"
                size="sm"
                title="重试加载探测数据"
                variant="outline"
                onClick={() => setProbesReloadKey((current) => current + 1)}
              >
                重试
              </Button>
            </div>
          ) : null}
          <AdminDataTable
            ariaLabel="网络连通性"
            className="min-h-0 flex-1 flex flex-col"
            columns={probeTableColumns}
            rows={activeProbeRows}
            rowKey={(row) => row.nodeId}
            emptyLabel={
              probesError ? (
                "—"
              ) : probesOverview === null ? (
                "加载中…"
              ) : (
                // 数据已就绪但仍无行：没有任何节点配置探测（窗口内也没有数据），
                // 给出可直接行动的入口，而不是一列「—」。
                <span className="flex flex-col items-center gap-2">
                  <span>还没有节点在运行探测</span>
                  <button
                    type="button"
                    className={probeInlineLinkClass}
                    onClick={() => onNavigate("probes")}
                  >
                    去探测设置
                  </button>
                </span>
              )
            }
            showRowChevron={false}
            scrollClassName="min-h-0 flex-1 overflow-y-auto overscroll-contain max-lg:max-h-[420px]"
            stickyHeader
            // 既无配置也无数据的节点不占用表格行：在卡片底部汇总成一行入口。
            // 全部节点都未配置时行列表本身为空（上方空态已给出入口），这里不重复。
            footer={
              probesReady && probeUnconfiguredCount > 0 && activeProbeRows.length > 0 ? (
                <button
                  type="button"
                  className={probeInlineLinkClass}
                  onClick={() => onNavigate("probes")}
                >
                  {`另有 ${probeUnconfiguredCount} 个节点未配置探测目标`}
                </button>
              ) : null
            }
          />
        </AdminPanel>
        </div>
        ) : null}

        <AdminPanel
          className={cn("min-w-0", showOnboarding ? "lg:col-span-12" : "lg:col-span-4")}
          bodyClassName="flex-1 flex flex-col"
          headerClassName="min-h-[52px] flex-nowrap"
          title="主控状态"
          actions={
            systemStatusError ? (
              <Button
                aria-label="重试加载主控状态"
                className="h-7 gap-1 px-2 text-xs dark:border-[var(--hairline-strong)] dark:bg-[rgba(255,255,255,0.12)]"
                size="sm"
                title="重试加载主控状态"
                variant="outline"
                onClick={() => setSystemStatusReloadKey((current) => current + 1)}
              >
                <RefreshCw aria-hidden="true" className="h-3.5 w-3.5" />
                重试
              </Button>
            ) : null
          }
        >
          <div className={cn(adminGroupedCardClass, "min-h-0 flex-1")}>
            {systemStatusError ? (
              <div
                role="status"
                className="flex items-center gap-2 border-b border-[var(--hairline)] px-4 py-2.5 text-[13px] text-[var(--warn-text)]"
              >
                <span
                  aria-hidden="true"
                  className="size-1.5 shrink-0 rounded-full bg-[var(--warn)]"
                />
                数据可能已过期
              </div>
            ) : null}
            {statusRows.map((row) => (
              <div
                key={row.label}
                className={cn(
                  adminGroupedCardRowClass,
                  "flex items-center justify-between gap-x-6 py-3",
                )}
              >
                <span className="shrink-0 text-[13px] font-medium leading-5 text-[var(--label-1)]">
                  {row.label}
                </span>
                <span
                  className={cn(
                    "min-w-0 truncate text-right text-[13px] leading-5 tabular-nums text-[var(--label-1)]",
                    row.mono && "data-text",
                  )}
                >
                  {row.value}
                </span>
              </div>
            ))}
          </div>
        </AdminPanel>
      </div>

      {/* 第三行：「资源热点」（12 列）：CPU / 内存 / 磁盘 ≥80% 的节点，进度条同前台样式。 */}
      {!showOnboarding ? (
      <AdminPanel title="资源热点" headerClassName="min-h-[52px] flex-nowrap">
        <div className={adminGroupedCardClass}>
          {hotspots.length === 0 ? (
            <div className="px-5 py-8 text-center">
              <p className="text-sm text-[var(--label-3)]">资源使用正常</p>
              <p className="text-xs text-[var(--label-3)]">CPU、内存、磁盘使用率 ≥ 80% 的节点会显示在这里</p>
            </div>
          ) : (
            hotspots.map((hotspot) => {
              const meta = RESOURCE_METRIC_META[hotspot.metric];
              const hot = hotspot.valuePct >= PROBE_HOT_LEVEL_PCT;
              return (
                <div key={`${hotspot.nodeId}:${hotspot.metric}`} className={cn(adminGroupedCardRowClass, "py-3.5")}>
                  <div className="flex items-baseline justify-between gap-x-4">
                    <div className="flex min-w-0 items-baseline gap-2">
                      <span className="truncate text-sm font-medium text-[var(--label-1)]">
                        {hotspot.nodeName}
                      </span>
                      <span className="shrink-0 text-xs text-[var(--label-3)]">{meta.label}</span>
                    </div>
                    <span
                      className={cn(
                        "shrink-0 text-[13px] font-semibold tabular-nums",
                        hot ? "text-[var(--danger-text)]" : "text-[var(--warn-text)]",
                      )}
                    >
                      {formatDashboardPercent(hotspot.valuePct)}
                    </span>
                  </div>
                  <div className="cm-dashboard-meter mt-2">
                    <div
                      className="cm-dashboard-meter-fill"
                      style={{
                        width: `${Math.min(100, Math.max(0, hotspot.valuePct))}%`,
                        background: hot ? "var(--meter-hot)" : meta.meter,
                        color: hot ? "#e5383b" : meta.endColor,
                      }}
                    />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </AdminPanel>
      ) : null}
    </div>
  );
}
