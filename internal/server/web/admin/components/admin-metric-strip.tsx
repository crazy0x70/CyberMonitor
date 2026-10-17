import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

// A-08：统计条每项一张小卡（与前台 P-04 同基调）。色点颜色由 tone 决定，
// 现有调用不传 tone 时显示中性点；label/value 数据来源与结构不变（M-04 数字滚动不做）。
export type AdminMetricItem = {
  label: ReactNode;
  value: ReactNode;

  tone?: "ok" | "danger" | "warn" | "accent" | "neutral";
};

// 8px 状态色点（P-04 第 3 条）：ok 绿 / danger 红 / warn 琥珀 / accent 主蓝 / neutral 中性
const metricDotToneClass: Record<NonNullable<AdminMetricItem["tone"]>, string> = {
  ok: "bg-[var(--ok)]",
  danger: "bg-[var(--danger)]",
  warn: "bg-[var(--warn)]",
  accent: "bg-[var(--accent)]",
  neutral: "bg-[var(--label-4)]",
};

type AdminMetricStripProps = {
  items: ReadonlyArray<AdminMetricItem>;

  ariaLabel?: string;
  className?: string;
};

export function AdminMetricStrip({ items, ariaLabel = "统计摘要", className }: AdminMetricStripProps) {
  return (
    // 4 项一行；手机 2×2（A-08）
    <section
      aria-label={ariaLabel}
      className={cn("grid grid-cols-2 gap-3 sm:grid-cols-4", className)}
    >
      {items.map((item, index) => (
        <div
          key={index}
          className={cn(
            // 卡片：--surface-raised 实底（内容层，不开 backdrop）+ --r-lg + 内边距 14px 16px + 最小宽 160px；
            // 1px --hairline 边 + 上沿内高光 + --shadow-1（P-04 第 2 条卡片配方）
            "flex min-w-[160px] flex-col gap-2 rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] px-4 py-[14px] shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-1)]",
          )}
        >
          <span className="flex min-w-0 items-center gap-1.5 text-[var(--label-3)] [font:var(--t-caption)] tracking-[var(--t-caption-ls)]">
            <span
              aria-hidden="true"
              className={cn("size-2 shrink-0 rounded-full", metricDotToneClass[item.tone ?? "neutral"])}
            />
            <span className="truncate">{item.label}</span>
          </span>
          {/* A-08：统计数字用 UI 字体 + tabular-nums（不带斜杠 0），22px/600 与前台 P-05 对齐；
              全站规则——只有 IP、版本号、路径、Token、时间戳用 data-text */}
          <span className="text-[22px] font-semibold leading-none tracking-[-0.015em] tabular-nums text-[var(--label-1)] [font-family:var(--font-ui)]">
            {item.value}
          </span>
        </div>
      ))}
    </section>
  );
}
