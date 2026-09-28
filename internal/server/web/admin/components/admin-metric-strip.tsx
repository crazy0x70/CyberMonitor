import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export type AdminMetricItem = {
  label: ReactNode;
  value: ReactNode;
};

type AdminMetricStripProps = {
  items: ReadonlyArray<AdminMetricItem>;

  ariaLabel?: string;
  className?: string;
};

export function AdminMetricStrip({ items, ariaLabel = "统计摘要", className }: AdminMetricStripProps) {
  return (
    <section
      aria-label={ariaLabel}
      className={cn("flex flex-wrap items-baseline gap-x-8 gap-y-4", className)}
    >
      {items.map((item, index) => (
        <div key={index} className="flex items-baseline gap-2.5">
          <span className="data-text text-[30px] font-medium leading-none text-slate-900 dark:text-neutral-50">
            {item.value}
          </span>
          <span className="text-xs font-medium text-[var(--label-3)]">{item.label}</span>
        </div>
      ))}
    </section>
  );
}
