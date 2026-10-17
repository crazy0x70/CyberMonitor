import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

// =====================================================================
// A-16：空态组件 AdminEmptyState，用于分组管理、探测设置、运维助手（无数据时）、
// 日志筛选无结果时（E-11）。
//
// 结构从上到下：
// - 56px 图标方块：--r-lg、--surface-sunken 底、图标 24px --label-3（[&_svg]:size-6 强制）；
// - 间距 16px，标题（15px / 600）；
// - 间距 4px，说明（13px --label-2，最大宽 320px）；
// - 间距 16px，主按钮（可选）——按钮由使用方传入（action 插槽），
//   其 onClick 复用页头「新建」按钮的处理函数，不新增逻辑（0.1.2 裁定）。
// =====================================================================
export function AdminEmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center text-center", className)}>
      <span
        aria-hidden="true"
        className="flex size-14 shrink-0 items-center justify-center rounded-[var(--r-lg)] bg-[var(--surface-sunken)] text-[var(--label-3)] [&_svg]:size-6"
      >
        {icon}
      </span>
      <p className="mt-4 text-[15px] font-semibold leading-snug text-[var(--label-1)]">{title}</p>
      {description ? (
        <p className="mt-1 max-w-[320px] text-[13px] leading-relaxed text-[var(--label-2)]">
          {description}
        </p>
      ) : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
