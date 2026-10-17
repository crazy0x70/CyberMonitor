import type { ReactNode } from "react";

import { adminGroupedCardClass, adminGroupedCardRowClass } from "@/components/admin-section-panel";
import { cn } from "@/lib/utils";

// =====================================================================
// A-15 / M-06：后台加载骨架，替换 adminLoadingCardClass 那张白卡片
// 「正在加载…」（App.tsx 的 SectionLoader 接线，0.1.2 裁定）。
//
// - 骨架块：--surface-sunken，圆角与真实元素一致（统计卡 --r-lg、输入控件 --r-md、
//   其余文本/行块 --r-sm）。
// - 扫光（M-06，文档给定值直接写上，不走令牌）：
//   linear-gradient(90deg, transparent, rgba(255,255,255,.5), transparent)、
//   background-size 200%、1.2s 线性循环；prefers-reduced-motion 时退化为静态骨架。
// - 三套布局：AdminSkeletonList（列表页）/ AdminSkeletonSettings（设置页）/
//   AdminSkeletonDashboard（首页）。
// - 读屏：容器 aria-busy="true" + 视觉隐藏的加载文案（label 由调用方传入）。
// =====================================================================

const ADMIN_SKELETON_STYLE = `
@keyframes admin-skeleton-sweep {
  from {
    background-position: 200% 0;
  }
  to {
    background-position: -200% 0;
  }
}
.cm-admin-skeleton-block {
  background-color: var(--surface-sunken);
  background-image: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.5), transparent);
  background-size: 200% 100%;
  background-repeat: no-repeat;
  animation: admin-skeleton-sweep 1.2s linear infinite;
}
@media (prefers-reduced-motion: reduce) {
  .cm-admin-skeleton-block {
    animation: none;
  }
}
`;

function SkeletonBlock({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cn("cm-admin-skeleton-block block", className)} />;
}

type AdminSkeletonLayoutProps = {
  // 视觉隐藏的加载文案（读屏可访问），来自 App.tsx SectionLoader 的 label
  label?: ReactNode;
  className?: string;
};

function AdminSkeletonShell({
  label,
  className,
  children,
}: AdminSkeletonLayoutProps & { children: ReactNode }) {
  return (
    <div aria-busy="true" className={className}>
      <style>{ADMIN_SKELETON_STYLE}</style>
      <span className="sr-only">{label ?? "正在加载…"}</span>
      {children}
    </div>
  );
}

// 列表页骨架（节点 / 分组 / 探测 / 日志等）：页头 28px 一条 + 统计区 4 个 48px + 表格 6 行 44px
export function AdminSkeletonList({ label, className }: AdminSkeletonLayoutProps) {
  return (
    <AdminSkeletonShell label={label} className={className}>
      <div className="space-y-10">
        {/* 页头：28px 一条 */}
        <SkeletonBlock className="h-7 w-52 rounded-[var(--r-sm)]" />
        {/* 统计区：4 个 48px，2×2 / 4 列与 AdminMetricStrip 同构 */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, index) => (
            <SkeletonBlock key={index} className="h-12 rounded-[var(--r-lg)]" />
          ))}
        </div>
        {/* 表格：6 行 44px */}
        <div className="space-y-2">
          {Array.from({ length: 6 }, (_, index) => (
            <SkeletonBlock key={index} className="h-11 rounded-[var(--r-sm)]" />
          ))}
        </div>
      </div>
    </AdminSkeletonShell>
  );
}

// 设置页骨架（基础设置 / 通知告警 / 运维助手）：页头一条 + 2 张分组卡片各 3 行，
// 卡片与行复用 A-07 的 adminGroupedCardClass / adminGroupedCardRowClass 保持同构
export function AdminSkeletonSettings({ label, className }: AdminSkeletonLayoutProps) {
  return (
    <AdminSkeletonShell label={label} className={className}>
      <div className="space-y-8">
        {/* 页头：28px 一条 */}
        <SkeletonBlock className="h-7 w-52 rounded-[var(--r-sm)]" />
        {/* 2 张分组卡片，各 3 行（左标签块 + 右控件块 min(360px,50%)） */}
        {Array.from({ length: 2 }, (_, card) => (
          <div key={card} className={adminGroupedCardClass}>
            {Array.from({ length: 3 }, (_, row) => (
              <div key={row} className={cn(adminGroupedCardRowClass, "flex items-center gap-6")}>
                <SkeletonBlock className="h-5 w-28 rounded-[var(--r-sm)]" />
                <SkeletonBlock className="ml-auto h-9 w-[min(360px,50%)] rounded-[var(--r-md)]" />
              </div>
            ))}
          </div>
        ))}
      </div>
    </AdminSkeletonShell>
  );
}

// 首页骨架（Dashboard）：页头一条 + 统计区 4 个 48px + 内容区面板卡 3 行
export function AdminSkeletonDashboard({ label, className }: AdminSkeletonLayoutProps) {
  return (
    <AdminSkeletonShell label={label} className={className}>
      <div className="space-y-10">
        {/* 页头（hero 标题位）：28px 一条 */}
        <SkeletonBlock className="h-7 w-52 rounded-[var(--r-sm)]" />
        {/* 统计区：4 个 48px，2×2 / 4 列与 AdminMetricStrip 同构 */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, index) => (
            <SkeletonBlock key={index} className="h-12 rounded-[var(--r-lg)]" />
          ))}
        </div>
        {/* 内容区：面板卡 3 行（核心配置 / 需要关注区的占位） */}
        <div className={adminGroupedCardClass}>
          {Array.from({ length: 3 }, (_, row) => (
            <div key={row} className={cn(adminGroupedCardRowClass, "flex items-center gap-6")}>
              <SkeletonBlock className="h-5 w-24 rounded-[var(--r-sm)]" />
              <SkeletonBlock className="ml-auto h-5 w-40 rounded-[var(--r-sm)]" />
            </div>
          ))}
        </div>
      </div>
    </AdminSkeletonShell>
  );
}
