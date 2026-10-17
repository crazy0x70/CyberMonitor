import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

// =====================================================================
// A-07「分组卡片（Inset Grouped）」套件 —— 供设置类页面（基础设置 / 通知告警 /
// 运维助手）接线使用。AdminSectionPanel 仍是分区外壳（区块语义 aria-label +
// 组标题行 + 卡片右上角操作位），卡片容器与字段行以可组合的组件 / 样式类提供：
//
//   <AdminSectionPanel label="OAuth / OIDC 登录" title="GitHub OAuth" actions={…}>
//     <AdminGroupedCard>
//       <AdminGroupedFieldRow label="Client ID" htmlFor="github-client-id" hint="…">
//         <Input id="github-client-id" … />
//       </AdminGroupedFieldRow>
//       <AdminGroupedSwitchRow label="启用" htmlFor="github-oauth-enabled" hint="…">
//         <Switch id="github-oauth-enabled" … />
//       </AdminGroupedSwitchRow>
//     </AdminGroupedCard>
//   </AdminSectionPanel>
//
// 红线（evolution_log 第 10 节）：字段 id / name、校验规则与聚焦定位逻辑
// （focusAlertField 等）由使用方保持不变，本套件只提供排版容器。
// =====================================================================

// 分组卡片容器：背景 --surface-raised、圆角 --r-lg、--shadow-1、边框 --hairline、内边距 0。
// 不加 overflow-hidden：卡片内无粘性表头（无 A-09 的取舍），避免裁剪首/末行控件的焦点环。
export const adminGroupedCardClass =
  "rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] shadow-[var(--shadow-1)]";

// 卡片上方组标题：--t-caption（11px/500）、--label-3；左端缩进 16px 由标题行的 pl-4 提供。
export const adminGroupedCardTitleClass =
  "text-[var(--label-3)] [font:var(--t-caption)] tracking-[var(--t-caption-ls)]";

// 字段行基类：最小高 52px、内边距 12px 16px；行与行之间 1px --hairline 分隔线，
// 左端缩进 16px 与文字对齐（iOS / macOS 分隔线规则）。技法与 AdminDataTable 的
// tr::after 一致：每行（末行除外）在自身底边画线。
export const adminGroupedCardRowClass =
  "relative min-h-[52px] px-4 py-3 [&:not(:last-child)]:after:absolute [&:not(:last-child)]:after:bottom-0 [&:not(:last-child)]:after:left-4 [&:not(:last-child)]:after:right-0 [&:not(:last-child)]:after:h-px [&:not(:last-child)]:after:bg-[var(--hairline)] [&:not(:last-child)]:after:content-['']";

// 行内标签：13px / 500 / --label-1（A-07 第 2 条「行布局（桌面）」的左侧标签）
export const adminGroupedRowLabelClass =
  "text-[13px] font-medium leading-5 text-[var(--label-1)]";

// 行内说明：12px / --label-3，位于标签下方
export const adminGroupedRowHintClass =
  "mt-0.5 text-xs leading-relaxed text-[var(--label-3)]";

export function AdminGroupedCard({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn(adminGroupedCardClass, className)}>{children}</div>;
}

function renderGroupedLabel(label: ReactNode, htmlFor?: string) {
  if (typeof label !== "string") {
    return label;
  }
  return htmlFor ? (
    <label htmlFor={htmlFor} className={adminGroupedRowLabelClass}>
      {label}
    </label>
  ) : (
    <span className={adminGroupedRowLabelClass}>{label}</span>
  );
}

// 文本类字段行（输入框 / 选择框 / 文本域等）：
// - 桌面（≥sm）：左侧标签 + 说明，右侧控件列宽 min(360px, 50%)、右对齐；
// - 手机（<sm）：标签在上、控件在下，宽 100%（A-07 第 2 条「行布局（手机）」）。
export function AdminGroupedFieldRow({
  label,
  htmlFor,
  hint,
  children,
  className,
}: {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        adminGroupedCardRowClass,
        "flex flex-col gap-2 sm:grid sm:grid-cols-[minmax(0,1fr)_min(360px,50%)] sm:items-center sm:gap-x-6",
        className,
      )}
    >
      <div className="min-w-0">
        {renderGroupedLabel(label, htmlFor)}
        {hint ? <p className={adminGroupedRowHintClass}>{hint}</p> : null}
      </div>
      {/* A-09：控件列 flex-col + sm:items-end，窄控件（数字输入、开关、按钮）桌面端靠右；
          自带 w-full 的输入框仍占满整列不受影响。手机端 flex-col 保持标签上、控件下的纵排。 */}
      <div className="flex w-full min-w-0 flex-col sm:items-end">{children}</div>
    </div>
  );
}

// 开关类字段行：
// - 桌面（≥sm）：左侧标签 + 说明，开关始终在最右；
// - 手机（<sm）：标签在左、开关在右保持一行，说明文字换到下一行（E-05）。
export function AdminGroupedSwitchRow({
  label,
  htmlFor,
  hint,
  children,
  className,
}: {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        adminGroupedCardRowClass,
        "flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:gap-x-6",
        className,
      )}
    >
      <div className="min-w-0">
        {renderGroupedLabel(label, htmlFor)}
        {hint ? <p className={adminGroupedRowHintClass}>{hint}</p> : null}
      </div>
      <div className="flex shrink-0 items-center">{children}</div>
    </div>
  );
}

// E-01：三个设置页（BasicSettings / NotificationAlert / AIProvider）共用的单分区面板外壳，
// 由各页完全相同的本地 SectionPanel 实现合并而来（纯组件搬家，不改行为）。
// 分区名已作为页头 h1 展示，分区图标也随 E-01 移入页头图标方块（AdminPageHeader 的 icon），
// 这里仅保留区块语义（aria-label）与可选的组标题 / 右侧操作位，不渲染重复的同名标题；
// 不渲染 icon，且只有存在 title / actions 时才渲染头部行（E-01：无 actions 时无头部行，
// 有 actions 时右对齐）。A-07 第 3/4 条：组标题行的右侧即「卡片右上角操作位」。
export function AdminSectionPanel({
  label,
  title,
  actions,
  children,
  className,
}: {
  label: string;
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section aria-label={label} className={cn("text-slate-900 dark:text-neutral-100", className)}>
      {title || actions ? (
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 pb-3 pl-4">
          {title ? <h3 className={adminGroupedCardTitleClass}>{title}</h3> : null}
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
