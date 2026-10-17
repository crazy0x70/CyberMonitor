import type { ReactNode } from "react";

import {
  adminMutedTextClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageTitleClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

type AdminPageHeaderProps = {
  // 单分区视图的小号面包屑（页面名 ›，12px --label-3），渲染在分区标题 h1 之上（E-02）。
  breadcrumb?: ReactNode;
  // E-01：分区图标，按 A-07 第 1 条渲染成 macOS「系统设置」风格的图标方块（36px、
  // --r-sm 圆角、20px 白色图标、1px 内高光），置于 h1 左侧；
  // iconClassName 提供该分区专属的渐变/纯色底（色表见 A-07 第 1 条）。
  icon?: ReactNode;
  iconClassName?: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;

  actionsClassName?: string;

  as?: "div" | "section";
};

export function AdminPageHeader({
  breadcrumb,
  icon,
  iconClassName,
  title,
  description,
  actions,
  actionsClassName,
  as: Tag = "div",
}: AdminPageHeaderProps) {
  return (
    <Tag className={adminPageHeaderClass}>
      <div className="flex items-center gap-4">
        {icon ? (
          <span
            aria-hidden="true"
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--r-sm,10px)] text-white",
              "shadow-[inset_0_1px_0_rgba(255,255,255,0.35)]",
              iconClassName,
            )}
          >
            {icon}
          </span>
        ) : null}
        <div>
          {breadcrumb ? (
            <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-[var(--label-3)]">
              {breadcrumb}
            </div>
          ) : null}
          <h1 className={adminPageTitleClass}>{title}</h1>
          {description ? (
            <p className={cn("mt-2 text-sm", adminMutedTextClass)}>{description}</p>
          ) : null}
        </div>
      </div>
      {actions ? (
        <div className={actionsClassName ?? adminPageActionsClass}>{actions}</div>
      ) : null}
    </Tag>
  );
}
