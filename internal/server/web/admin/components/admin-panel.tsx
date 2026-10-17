import type { ReactNode } from "react";

import { adminSectionHeaderClass } from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

type AdminPanelProps = {
  title: ReactNode;

  icon?: ReactNode;

  iconClassName?: string;

  titleClassName?: ReactNode;

  actions?: ReactNode;

  headerClassName?: string;

  className?: string;

  // A-05：传入时 <section> 变为 flex 纵向容器，children 包在带该类的 <div> 中
  //（配合 min-h-0 供卡片体高度受控 / 撑满）。不传时保持原有渲染结构。
  bodyClassName?: string;

  id?: string;
  children: ReactNode;
};

export function AdminPanel({
  title,
  icon,
  iconClassName,
  titleClassName,
  actions,
  headerClassName,
  className,
  bodyClassName,
  id,
  children,
}: AdminPanelProps) {
  return (
    <section
      id={id}
      className={cn(
        "text-slate-900 dark:text-neutral-100",
        bodyClassName && "flex flex-col",
        className,
      )}
    >
      { }
      <div className={cn(adminSectionHeaderClass, headerClassName)}>
        <h2
          className={cn(
            "flex items-center gap-2 text-[15px] leading-snug font-semibold tracking-tight",
            titleClassName
          )}
        >
          {icon ? (
            iconClassName ? (
              <span className={cn("flex items-center justify-center", iconClassName)}>{icon}</span>
            ) : (
              icon
            )
          ) : null}
          {title}
        </h2>
        {actions}
      </div>
      {bodyClassName ? (
        <div className={cn("min-h-0", bodyClassName)}>{children}</div>
      ) : (
        children
      )}
    </section>
  );
}
