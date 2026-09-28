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

  className?: ReactNode;

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
  id,
  children,
}: AdminPanelProps) {
  return (
    <section id={id} className={cn("text-slate-900 dark:text-neutral-100", className)}>
      { }
      <div className={cn(adminSectionHeaderClass, headerClassName)}>
        <h2
          className={cn(
            "flex items-center gap-2 text-base leading-snug font-medium tracking-tight",
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
      {children}
    </section>
  );
}
