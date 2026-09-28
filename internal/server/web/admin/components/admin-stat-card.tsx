import type { ReactNode } from "react";

import { adminStatCardClass, adminStatEyebrowClass } from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

type AdminStatCardProps = {

  title: ReactNode;
  value: ReactNode;

  className?: string;
};

export function AdminStatCard({ title, value, className }: AdminStatCardProps) {
  return (
    <div className={cn(adminStatCardClass, className)}>
      <span className={adminStatEyebrowClass}>{title}</span>
      { }
      <span className="data-text mt-1.5 text-4xl font-medium leading-none tracking-tight text-slate-900 dark:text-neutral-50">
        {value}
      </span>
    </div>
  );
}
