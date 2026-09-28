import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export const adminKVGridClass =
  "admin-kv-grid grid grid-cols-1 items-baseline gap-y-2 sm:grid-cols-[200px_minmax(0,1fr)] sm:gap-x-6 sm:gap-y-0";

export const adminKVLabelClass =
  "admin-kv-label text-xs font-medium leading-5 text-[var(--label-2)] sm:text-right";

type AdminKVFieldProps = {
  label: ReactNode;

  htmlFor?: string;

  children: ReactNode;

  className?: string;
};

export function AdminKVField({ label, htmlFor, children, className }: AdminKVFieldProps) {
  const labelNode =
    typeof label === "string" ? (
      htmlFor ? (
        <label htmlFor={htmlFor} className={adminKVLabelClass}>
          {label}
        </label>
      ) : (
        <span className={adminKVLabelClass}>{label}</span>
      )
    ) : (
      label
    );
  return (
    <div className={cn(adminKVGridClass, className)}>
      {labelNode}
      <div className="min-w-0">{children}</div>
    </div>
  );
}
