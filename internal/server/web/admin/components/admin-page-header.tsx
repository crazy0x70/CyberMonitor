import type { ReactNode } from "react";

import {
  adminMutedTextClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageTitleClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";

type AdminPageHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;

  actionsClassName?: string;

  as?: "div" | "section";
};

export function AdminPageHeader({
  title,
  description,
  actions,
  actionsClassName,
  as: Tag = "div",
}: AdminPageHeaderProps) {
  return (
    <Tag className={adminPageHeaderClass}>
      <div>
        <h1 className={adminPageTitleClass}>{title}</h1>
        {description ? (
          <p className={cn("mt-2 text-sm", adminMutedTextClass)}>{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className={actionsClassName ?? adminPageActionsClass}>{actions}</div>
      ) : null}
    </Tag>
  );
}
