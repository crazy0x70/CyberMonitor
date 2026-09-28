import type { ReactNode } from "react";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

type AdminDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;

  children: ReactNode;

  footer?: ReactNode;
  className?: string;
};

export function AdminDrawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: AdminDrawerProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className={cn(
          "gap-0 border-[var(--cm-panel-border)] bg-[var(--cm-panel-bg)] p-0",
          "transition-[translate,opacity,color,background-color,border-color] duration-200 ease-out",
          "data-[side=right]:w-[min(100vw-2rem,26rem)] data-[side=right]:sm:max-w-none",
          className,
        )}
      >
        <SheetHeader className="border-b border-[var(--separator)] px-6 py-4">
          <SheetTitle className="text-base font-medium leading-snug">{title}</SheetTitle>
          {description ? (
            <SheetDescription className="text-xs leading-relaxed">
              {description}
            </SheetDescription>
          ) : null}
        </SheetHeader>
        { }
        <div
          className={cn(
            "min-h-0 flex-1 divide-y divide-[var(--separator)] overflow-y-auto",
            "[&>section]:space-y-4 [&>section]:px-6 [&>section]:py-6 [&>section]:first:pt-6 [&>section]:last:pb-6",
            "[&_.admin-kv-grid]:sm:grid-cols-1 [&_.admin-kv-grid]:sm:gap-y-1.5 [&_.admin-kv-grid_.admin-kv-label]:sm:text-left",
          )}
        >
          {children}
        </div>
        {footer ? (
          <div className="shrink-0 border-t border-[var(--separator)] bg-[var(--cm-panel-bg)] px-6 py-4">
            {footer}
          </div>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
