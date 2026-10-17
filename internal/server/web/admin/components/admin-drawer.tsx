import type { ReactNode, Ref } from "react";

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
  bodyRef?: Ref<HTMLDivElement>;
};

// A-11 第 2 条：右侧浮动抽屉 —— 离窗口边缘 8px 的浮动玻璃面板。
// 玻璃同弹窗：--mat-sheet-bg + --blur-thick + 上沿内高光 + --shadow-4；圆角 --r-2xl；
// 宽 min(560px, 100vw - 16px)。shadow 带 !：与 Sheet 内置 shadow-[var(--cm-elev-2)] 不属
// 同一 tailwind-merge 组（inset 差异），须强制优先。滑入过渡用 --dur-3 + --ease-spring。
const drawerPanelClass = cn(
  "gap-0 overflow-hidden border border-[var(--hairline)] bg-[var(--mat-sheet-bg)] p-0",
  "shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-4)]! [-webkit-backdrop-filter:var(--blur-thick)] [backdrop-filter:var(--blur-thick)]",
  "transition-[translate,opacity,color,background-color,border-color] duration-[var(--dur-3)] ease-[var(--ease-spring)]",
  "data-[side=right]:inset-y-2 data-[side=right]:right-2 data-[side=right]:h-auto data-[side=right]:rounded-[var(--r-2xl)]",
  "data-[side=right]:w-[min(560px,calc(100vw_-_16px))] data-[side=right]:max-w-none data-[side=right]:sm:max-w-none",
  // A-12：关闭按钮 32×32 圆形 --surface-sunken 底，absolute 16/16（基座 ui/sheet.tsx 已定，
  // 这里只补 hover/focus 的可见反馈）。
  "[&>[data-slot=sheet-close]]:text-[var(--label-2)] [&>[data-slot=sheet-close]:hover]:text-[var(--label-1)] [&>[data-slot=sheet-close]:focus-visible]:ring-2 [&>[data-slot=sheet-close]:focus-visible]:ring-[var(--primary-ring)]",
);

export function AdminDrawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
  bodyRef,
}: AdminDrawerProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className={cn(drawerPanelClass, className)}>
        {/* A-12：头部 padding 20/24/16（右侧加宽到 56px 给 32px 关闭钮让位）、min-height 64px；
            背景不再单独上灰底/模糊，直接透出抽屉主体的面板底色（--mat-sheet-bg）。
            头部位于滚动容器之外，滚动内容不会从其下方穿过，无需自带上底。 */}
        <SheetHeader className="min-h-16 justify-center gap-1 border-b border-[var(--hairline)] pt-5 pb-4 pr-14 pl-6">
          <SheetTitle className="text-[17px] font-semibold leading-snug tracking-tight break-words text-[var(--label-1)]">
            {title}
          </SheetTitle>
          {description ? (
            <SheetDescription className="text-[13px] leading-relaxed break-words text-[var(--label-2)]">
              {description}
            </SheetDescription>
          ) : null}
        </SheetHeader>
        {/* 内容分组：A-07 分组卡片基调 —— --surface-raised、--r-lg、--shadow-1、1px --hairline。
            卡内行级排版（行高/分隔线左缩进）由各页 section 内容自定，容器只给卡片外观与间距。 */}
        <div
          ref={bodyRef}
          className={cn(
            "min-h-0 flex-1 overflow-y-auto overscroll-contain p-4",
            "[&>section]:space-y-3 [&>section]:rounded-[var(--r-lg)] [&>section]:border [&>section]:border-[var(--hairline)] [&>section]:bg-[var(--surface-raised)] [&>section]:px-4 [&>section]:py-4 [&>section]:shadow-[var(--shadow-1)]",
            "[&>section+section]:mt-4",
            "[&_.admin-kv-grid]:sm:grid-cols-1 [&_.admin-kv-grid]:sm:gap-y-1.5 [&_.admin-kv-grid_.admin-kv-label]:sm:text-left",
          )}
        >
          {children}
        </div>
        {footer ? (
          <div className="shrink-0 border-t border-[var(--hairline)] bg-[var(--mat-sheet-bg)] px-6 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
            {footer}
          </div>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
