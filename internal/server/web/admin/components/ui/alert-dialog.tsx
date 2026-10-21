import * as React from "react"
import { CircleAlert as AlertDialogIcon } from "lucide-react"
import { AlertDialog as AlertDialogPrimitive } from "@base-ui/react/alert-dialog"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

// A-11 第 1/3 条：遮罩与弹窗同规格 —— 浅色 rgba(0,0,0,.20)、深色 rgba(0,0,0,.45)，加 blur(6px)。
const alertDialogOverlayClass = cn(
  "fixed inset-0 isolate z-50 bg-[rgba(0,0,0,0.20)] [-webkit-backdrop-filter:blur(6px)] [backdrop-filter:blur(6px)]",
  "dark:bg-[rgba(0,0,0,0.45)]",
  "duration-[var(--dur-2)] data-open:animate-in data-open:fade-in data-closed:animate-out data-closed:fade-out"
)

function AlertDialog({ ...props }: AlertDialogPrimitive.Root.Props) {
  return <AlertDialogPrimitive.Root data-slot="alert-dialog" {...props} />
}

function AlertDialogTrigger({ ...props }: AlertDialogPrimitive.Trigger.Props) {
  return (
    <AlertDialogPrimitive.Trigger data-slot="alert-dialog-trigger" {...props} />
  )
}

function AlertDialogPortal({ ...props }: AlertDialogPrimitive.Portal.Props) {
  return (
    <AlertDialogPrimitive.Portal data-slot="alert-dialog-portal" {...props} />
  )
}

function AlertDialogOverlay({
  className,
  ...props
}: AlertDialogPrimitive.Backdrop.Props) {
  return (
    <AlertDialogPrimitive.Backdrop
      data-slot="alert-dialog-overlay"
      className={cn(alertDialogOverlayClass, className)}
      {...props}
    />
  )
}

// A-11 第 3 条：确认弹窗（macOS alert 样式）。
// 注意：组件内置样式排列在页面传入 className 之后（cn(className, internal)）——
// 页面历史传入的 adminDialogContentClass（p-0 / 旧底色 / 旧投影）会被本规格整体取代，
// 这正是「确认弹窗统一 macOS alert」的落地方式；追加型类（定位、宽度微调）仍可传入。
// variant="danger" 供删除、放弃修改等危险确认框显式声明，顶部图标圆切危险色板；
// 以前靠 :has([data-slot=alert-dialog-action][class*='text-[var(--danger)]']) 探测，
// 但危险按钮实际传的是 adminDialogDangerActionClass（rose 底白字），从不匹配。
function AlertDialogContent({
  className,
  size = "default",
  variant = "default",
  children,
  ...props
}: AlertDialogPrimitive.Popup.Props & {
  size?: "default" | "sm"
  variant?: "default" | "danger"
}) {
  return (
    <AlertDialogPortal>
      <AlertDialogOverlay />
      <AlertDialogPrimitive.Popup
        data-slot="alert-dialog-content"
        data-size={size}
        data-variant={variant}
        className={cn(
          className,
          // 玻璃弹窗底：--mat-sheet-bg + --blur-thick + 上沿内高光 + --shadow-4，圆角 --r-2xl，内边距 24px。
          // shadow 带 ! —— 调用方历史类 shadow-[var(--cm-elev-2)] 与 inset 阴影不属同一合并组，须强制优先；
          // dark:border-[var(--hairline)] 同理压掉调用方残留的 dark:border-neutral-800/60。
          "group/alert-dialog-content fixed top-1/2 left-1/2 z-50 grid w-[min(400px,calc(100%-2rem))] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-[var(--r-2xl)] border border-[var(--hairline)] bg-[var(--mat-sheet-bg)] p-6 text-center text-[var(--label-1)] dark:border-[var(--hairline)]",
          "shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-4)]! [-webkit-backdrop-filter:var(--blur-thick)] [backdrop-filter:var(--blur-thick)] outline-none",
          // 顶部 48px 图标圆的色板：保存/通用 --accent-tint 底 + --accent 图标；危险场景
          // --danger-tint 底 + --danger-text 图标（浅色 #b02225 / 深色 --danger，对比度达标）。
          // 变量按 variant 直接给出，不依赖类名探测。
          variant === "danger"
            ? "[--alert-media-bg:var(--danger-tint)] [--alert-media-fg:var(--danger-text)]"
            : "[--alert-media-bg:var(--accent-tint)] [--alert-media-fg:var(--accent)]",
          // 进入：scale(.96) translateY(8px)→0 + opacity，--dur-4 --ease-spring；退出：--dur-2 淡出 + scale(.98)
          "transition-none duration-100",
          "data-open:animate-in data-open:fade-in data-open:[--tw-enter-scale:0.96] data-open:[--tw-enter-translate-y:0.5rem] data-open:duration-[var(--dur-4)] data-open:ease-[var(--ease-spring)]",
          "data-closed:animate-out data-closed:fade-out data-closed:[--tw-exit-scale:0.98] data-closed:duration-[var(--dur-2)]"
        )}
        {...props}
      >
        {/* A-11 第 3 条：顶部 48px 图标圆，由组件自动渲染（页面无需逐个接入）；
            保存/通用 --accent-tint、危险确认框 --danger-tint（由 variant 决定） */}
        <div
          data-slot="alert-dialog-media"
          aria-hidden="true"
          className="mx-auto mb-1.5 inline-flex size-12 items-center justify-center rounded-full bg-[var(--alert-media-bg,var(--accent-tint))] text-[var(--alert-media-fg,var(--accent))]"
        >
          <AlertDialogIcon className="size-6" />
        </div>
        {children}
      </AlertDialogPrimitive.Popup>
    </AlertDialogPortal>
  )
}

function AlertDialogHeader({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-dialog-header"
      className={cn(
        className,
        // macOS alert：图标圆下方，标题 + 说明居中（px/py 归零：抵消调用方历史类的内边距，
        // 弹窗 24px 内边距由 Content 的 p-6 统一提供；内置类在后，覆盖历史外观类）
        "flex flex-col items-center gap-1.5 px-0 pt-0 pb-0 text-center"
      )}
      {...props}
    />
  )
}

function AlertDialogFooter({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-dialog-footer"
      className={cn(
        className,
        // macOS alert：两栏全宽胶囊按钮（sm:grid 压掉调用方可能残留的 sm:flex-row；
        // px/py 归零抵消调用方历史内边距；内置类在后，覆盖历史外观类）
        "grid grid-cols-2 gap-2 px-0 pt-0 pb-0 sm:grid"
      )}
      {...props}
    />
  )
}

function AlertDialogMedia({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-dialog-media"
      className={cn(
        // A-11 第 3 条：48px 图标圆
        "mb-1.5 inline-flex size-12 items-center justify-center rounded-full bg-[var(--alert-media-bg,var(--accent-tint))] text-[var(--alert-media-fg,var(--accent))] *:[svg:not([class*='size-'])]:size-6",
        className
      )}
      {...props}
    />
  )
}

function AlertDialogTitle({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Title>) {
  return (
    <AlertDialogPrimitive.Title
      data-slot="alert-dialog-title"
      className={cn(
        // 弹窗标题 --t-title2（A-11 第 1 条）
        "text-[var(--label-1)] [font:var(--t-title2)] tracking-[var(--t-title2-ls)]",
        className
      )}
      {...props}
    />
  )
}

function AlertDialogDescription({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Description>) {
  return (
    <AlertDialogPrimitive.Description
      data-slot="alert-dialog-description"
      className={cn(
        "text-balance text-[13px] leading-relaxed text-[var(--label-2)] *:[a]:underline *:[a]:underline-offset-3 *:[a]:hover:text-[var(--label-1)]",
        className
      )}
      {...props}
    />
  )
}

function AlertDialogAction({
  className,
  variant = "default",
  size = "default",
  ...props
}: AlertDialogPrimitive.Close.Props & { variant?: any; size?: any }) {
  return (
    <AlertDialogPrimitive.Close
      data-slot="alert-dialog-action"
      className={cn(className, "w-full")}
      render={<Button variant={variant} size={size} />}
      {...props}
    />
  )
}

function AlertDialogCancel({
  className,
  variant = "outline",
  size = "default",
  ...props
}: AlertDialogPrimitive.Close.Props & { variant?: any; size?: any }) {
  return (
    <AlertDialogPrimitive.Close
      data-slot="alert-dialog-cancel"
      className={cn(className, "w-full")}
      render={<Button variant={variant} size={size} />}
      {...props}
    />
  )
}

export {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogIcon,
  AlertDialogMedia,
  AlertDialogOverlay,
  AlertDialogPortal,
  AlertDialogTitle,
  AlertDialogTrigger,
  alertDialogOverlayClass,
}
