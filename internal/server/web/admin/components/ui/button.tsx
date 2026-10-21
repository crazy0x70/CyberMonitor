import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

// A-05 按钮体系（evolution_log §6 A-05）：
// - 通用：transition 按令牌分属性时长（transform 与 scale 均 --dur-1——Tailwind v4 的
//   active:scale-* 走原生 scale 属性，须与 transform 分列才能被过渡；颜色/边框/阴影 --dur-2），
//   按下 scale(.97)（M-08），
//   焦点环 0 0 0 3px var(--accent-ring)，与边框之间留 2px 透明间隙（ring-offset-transparent）。
// - 变体与 lib/admin-ui.ts 的 admin*ButtonClass 使用完全一致的 utility 字符串，
//   页面同时传 variant + admin 类时 tailwind-merge 可正确去重。
const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-full border border-transparent bg-clip-padding text-sm font-medium whitespace-nowrap outline-none select-none [transition:color_var(--dur-2),background-color_var(--dur-2),border-color_var(--dur-2),box-shadow_var(--dur-2),transform_var(--dur-1),scale_var(--dur-1)] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent active:scale-[0.97] disabled:pointer-events-none aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 [&_svg]:transition-transform [&_svg]:duration-[var(--dur-2)]",
  {
    variants: {
      variant: {
        // 主按钮：--accent 底 + 白色高光渐变 + inset 高光 + --shadow-1；禁用为内凹底、无边框无投影
        default:
          "bg-[linear-gradient(180deg,rgba(255,255,255,0.12),transparent)] bg-[var(--accent)] text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.25),var(--shadow-1)] hover:bg-[var(--accent-hover)] disabled:border-transparent disabled:bg-none disabled:bg-[var(--surface-sunken)] disabled:text-[var(--label-4)] disabled:shadow-none",
        // 次级：36px 胶囊玻璃（--mat-control-bg + --blur-ultrathin + --hairline 边 + 上沿内高光）
        outline:
          "border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--label-1)] shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] hover:border-[var(--hairline-strong)] hover:bg-[rgba(255,255,255,0.85)] hover:text-[var(--label-1)] dark:hover:bg-[rgba(255,255,255,0.12)] disabled:opacity-50",
        secondary:
          "border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--label-1)] shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] hover:border-[var(--hairline-strong)] hover:bg-[rgba(255,255,255,0.85)] hover:text-[var(--label-1)] dark:hover:bg-[rgba(255,255,255,0.12)] disabled:opacity-50",
        ghost:
          "text-[var(--label-1)] hover:bg-[var(--accent-tint)] hover:text-[var(--label-1)] disabled:opacity-50",
        // 危险：次级外观 + --danger 字，悬停 --danger-tint 底
        destructive:
          "border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--danger-text)] shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] hover:border-[var(--hairline-strong)] hover:bg-[var(--danger-tint)] hover:text-[var(--danger-text)] disabled:opacity-50",
        // 文字按钮：无底无框 --accent-text，悬停 --accent-tint 胶囊，箭头 translateX(2px)
        link: "border-transparent bg-none text-[var(--accent-text)] hover:bg-[var(--accent-tint)] hover:[&_svg]:translate-x-0.5 disabled:opacity-50",
      },
      size: {
        default:
          "h-9 gap-1 px-4 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        xs: "h-6 gap-1 px-2 text-xs in-data-[slot=button-group]:rounded-full has-data-[icon=inline-end]:pr-1 has-data-[icon=inline-start]:pl-1 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-7 gap-1 px-2 text-[0.8rem] in-data-[slot=button-group]:rounded-full has-data-[icon=inline-end]:pr-1 has-data-[icon=inline-start]:pl-1 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-10 gap-1 px-4 has-data-[icon=inline-end]:pr-4 has-data-[icon=inline-start]:pl-4",
        // 纯图标按钮：32 / 36px 圆形（A-05）
        icon: "size-8",
        "icon-xs":
          "size-6 in-data-[slot=button-group]:rounded-full [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
          "size-7 in-data-[slot=button-group]:rounded-full",
        "icon-lg": "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  type = "button",
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      type={type}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
