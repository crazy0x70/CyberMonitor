"use client"

import { Switch as SwitchPrimitive } from "@base-ui/react/switch"

import { cn } from "@/lib/utils"

// A-06 第 4 条（0.1.1 裁定开启色用 --ok）：
// 轨道 40×24（sm 32×20）、--r-full；滑块 20px 白 + --shadow-1；
// 关闭 --surface-sunken + 1px --hairline；开启 --ok；
// 滑块移动 --ease-bounce --dur-3；按住时滑块横向拉长到 24px（宽度增大，
// 选中位移用 calc(内容宽 - 100%) 让右缘固定、向左伸展，iOS 按压形变）。
// 内容宽 = 轨道宽 - 2×边框(1px) - 2×内边距(2px)：default 36px、sm 28px。
function Switch({
  className,
  size = "default",
  ...props
}: SwitchPrimitive.Root.Props & {
  size?: "sm" | "default"
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch relative inline-flex shrink-0 items-center rounded-full border border-transparent px-[1px] outline-none after:absolute after:-inset-x-3 after:-inset-y-2 [transition:background-color_var(--dur-2),border-color_var(--dur-2),box-shadow_var(--dur-2),opacity_var(--dur-2)] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent aria-invalid:border-[var(--danger)] aria-invalid:ring-[3px] aria-invalid:ring-[color-mix(in_srgb,var(--danger)_40%,transparent)] aria-invalid:ring-offset-2 aria-invalid:ring-offset-transparent data-[size=default]:h-6 data-[size=default]:w-10 data-[size=sm]:h-5 data-[size=sm]:w-8 data-checked:border-transparent data-checked:bg-[var(--ok)] data-unchecked:border-[var(--hairline)] data-unchecked:bg-[var(--surface-sunken)] data-disabled:cursor-not-allowed data-disabled:opacity-50",
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block size-5 rounded-full bg-white shadow-[var(--shadow-1)] ring-0 [transition:transform_var(--dur-3)_var(--ease-bounce),width_var(--dur-2)] group-data-[size=default]/switch:data-checked:translate-x-[calc(36px_-_100%)] group-data-[size=sm]/switch:size-4 group-data-[size=sm]/switch:data-checked:translate-x-[calc(28px_-_100%)] group-active/switch:w-6"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
