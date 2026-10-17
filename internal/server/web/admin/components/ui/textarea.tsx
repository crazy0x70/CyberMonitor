import * as React from "react"

import { cn } from "@/lib/utils"

function Textarea({ className, id, name, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      id={id}
      name={name || id}
      data-slot="textarea"
      className={cn(
        "flex min-h-[88px] w-full resize-y rounded-[var(--r-md)] bg-[var(--surface-sunken)] px-3.5 py-2 text-sm leading-relaxed text-[var(--label-1)] outline-none [transition:background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[color-mix(in_oklab,var(--surface-sunken)_98%,black)] placeholder:text-[var(--label-4)] placeholder:[font-family:var(--font-ui)] focus:bg-[var(--surface-solid)] focus:shadow-[0_0_0_1px_var(--accent),0_0_0_4px_var(--accent-ring)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:bg-[var(--danger-tint)] aria-invalid:focus:shadow-[0_0_0_1px_var(--danger),0_0_0_4px_color-mix(in_srgb,var(--danger)_40%,transparent)]",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
