import * as React from "react"
import { Input as InputPrimitive } from "@base-ui/react/input"

import { cn } from "@/lib/utils"

function Input({ className, type, id, name, ...props }: React.ComponentProps<"input">) {
  return (
    <InputPrimitive
      type={type}
      id={id}
      name={name || id}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 rounded-[var(--r-md)] bg-[var(--surface-sunken)] px-3.5 py-2 text-sm text-[var(--label-1)] outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-[var(--label-1)] [transition:background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[color-mix(in_oklab,var(--surface-sunken)_98%,black)] placeholder:text-[var(--label-4)] placeholder:[font-family:var(--font-ui)] focus:bg-[var(--surface-solid)] focus:shadow-[0_0_0_1px_var(--accent),0_0_0_4px_var(--accent-ring)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:bg-[var(--danger-tint)] aria-invalid:focus:shadow-[0_0_0_1px_var(--danger),0_0_0_4px_color-mix(in_srgb,var(--danger)_40%,transparent)]",
        className
      )}
      {...props}
    />
  )
}

export { Input }
