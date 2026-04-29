import * as React from "react"

import { cn } from "@/lib/utils"

function Textarea({ className, id, name, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      id={id}
      name={name || id}
      data-slot="textarea"
      className={cn(
        "flex field-sizing-content min-h-16 w-full rounded-[1rem] border border-input bg-background px-3.5 py-3 text-base transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 md:text-sm",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
