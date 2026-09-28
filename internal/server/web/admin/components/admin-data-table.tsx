import type { KeyboardEvent, ReactNode } from "react";
import { ChevronRight } from "lucide-react";

import { cn } from "@/lib/utils";

export type AdminDataTableColumn<Row> = {
  key: string;
  label: ReactNode;

  align?: "left" | "right";

  width?: string;
  mono?: boolean;
  render: (row: Row, index: number) => ReactNode;
};

type AdminDataTableProps<Row> = {
  columns: ReadonlyArray<AdminDataTableColumn<Row>>;
  rows: ReadonlyArray<Row>;
  rowKey: (row: Row, index: number) => string;

  onRowClick?: (row: Row, index: number) => void;

  rowAttributes?: (row: Row, index: number) => Record<string, string>;

  emptyLabel: ReactNode;
  ariaLabel: string;
  className?: string;

  showRowChevron?: boolean;
};

export function AdminDataTable<Row>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowAttributes,
  emptyLabel,
  ariaLabel,
  className,
  showRowChevron = true,
}: AdminDataTableProps<Row>) {
  const clickable = Boolean(onRowClick);
  const rowChevron = clickable && showRowChevron;

  const handleRowKeyDown = (event: KeyboardEvent<HTMLTableRowElement>, row: Row, index: number) => {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    event.preventDefault();
    onRowClick?.(row, index);
  };

  return (
    <div className={cn(className)}>
      <table aria-label={ariaLabel} className="w-full border-separate border-spacing-0 text-sm">
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                style={column.width ? { width: column.width } : undefined}
                className={cn(
                  "sticky top-0 z-10 border-b border-[var(--separator-opaque)] bg-[var(--surface-base)] px-3 py-2.5 text-xs font-medium text-[var(--label-2)] first:pl-5 last:pr-5",
                  column.align === "right" ? "text-right" : "text-left",
                  column.mono && "data-text",
                )}
              >
                {column.label}
              </th>
            ))}
            {rowChevron ? (
              <th
                scope="col"
                aria-hidden="true"
                className="sticky top-0 z-10 w-8 border-b border-[var(--separator-opaque)] bg-[var(--surface-base)] py-2.5 pr-5"
              />
            ) : null}
          </tr>
        </thead>
        <tbody className="[&>tr>td]:border-b [&>tr>td]:border-[var(--separator)] [&>tr:last-child>td]:border-b-0">
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length + (rowChevron ? 1 : 0)}
                className="px-5 py-12 text-center text-sm text-[var(--label-3)]"
              >
                {emptyLabel}
              </td>
            </tr>
          ) : (
            rows.map((row, index) => (
              <tr
                key={rowKey(row, index)}
                tabIndex={clickable ? 0 : undefined}
                {...(rowAttributes?.(row, index) || {})}
                className={cn(
                  clickable &&
                    "cursor-pointer transition-colors duration-150 outline-none hover:bg-[var(--surface-2)] focus-visible:bg-[var(--surface-2)] focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--primary-ring)]",
                )}
                onClick={clickable ? () => onRowClick?.(row, index) : undefined}
                onKeyDown={
                  clickable ? (event) => handleRowKeyDown(event, row, index) : undefined
                }
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn(
                      "whitespace-nowrap px-3 py-2.5 text-slate-700 dark:text-neutral-200",
                      "first:pl-5 last:pr-5",
                      column.align === "right" ? "text-right" : "text-left",
                      column.mono && "data-text",
                    )}
                  >
                    {column.render(row, index)}
                  </td>
                ))}
                {rowChevron ? (
                  <td className="w-8 py-2.5 pr-5 text-right text-[var(--label-3)]">
                    <ChevronRight className="ml-auto h-4 w-4" aria-hidden="true" />
                  </td>
                ) : null}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
