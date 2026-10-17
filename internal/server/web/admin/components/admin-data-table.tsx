import { useEffect, useRef, type KeyboardEvent, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";

import { cn } from "@/lib/utils";

export type AdminDataTableColumn<Row> = {
  key: string;
  label: ReactNode;

  align?: "left" | "center" | "right";
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
  // 覆盖 <table> 自身样式，典型用途：列宽之和较大的表格在窄屏下声明更大的最小宽度。
  tableClassName?: string;

  // A-05：作用于表格外层滚动容器（默认 w-full max-md:overflow-x-auto 的 div），
  // 典型用途：卡片高度受控时声明 h-full overflow-y-auto 让表格在卡片内滚动。
  scrollClassName?: string;

  // A-05：为 th 显式声明 sticky top-0 z-[1] 与表头背景（现有 th 样式已含吸顶
  // 玻璃底；传入时 z 层收敛为 z-[1]，供内部滚动容器场景使用）。
  stickyHeader?: boolean;

  fixed?: boolean;
  showRowChevron?: boolean;
};

// A-09 第 5/6 条：状态徽标（在线 / 离线 / 未配置 / 日志等级）共用一套规格 ——
// 高 20px、--r-full、左右 8px、11px/600、前置 6px 圆点（bg-current 跟随文字色）、无边框。
// 颜色：在线 ok / 离线 danger / 警告 warn / 信息 accent（小字用 --accent-text 保 AA）/ 调试·未配置中性。
export type AdminStatusBadgeTone = "ok" | "danger" | "warn" | "accent" | "neutral";

const adminStatusBadgeToneClass: Record<AdminStatusBadgeTone, string> = {
  ok: "bg-[var(--ok-tint)] text-[var(--ok)]",
  danger: "bg-[var(--danger-tint)] text-[var(--danger)]",
  warn: "bg-[var(--warn-tint)] text-[var(--warn)]",
  accent: "bg-[var(--accent-tint)] text-[var(--accent-text)]",
  neutral: "bg-[var(--surface-sunken)] text-[var(--label-2)]",
};

export function adminStatusBadgeClass(tone: AdminStatusBadgeTone) {
  return cn(
    "inline-flex h-5 items-center gap-1.5 rounded-full px-2 text-[11px] font-semibold",
    "before:inline-block before:size-1.5 before:shrink-0 before:rounded-full before:bg-current before:content-['']",
    adminStatusBadgeToneClass[tone],
  );
}

export function AdminDataTable<Row>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowAttributes,
  emptyLabel,
  ariaLabel,
  className,
  tableClassName,
  scrollClassName,
  stickyHeader = false,
  fixed = false,
  showRowChevron = true,
}: AdminDataTableProps<Row>) {
  const clickable = Boolean(onRowClick);
  const rowChevron = clickable && showRowChevron;

  // A-05 第 6 条：滚动容器在 scrollHeight > clientHeight + 1 且未滚到底时加
  // is-scrollable 类（配合恒挂的 [&.is-scrollable]:mask… 做 16px 底部渐隐），
  // 在 ResizeObserver 与 scroll 事件中更新。默认容器不可纵向滚动，恒不触发。
  const scrollRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) {
      return;
    }
    const update = () => {
      const scrollable =
        el.scrollHeight > el.clientHeight + 1 &&
        el.scrollTop + el.clientHeight < el.scrollHeight - 1;
      el.classList.toggle("is-scrollable", scrollable);
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    el.addEventListener("scroll", update, { passive: true });
    return () => {
      observer.disconnect();
      el.removeEventListener("scroll", update);
      el.classList.remove("is-scrollable");
    };
  }, []);

  const handleRowKeyDown = (event: KeyboardEvent<HTMLTableRowElement>, row: Row, index: number) => {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    event.preventDefault();
    onRowClick?.(row, index);
  };

  return (
    // A-09 第 1 条：表格整体入卡。--surface-raised、--r-lg、--shadow-1、1px --hairline 边。
    // 说明：不加 overflow-hidden——那会创建滚动容器、令 sticky 表头（第 2 条）失效；
    // 圆角由表头单元格与末行/空态单元格的自身圆角保证（悬停背景在 td 上，同样被圆角约束）。
    <div
      className={cn(
        "rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] shadow-[var(--shadow-1)]",
        className,
      )}
    >
      {/* A-13 第 1 条：w-full 保证表头/表格铺满卡片宽度；thead 的背景落在各 th 上。
          A-05：scrollClassName 作用于该滚动容器；is-scrollable 由上方 effect 按需
          切换，底部 16px 渐隐提示可继续滚动。 */}
      <div
        ref={scrollRef}
        className={cn(
          "w-full max-md:overflow-x-auto",
          "[&.is-scrollable]:[mask-image:linear-gradient(to_bottom,black_calc(100%-16px),transparent)]",
          scrollClassName,
        )}
      >
        <table
          aria-label={ariaLabel}
          className={cn(
            "w-full border-separate border-spacing-0 text-sm",
            fixed && "table-fixed max-md:min-w-[44rem]",
            tableClassName,
          )}
        >
          <thead>
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  style={
                    column.width
                      ? { width: column.width }
                      : fixed
                        ? { width: "100%" }
                        : undefined
                  }
                  className={cn(
                    // A-09 第 2 条：36px 高、--t-caption、--label-3、下边 1px --hairline。
                    // 吸顶（sticky top-0）：玻璃条 --mat-bar-bg + --blur-thin——纯 CSS 无法区分
                    // 「是否已吸顶」，玻璃底常驻（未吸顶时表头下无内容滑过，视觉≈卡内白色表头）。
                    "sticky top-0 z-10 h-9 border-b border-[var(--hairline)] bg-[var(--mat-bar-bg)] px-3 text-left whitespace-nowrap text-[var(--label-3)] [-webkit-backdrop-filter:var(--blur-thin)] [backdrop-filter:var(--blur-thin)] [font:var(--t-caption)] first:rounded-tl-[var(--r-lg)] first:pl-4 last:rounded-tr-[var(--r-lg)] last:pr-4",
                    // A-05：stickyHeader 时 z 收敛为 z-[1]（内部滚动容器场景）。
                    stickyHeader && "z-[1]",
                    column.align === "center" && "text-center",
                    column.align === "right" && "text-right",
                  )}
                >
                  {column.label}
                </th>
              ))}
              {rowChevron ? (
                <th
                  scope="col"
                  aria-hidden="true"
                  className={cn(
                    "sticky top-0 z-10 h-9 w-8 border-b border-[var(--hairline)] bg-[var(--mat-bar-bg)] py-0 pr-4 [-webkit-backdrop-filter:var(--blur-thin)] [backdrop-filter:var(--blur-thin)]",
                    "rounded-tr-[var(--r-lg)]",
                    stickyHeader && "z-[1]",
                  )}
                />
              ) : null}
            </tr>
          </thead>
          <tbody
            className={cn(
              // A-09 第 3 条：行分隔 1px --hairline，左端缩进 16px（iOS / macOS 分隔线规则）。
              // 用 tr::after 画线（首列 border 无法只从 16px 处起笔），末行不画。
              "[&_tr]:relative [&_tr::after]:pointer-events-none [&_tr::after]:absolute [&_tr::after]:-bottom-px [&_tr::after]:left-4 [&_tr::after]:right-0 [&_tr::after]:h-px [&_tr::after]:bg-[var(--hairline)] [&_tr::after]:content-['']",
              "[&_tr:last-child::after]:content-none",
              // 末行首/末单元格承接卡片底部圆角（悬停背景在 td 上，圆角对背景生效）
              "[&_tr:last-child>td:first-child]:rounded-bl-[var(--r-lg)] [&_tr:last-child>td:last-child]:rounded-br-[var(--r-lg)]",
            )}
          >
            {rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length + (rowChevron ? 1 : 0)}
                  className={cn(
                    "px-5 py-12 text-center text-sm text-[var(--label-3)]",
                    "first:rounded-bl-[var(--r-lg)] last:rounded-br-[var(--r-lg)]",
                  )}
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
                    "group/row h-12",
                    clickable &&
                      cn(
                        "cursor-pointer outline-none",
                        // 悬停 / 按下背景落在 td 上（末行圆角由 td 承接）；深色取对称提亮值
                        "hover:[&>td]:bg-[rgba(0,0,0,0.025)] hover:dark:[&>td]:bg-[rgba(255,255,255,0.05)]",
                        "active:[&>td]:bg-[rgba(0,0,0,0.05)] active:dark:[&>td]:bg-[rgba(255,255,255,0.10)]",
                        "focus-visible:[&>td]:bg-[rgba(0,0,0,0.025)] focus-visible:dark:[&>td]:bg-[rgba(255,255,255,0.05)]",
                        "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--primary-ring)]",
                      ),
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
                        // A-09 第 3/4 条：48px 行高（py 14px + 20px 行高）；名称列 14px/500 由列渲染处给出。
                        // mono 列（IP/版本/时间戳/端点）：.num（--font-data + tabular-nums）13px --label-2。
                        "whitespace-nowrap px-3 py-[14px] text-left text-sm text-[var(--label-1)]",
                        "first:pl-4 last:pr-4",
                        // 固定布局下列宽固定，内容超宽时裁切在本列内，避免溢出压到相邻列上。
                        fixed && "overflow-hidden text-ellipsis",
                        column.align === "center" && "text-center",
                        column.align === "right" && "text-right",
                        column.mono && "data-text text-[13px] font-normal text-[var(--label-2)]",
                      )}
                    >
                      {column.render(row, index)}
                    </td>
                  ))}
                  {rowChevron ? (
                    <td className="w-8 py-[14px] pr-4 text-right text-[var(--label-4)] transition-colors duration-150 group-hover/row:text-[var(--label-2)]">
                      <ChevronRight
                        aria-hidden="true"
                        className="ml-auto h-4 w-4 transition-transform duration-150 group-hover/row:translate-x-0.5"
                      />
                    </td>
                  ) : null}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
