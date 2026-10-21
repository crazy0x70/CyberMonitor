
export const adminPageShellClass =
  "mx-auto w-full max-w-[1200px] space-y-10 text-slate-900 dark:text-neutral-100";

// E-03：设置类页面窄版外壳（页头、横幅、表单同宽 880px），页面接线由后续任务做
export const adminNarrowPageShellClass =
  "mx-auto w-full max-w-[880px] space-y-8 text-[var(--label-1)]";

export const adminPageHeaderClass =
  "flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between";

// A-04 第 2 条：h1 用 --t-title1（650 28px/1.15 --font-display / -0.022em），手机（<sm）降 24px
export const adminPageTitleClass =
  "text-[var(--label-1)] [font:var(--t-title1)] max-sm:[font:650_24px/1.15_var(--font-display)] tracking-[var(--t-title1-ls)]";

// 移动端（<sm）页头操作区为 2 列网格（R3）：状态徽标（直接子 span）独占整行且内容宽左对齐，
// 唯一操作按钮（主操作）整行铺满，多个操作按钮时各占半宽；
// sm 起恢复 flex 内容宽度左对齐，lg 起由页头的 flex-row justify-between 接管。
export const adminPageActionsClass =
  "grid w-full grid-cols-2 gap-2 [&>span]:col-span-2 [&>span]:justify-self-start [&>button:only-of-type]:col-span-2 sm:flex sm:w-auto sm:flex-wrap sm:items-center sm:justify-start";

// A-05：min-h-9（36px）固定标题行高度——标题行内容（如分段控件）高度不一时，
// 全站 AdminPanel 卡片体顶部对齐。
export const adminSectionHeaderClass =
  "flex min-h-9 flex-wrap items-center justify-between gap-x-4 gap-y-2 pb-4";

export const adminMutedTextClass = "text-[var(--label-2)]";

// A-06 第 6 条：错误文字 12px --danger-text，前置 12px exclamationmark.circle 图标（currentColor 着色）
export const adminFieldErrorClass =
  "flex items-start gap-1.5 text-xs font-medium leading-relaxed text-[var(--danger-text)] before:mt-px before:inline-block before:size-3 before:shrink-0 before:bg-current before:content-[''] before:[mask-image:url('data:image/svg+xml,%3Csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20viewBox=%270%200%2024%2024%27%20fill=%27none%27%20stroke=%27black%27%20stroke-width=%272%27%20stroke-linecap=%27round%27%20stroke-linejoin=%27round%27%3E%3Ccircle%20cx=%2712%27%20cy=%2712%27%20r=%2710%27%2F%3E%3Cline%20x1=%2712%27%20y1=%278%27%20x2=%2712%27%20y2=%2712%27%2F%3E%3Cline%20x1=%2712%27%20y1=%2712.01%27%20x2=%2712%27%20y2=%2716%27%2F%3E%3C/svg%3E')] before:[mask-size:100%_100%] before:[mask-repeat:no-repeat]";

export const adminHelpTextClass =
  "text-xs leading-relaxed text-[var(--label-2)]";

// 抽屉内分区标题；如需按 §5 层级规范升 15px，须由页面组统一切换，避免字号漂移。
export const adminDrawerSectionTitleClass =
  "text-sm font-semibold text-[var(--label-1)]";

export const adminDirtyBadgeClass =
  "rounded-full border border-amber-200 bg-amber-50/80 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200";

export const adminSuccessBadgeClass =
  "border-emerald-200/80 bg-emerald-100/80 text-emerald-700 hover:border-emerald-300 hover:bg-emerald-200 dark:border-emerald-900/60 dark:bg-emerald-950/80 dark:text-emerald-300 dark:hover:border-emerald-800 dark:hover:bg-emerald-900";

export const adminDangerBadgeClass =
  "border-rose-200/80 bg-rose-100/80 text-rose-700 hover:border-rose-300 hover:bg-rose-200 dark:border-rose-900/60 dark:bg-rose-950/80 dark:text-rose-300 dark:hover:border-rose-800 dark:hover:bg-rose-900";

export const adminWarningBadgeClass =
  "border-amber-200 bg-amber-50/80 text-amber-700 hover:bg-amber-100 dark:border-amber-900 dark:bg-amber-950/80 dark:text-amber-300 dark:hover:bg-amber-900";

export const adminNeutralBadgeClass =
  "border border-[var(--separator)] bg-slate-100/80 text-slate-700 hover:bg-slate-200 dark:bg-neutral-800/80 dark:text-neutral-300 dark:hover:bg-neutral-700";

// A-10 / P-05 分段控件（AdminLogs 日志筛选 / ProbeSettings 类型切换）公共部分：
// 轨道 32px、内边距 3px、--surface-sunken 底、--r-full、无边框；
// 选中项为静态白色滑块（--surface-solid + --shadow-1，深色 rgba(255,255,255,.14)），
// 0.1.2 裁定：滑动动画不做，仅 transition 背景色。差异部分由页面追加：
// AdminLogs 追加轨道 sm:w-auto、item sm:min-w-[52px] sm:flex-none；
// ProbeSettings 的 item 追加 outline-none/transition/focus-visible/disabled。
export const adminSegmentedTrackClass =
  "flex h-8 w-full gap-0.5 rounded-full bg-[var(--surface-sunken)] p-[3px]";

export const adminSegmentedItemClass =
  "h-[26px] min-w-0 flex-1 rounded-full px-3 text-xs font-medium";

export const adminSegmentedItemActiveClass =
  "bg-[var(--surface-solid)] text-[var(--label-1)] shadow-[var(--shadow-1)] [transition:background-color_var(--dur-2)] dark:bg-[rgba(255,255,255,0.14)]";

export const adminSegmentedItemInactiveClass =
  "bg-transparent text-[var(--label-2)] [transition:background-color_var(--dur-2)] hover:bg-transparent hover:text-[var(--label-1)]";

// A-05 按钮体系 —— 主按钮：36px 胶囊，--accent 底 + 由上到下 12% 白色高光渐变 + inset 高光 + --shadow-1；
// 悬停 --accent-hover，按下 scale(.97)；禁用为 --surface-sunken 底 --label-4 字、无边框无投影（不要白底灰边）。
// 通用：transition 按令牌分属性时长；焦点环 0 0 0 3px var(--accent-ring)，与边框留 2px 透明间隙。
export const adminPrimaryButtonClass =
  "inline-flex h-9 min-w-[110px] items-center justify-center gap-1.5 rounded-full border border-transparent bg-[linear-gradient(180deg,rgba(255,255,255,0.12),transparent)] bg-[var(--accent)] px-4 text-sm font-medium text-white outline-none shadow-[inset_0_1px_0_rgba(255,255,255,0.25),var(--shadow-1)] [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[var(--accent-hover)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:border-transparent disabled:bg-none disabled:bg-[var(--surface-sunken)] disabled:text-[var(--label-4)] disabled:shadow-none";

// A-05 次级按钮：36px 胶囊玻璃（--mat-control-bg + --blur-ultrathin + --hairline 边 + 上沿内高光），
// 悬停背景提亮、边框 --hairline-strong。
export const adminOutlineButtonClass =
  "h-9 rounded-full border border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--label-1)] outline-none shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2),border-color_var(--dur-2),box-shadow_var(--dur-2)] hover:border-[var(--hairline-strong)] hover:bg-[rgba(255,255,255,0.85)] hover:text-[var(--label-1)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50 dark:hover:bg-[rgba(255,255,255,0.12)]";

export const adminActionButtonClass =
  `${adminOutlineButtonClass} inline-flex min-w-[110px] items-center justify-center px-4`;

export const adminCompactActionButtonClass =
  `${adminOutlineButtonClass} inline-flex items-center justify-center gap-1.5 h-9 whitespace-nowrap px-4 text-xs font-medium leading-none`;

// A-05 危险按钮：次级按钮外观 + --danger-text 字，悬停 --danger-tint 底
export const adminDangerOutlineButtonClass =
  "h-9 rounded-full border border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--danger-text)] outline-none shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2),border-color_var(--dur-2),box-shadow_var(--dur-2)] hover:border-[var(--hairline-strong)] hover:bg-[var(--danger-tint)] hover:text-[var(--danger-text)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50";

// A-05 文字按钮：无底无框 --accent-text 字，悬停出现 --accent-tint 胶囊底，箭头悬停 translateX(2px)
export const adminTextButtonClass =
  "inline-flex items-center gap-1 rounded-full px-2 text-sm font-medium text-[var(--accent-text)] outline-none [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2)] hover:bg-[var(--accent-tint)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent [&_svg]:transition-transform [&_svg]:duration-[var(--dur-2)] hover:[&_svg]:translate-x-0.5";

export const adminLoadingCardClass =
  "w-full max-w-md rounded-xl border border-[var(--cm-panel-border)] bg-[var(--surface-1)]";

export const adminLoadingCardContentClass =
  "flex items-center justify-center gap-4 py-8 text-sm font-medium text-slate-500 dark:text-neutral-400";

// A-06 输入框：36px 高、--r-md、--surface-sunken 内凹底无边框（macOS 系统设置风格）；
// 悬停背景加深 2%（color-mix），聚焦变 --surface-solid 实底 + accent 焦点环（--dur-2）；
// 占位符 --label-4 且 --font-ui（E-06）。
export const adminInputClass =
  "h-9 rounded-[var(--r-md)] bg-[var(--surface-sunken)] px-3.5 text-sm text-[var(--label-1)] outline-none [transition:background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[color-mix(in_oklab,var(--surface-sunken)_98%,black)] placeholder:text-[var(--label-4)] placeholder:[font-family:var(--font-ui)] focus:bg-[var(--surface-solid)] focus:shadow-[0_0_0_1px_var(--accent),0_0_0_4px_var(--accent-ring)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50";

export const adminWideInputClass = `max-w-xl ${adminInputClass}`;

// A-06 文本域：同输入框，最小高 88px，resize: vertical
export const adminTextareaClass =
  "min-h-[88px] resize-y rounded-[var(--r-md)] bg-[var(--surface-sunken)] px-3.5 py-2 text-sm leading-relaxed text-[var(--label-1)] outline-none [transition:background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[color-mix(in_oklab,var(--surface-sunken)_98%,black)] placeholder:text-[var(--label-4)] placeholder:[font-family:var(--font-ui)] focus:bg-[var(--surface-solid)] focus:shadow-[0_0_0_1px_var(--accent),0_0_0_4px_var(--accent-ring)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50";

// A-06 选择框：同输入框；右侧双箭头（chevrons-up-down 12px --label-3）由 ui/select.tsx 的触发器图标提供
export const adminSelectTriggerClass =
  "h-9 rounded-[var(--r-md)] bg-[var(--surface-sunken)] px-3.5 text-sm text-[var(--label-1)] outline-none [transition:background-color_var(--dur-2),box-shadow_var(--dur-2)] hover:bg-[color-mix(in_oklab,var(--surface-sunken)_98%,black)] focus:bg-[var(--surface-solid)] focus:shadow-[0_0_0_1px_var(--accent),0_0_0_4px_var(--accent-ring)] disabled:cursor-not-allowed disabled:opacity-50";

export const adminSelectContentClass =
  "rounded-[14px] border border-[var(--cm-control-border)] bg-[var(--surface-3)] text-slate-900 dark:text-neutral-50";

export const adminDialogContentClass =
  "overflow-hidden rounded-2xl border-slate-200/60 bg-[var(--surface-3)] p-0 gap-0 dark:border-neutral-800/60 shadow-[var(--cm-elev-2)]";

export const adminDialogHeaderClass =
  "grid-rows-[auto] space-y-2 border-b-0 px-6 pt-6 pb-0 text-left";

export const adminDialogFooterClass =
  "m-0 border-t-0 bg-transparent px-6 pt-4 pb-6 dark:bg-transparent";

export const adminDialogCancelClass =
  "h-9 rounded-full border-slate-300 bg-white px-4 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-neutral-700 dark:bg-[var(--surface-2)] dark:text-neutral-300 dark:hover:bg-neutral-800";

export const adminDialogDangerActionClass =
  "h-9 rounded-full bg-rose-600 px-4 text-sm font-medium text-white hover:bg-rose-700 dark:bg-rose-500 dark:hover:bg-rose-400";

export const adminCodeBlockPanelClass =
  "rounded-lg border border-[var(--separator)] bg-[var(--surface-1)] p-4 data-text text-[12px] leading-relaxed text-slate-800 dark:bg-[var(--surface-2)] dark:text-neutral-200";

// A-02 一级菜单项：手机抽屉 44px（h-11）/ 桌面 34px（md:h-[34px]，A-07 第 3 条）/ --r-sm / 内边距 0 10px。
// A-06：标签区与右侧箭头按钮同为行内热区，锚点改 flex-1 占满剩余宽度（外层为 flex 行容器）。
// 图标 16px stroke 1.75 由 JSX 上的 strokeWidth 控制；悬停浅色 rgba(0,0,0,.04)、深色 rgba(255,255,255,.06)。
export const adminSidebarNavItemClass =
  "group relative flex h-11 min-w-0 flex-1 items-center gap-2.5 rounded-[var(--r-sm)] px-2.5 text-[16px] font-medium text-[var(--label-2)] outline-none transition-colors duration-[var(--dur-2)] hover:bg-[rgba(0,0,0,0.04)] hover:text-[var(--label-1)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] md:h-[34px] md:text-[13px] dark:hover:bg-[rgba(255,255,255,0.06)]";

// 内层 gap-2.5（A-07 第 1 条：图标与文字间距 10px）
export const adminSidebarNavLabelClass = "flex min-w-0 items-center gap-2.5";

// A-03 汉堡按钮：36px 圆形玻璃（--mat-control-bg + --blur-ultrathin + hairline 边 + 上沿内高光）
export const adminSidebarIconButtonClass =
  "h-9 w-9 rounded-full border border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--label-2)] shadow-[inset_0_1px_0_var(--glass-edge)] outline-none [backdrop-filter:var(--blur-ultrathin)] transition-[background-color,color] duration-[var(--dur-2)] hover:bg-[rgba(255,255,255,0.85)] hover:text-[var(--label-1)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:hover:bg-[rgba(255,255,255,0.12)] dark:hover:text-[var(--label-1)]";

// A-03 顶栏 / A-02 底部工具区的语言、主题圆形按钮：与汉堡同规格玻璃
export const adminThemeToggleButtonClass =
  "h-9 w-9 rounded-full border border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--label-2)] shadow-[inset_0_1px_0_var(--glass-edge)] outline-none [backdrop-filter:var(--blur-ultrathin)] transition-[background-color,color] duration-[var(--dur-2)] hover:bg-[rgba(255,255,255,0.85)] hover:text-[var(--label-1)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:hover:bg-[rgba(255,255,255,0.12)] dark:hover:text-[var(--label-1)]";

// A-02 底部工具区「退出登录」：与一级菜单项同规格的 32px 行，悬停文字图标转 --danger-text
export const adminSidebarSecondaryButtonClass =
  "h-8 w-full justify-start rounded-[var(--r-sm)] px-2.5 text-[13px] font-medium text-[var(--label-2)] outline-none transition-colors duration-[var(--dur-2)] hover:bg-[rgba(0,0,0,0.04)] hover:text-[var(--danger-text)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:hover:bg-[rgba(255,255,255,0.06)] dark:hover:text-[var(--danger-text)]";

export const adminSubtleOutlineBadgeClass =
  "border-slate-200/80 text-slate-500 dark:border-neutral-700/80 dark:text-neutral-400";

// A-05 纯图标危险按钮：36px 圆形，规格同次级按钮，文字/图标 --danger，悬停 --danger-tint 底
export const adminDangerIconButtonClass =
  "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-[var(--hairline)] bg-[var(--mat-control-bg)] text-[var(--danger)] outline-none shadow-[inset_0_1px_0_var(--glass-edge)] [-webkit-backdrop-filter:var(--blur-ultrathin)] [backdrop-filter:var(--blur-ultrathin)] [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2),border-color_var(--dur-2),box-shadow_var(--dur-2)] hover:border-[var(--hairline-strong)] hover:bg-[var(--danger-tint)] hover:text-[var(--danger)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50";
