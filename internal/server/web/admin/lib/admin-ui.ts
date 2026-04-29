export const adminPageShellClass =
  "mx-auto w-full max-w-[1200px] space-y-6 text-slate-900 animate-in fade-in slide-in-from-bottom-4 duration-700 dark:text-slate-100";

export const adminPageHeaderClass =
  "flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between px-1";

export const adminPageTitleClass =
  "text-3xl font-black tracking-tighter text-slate-900 dark:text-slate-100";

export const adminPageLeadClass =
  "mt-2 max-w-3xl text-sm leading-relaxed text-slate-500 dark:text-slate-400";

export const adminPageActionsClass = "flex flex-wrap items-center gap-3";

export const adminSurfaceCardClass =
  "overflow-hidden rounded-[1.75rem] border border-[var(--cm-panel-border)] bg-[var(--cm-panel-bg)] backdrop-blur-xl shadow-[var(--cm-panel-shadow)] transition-[box-shadow,border-color,background-color] hover:shadow-[0_32px_72px_-36px_rgba(15,23,42,0.18)] dark:hover:shadow-[0_32px_72px_-36px_rgba(0,0,0,0.58)]";

export const adminSurfaceMutedClass =
  "border border-[var(--cm-control-border)] bg-[var(--cm-muted-surface)] backdrop-blur-md";

export const adminSectionHeaderClass =
  "border-b border-[var(--cm-panel-border)] bg-[var(--cm-panel-header-bg)] px-6 py-4";

export const adminInsetCardClass =
  "rounded-[1.25rem] border border-[var(--cm-control-border)] bg-[var(--cm-muted-surface)] backdrop-blur-sm";

export const adminNotePanelClass = `${adminInsetCardClass} p-4`;

export const adminMutedTextClass = "text-slate-500 dark:text-slate-400";

export const adminFieldHintClass = "text-xs leading-relaxed text-slate-500 dark:text-slate-400";

export const adminDirtyBadgeClass =
  "rounded-full border border-amber-200 bg-amber-50/80 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-amber-700 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200";

export const adminSuccessBadgeClass =
  "bg-emerald-100/80 text-emerald-700 hover:bg-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:hover:bg-emerald-900";

export const adminDangerBadgeClass =
  "bg-rose-100/80 text-rose-700 hover:bg-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:hover:bg-rose-900";

export const adminWarningBadgeClass =
  "border-amber-200 bg-amber-50/80 text-amber-700 hover:bg-amber-100 dark:border-amber-900 dark:bg-amber-950/80 dark:text-amber-300 dark:hover:bg-amber-900";

export const adminNeutralBadgeClass =
  "bg-slate-100/80 text-slate-700 hover:bg-slate-200 dark:bg-slate-800/80 dark:text-slate-300 dark:hover:bg-slate-700";

export const adminInfoBadgeClass =
  "bg-sky-100/80 text-sky-700 hover:bg-sky-200 dark:bg-sky-950/80 dark:text-sky-300 dark:hover:bg-sky-900";

export const adminAccentBadgeClass =
  "bg-indigo-100/80 text-indigo-700 hover:bg-indigo-200 dark:bg-indigo-950/80 dark:text-indigo-300 dark:hover:bg-indigo-900";

export const adminPrimaryButtonClass =
  "inline-flex h-11 min-w-[110px] items-center justify-center rounded-full border border-transparent bg-[#1f5dff] px-5 text-sm font-bold text-white shadow-[0_18px_36px_-10px_rgba(31,93,255,0.38)] outline-none transition-[background-color,box-shadow,transform,opacity] hover:scale-[1.02] hover:bg-[#2554dd] focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 active:scale-[0.98] disabled:scale-100 disabled:opacity-50 dark:bg-[#3b82f6] dark:hover:bg-[#60a5fa] dark:focus-visible:border-sky-700";

export const adminOutlineButtonClass =
  "h-11 rounded-full border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-slate-700 shadow-sm backdrop-blur-md outline-none transition-[border-color,background-color,color,transform,opacity] hover:border-sky-300 hover:bg-[var(--cm-control-hover)] hover:text-sky-700 focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 active:scale-[0.98] dark:text-slate-200 dark:hover:border-sky-700 dark:hover:text-sky-300 dark:focus-visible:border-sky-700";

export const adminActionButtonClass =
  `${adminOutlineButtonClass} inline-flex min-w-[110px] items-center justify-center px-5`;

export const adminCompactActionButtonClass =
  `${adminOutlineButtonClass} inline-flex items-center justify-center gap-1.5 h-9 px-4 text-xs font-bold`;

export const adminDangerOutlineButtonClass =
  "h-11 rounded-full border-rose-200/80 bg-rose-50/80 text-rose-600 shadow-none backdrop-blur-sm hover:bg-rose-100 hover:text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300 dark:hover:bg-rose-900/60";

export const adminPanelHeaderClass = adminSectionHeaderClass;

export const adminDangerPanelHeaderClass =
  "border-b border-rose-200/60 bg-rose-50/40 dark:border-rose-900/60 dark:bg-rose-950/40";

export const adminPanelFooterClass =
  "border-t border-slate-200/60 bg-slate-50/60 px-6 py-4 dark:border-slate-800/60 dark:bg-slate-950/60";

export const adminStatCardClass =
  "flex h-full flex-col justify-between overflow-hidden rounded-[1.75rem] border border-slate-200/60 shadow-none transition-[transform,border-color,background-color] hover:translate-y-[-2px]";

export const adminStatCardHeaderClass =
  "flex flex-row items-start justify-between space-y-0 p-6 pb-3";

export const adminStatEyebrowClass =
  "text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400 dark:text-slate-500";

export const adminStatDescriptionClass =
  "px-6 pb-6 text-xs leading-relaxed text-slate-500 dark:text-slate-400";

export const adminStatSurfaceClassByTone = {
  neutral: "border-slate-200/60 bg-white/80 dark:border-[rgba(148,163,184,0.12)] dark:bg-slate-900/40",
  success: "border-emerald-200/40 bg-white/80 dark:border-emerald-900/20 dark:bg-slate-900/40",
  danger: "border-rose-200/40 bg-white/80 dark:border-rose-900/20 dark:bg-slate-900/40",
  warning: "border-amber-200/40 bg-white/80 dark:border-amber-900/20 dark:bg-slate-900/40",
  info: "border-sky-200/40 bg-white/80 dark:border-sky-900/20 dark:bg-slate-900/40",
  accent: "border-indigo-200/40 bg-white/80 dark:border-indigo-900/20 dark:bg-slate-900/40",
} as const;

export const adminStatValueToneClassByTone = {
  neutral: "text-slate-900 dark:text-slate-50",
  success: "text-emerald-600 dark:text-emerald-400",
  danger: "text-rose-600 dark:text-rose-400",
  warning: "text-amber-600 dark:text-amber-400",
  info: "text-sky-600 dark:text-sky-400",
  accent: "text-indigo-600 dark:text-indigo-400",
} as const;

export const adminStatIconChipClass =
  "flex h-12 w-12 items-center justify-center rounded-2xl shadow-sm";

export const adminStatIconChipClassByTone = {
  neutral: "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900",
  success: "bg-emerald-500/10 text-emerald-600 dark:bg-emerald-400/10 dark:text-emerald-400",
  danger: "bg-rose-500/10 text-rose-600 dark:bg-rose-400/10 dark:text-rose-400",
  warning: "bg-amber-500/10 text-amber-600 dark:bg-amber-300/10 dark:text-amber-300",
  info: "bg-sky-500/10 text-sky-600 dark:bg-sky-400/10 dark:text-sky-400",
  accent: "bg-indigo-500/10 text-indigo-600 dark:bg-indigo-400/10 dark:text-indigo-400",
} as const;

export const adminOverviewCardClass = "overflow-hidden border border-slate-200/60 dark:border-slate-800/60";

export const adminLoadingCardClass = `${adminSurfaceCardClass} w-full max-w-md backdrop-blur-2xl`;

export const adminLoadingCardContentClass =
  "flex items-center justify-center gap-4 py-10 text-sm font-medium text-slate-500 dark:text-slate-400";

export const adminInputClass =
  "h-11 rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 text-sm text-slate-900 backdrop-blur-sm transition-[border-color,background-color,color,box-shadow] placeholder:text-slate-400 focus:border-sky-500 focus:ring-4 focus:ring-sky-500/10 dark:text-slate-50 dark:focus:border-sky-400 dark:focus:ring-sky-400/10";

export const adminWideInputClass = `max-w-xl ${adminInputClass}`;

export const adminCompactInputClass =
  `h-9 w-full min-w-[200px] max-w-sm rounded-lg ${adminInputClass}`;

export const adminTextareaClass =
  "rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 py-3 text-sm leading-relaxed text-slate-700 backdrop-blur-sm transition-[border-color,background-color,color,box-shadow] placeholder:text-slate-400 focus:border-sky-500 focus:ring-4 focus:ring-sky-500/10 dark:text-slate-50 dark:focus:border-sky-400 dark:focus:ring-sky-400/10";

export const adminSelectTriggerClass =
  "h-11 rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 text-sm text-slate-900 backdrop-blur-sm dark:text-slate-50";

export const adminSelectContentClass =
  "rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-panel-bg)] text-slate-900 backdrop-blur-2xl dark:text-slate-50";

export const adminDialogContentClass =
  "overflow-hidden rounded-[2rem] border-slate-200/60 bg-white/95 p-0 backdrop-blur-2xl dark:border-slate-800/60 dark:bg-slate-950/95 shadow-[0_48px_96px_-32px_rgba(15,23,42,0.4)]";

export const adminDialogHeaderClass =
  "space-y-2 border-b border-slate-200/60 px-8 py-5 text-left dark:border-slate-800/60";

export const adminDialogFooterClass =
  "border-t border-slate-200/60 bg-slate-50/40 px-8 py-4 dark:border-slate-800/60 dark:bg-slate-950/40";

export const adminDialogCancelClass =
  "h-11 rounded-full border-slate-300 bg-white px-6 text-sm font-bold text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800";

export const adminDialogDangerActionClass =
  "h-11 rounded-full bg-rose-600 px-6 text-sm font-bold text-white hover:bg-rose-700 shadow-lg shadow-rose-500/20 dark:bg-rose-500 dark:hover:bg-rose-400";

export const adminTabsListClass =
  "grid h-auto w-full grid-cols-2 border-b border-slate-200 bg-transparent p-0 shadow-none sm:grid-cols-3 dark:border-slate-800";

export const adminTabsTriggerClass =
  "rounded-none border-b-2 border-transparent px-1 py-3.5 text-[11px] font-black uppercase tracking-widest text-slate-400 transition-[border-color,color,background-color] data-[state=active]:border-sky-500 data-[state=active]:bg-transparent data-[state=active]:text-slate-900 dark:text-slate-500 dark:data-[state=active]:border-sky-400 dark:data-[state=active]:text-slate-50";

export const adminTableShellClass =
  "overflow-hidden rounded-[1.5rem] border border-slate-200/60 bg-white/40 dark:border-slate-800/60 dark:bg-slate-950/40";

export const adminInsetPanelClass =
  "rounded-[1.25rem] border border-slate-200/80 bg-white/50 p-5 dark:border-slate-800/80 dark:bg-slate-950/50";

export const adminInsetPanelCompactClass =
  "rounded-xl border border-slate-200 bg-white/50 p-4 text-xs dark:border-slate-800 dark:bg-slate-950/50";

export const adminInsetMutedPanelClass =
  "rounded-xl border border-slate-200 bg-slate-50/50 p-4 text-xs dark:border-slate-800 dark:bg-slate-950/50";

export const adminSectionIntroPanelClass =
  "rounded-[1.25rem] border border-slate-200/60 bg-slate-50/60 px-5 py-4 dark:border-slate-800/60 dark:bg-slate-950/60";

export const adminCodeValuePanelClass =
  "rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-3 font-mono text-xs text-slate-600 dark:border-slate-800/80 dark:bg-slate-950/80 dark:text-slate-300";

export const adminCodeBlockPanelClass =
  "rounded-[1.5rem] border border-slate-200 bg-slate-50/50 p-5 font-mono text-[12px] leading-relaxed text-slate-800 dark:border-slate-800 dark:bg-slate-950/50 dark:text-slate-200";

export const adminPreviewPanelClass =
  "rounded-[1.25rem] border border-slate-200/60 bg-slate-50/40 p-5 dark:border-slate-800/60 dark:bg-slate-950/40";

export const adminDetailCardClass =
  "overflow-hidden rounded-[1.5rem] border border-slate-200/60 bg-white/40 shadow-none dark:border-slate-800/60 dark:bg-slate-950/40";

export const adminDetailHeaderClass =
  "border-b border-slate-200/60 bg-slate-50/60 px-6 py-3.5 dark:border-slate-800/60 dark:bg-slate-900/60";

export const adminDetailGroupClass =
  "space-y-3 rounded-[1.25rem] border border-slate-200/40 bg-slate-50/40 p-4 dark:border-slate-800/40 dark:bg-slate-900/40";

export const adminDetailValuePanelClass =
  "rounded-xl border border-slate-200/60 bg-white/60 px-4 py-3 text-xs text-slate-500 dark:border-slate-700/60 dark:bg-slate-950/60 dark:text-slate-400";

export const adminDetailHintPanelClass =
  "rounded-xl border border-slate-200/40 bg-slate-50/40 px-4 py-3 text-xs text-slate-500 dark:border-slate-800/40 dark:bg-slate-900/40 dark:text-slate-400";

export const adminDetailWarningPanelClass =
  "rounded-[1.25rem] border border-amber-200/60 bg-amber-50/60 px-4 py-3 text-[13px] text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/40 dark:text-amber-200";

export const adminWorkspaceListClass = "space-y-4";

export const adminWorkspaceItemClass =
  "flex w-full flex-col gap-4 rounded-[1.75rem] border border-[var(--cm-panel-border)] bg-[var(--cm-panel-bg)] p-6 text-left shadow-[0_16px_32px_-24px_rgba(15,23,42,0.1)] transition-[border-color,background-color,box-shadow] hover:border-sky-300 hover:bg-[var(--cm-muted-surface)] hover:shadow-[0_24px_48px_-24px_rgba(15,23,42,0.14)] dark:hover:border-sky-700";

export const adminWorkspaceHeaderClass =
  "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between";

export const adminWorkspaceActionChipClass =
  "inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50/80 px-3.5 py-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 transition-[border-color,color,background-color] hover:border-sky-200 hover:text-sky-600 dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-400";

export const adminSelectionChipActiveClass =
  "rounded-full bg-slate-900 px-4 py-1.5 text-[11px] font-black uppercase tracking-widest text-white shadow-lg shadow-slate-900/20 dark:bg-slate-100 dark:text-slate-950 dark:shadow-white/10";

export const adminSelectionChipInactiveClass =
  "rounded-full border border-slate-200 bg-white/80 px-4 py-1.5 text-[11px] font-bold uppercase tracking-widest text-slate-600 transition-[border-color,color,background-color] hover:border-sky-300 hover:bg-slate-50 hover:text-sky-700 dark:border-slate-800 dark:bg-slate-950/80 dark:text-slate-300";

export const adminSidebarNavItemClass =
  "group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-2.5 rounded-xl border px-3.5 py-2.5 text-[13px] font-bold outline-none transition-[border-color,background-color,color,box-shadow] duration-300 focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 dark:focus-visible:border-sky-700";

export const adminSidebarNavLabelClass = "flex min-w-0 items-center gap-2";

export const adminSidebarLogoChipClass =
  "flex items-center justify-center rounded-[1.25rem] border border-[var(--cm-sidebar-border)] bg-[var(--cm-control-bg)] text-primary shadow-md transition-transform group-hover:scale-105";

export const adminSidebarChromeCardClass =
  "rounded-[1.75rem] border border-[var(--cm-sidebar-border)] bg-[var(--cm-sidebar-bg)] shadow-[var(--cm-panel-shadow)] backdrop-blur-2xl";

export const adminSidebarSectionCardClass = `${adminSidebarChromeCardClass} p-4`;

export const adminSidebarIconButtonClass =
  "h-9 w-9 rounded-full border border-[var(--cm-sidebar-border)] bg-[var(--cm-control-bg)] text-sidebar-foreground shadow-sm backdrop-blur-md outline-none transition-[border-color,background-color,color,transform] hover:border-sky-300 hover:bg-[var(--cm-control-hover)] focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 active:scale-95 dark:hover:border-sky-700 dark:focus-visible:border-sky-700";

export const adminThemeToggleButtonClass =
  "h-10 w-10 rounded-full border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-slate-600 shadow-sm backdrop-blur-md outline-none transition-[border-color,background-color,color,transform] hover:border-sky-300 hover:bg-[var(--cm-control-hover)] hover:text-sky-700 focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 active:scale-95 dark:text-slate-300 dark:hover:border-sky-700 dark:hover:text-sky-300 dark:focus-visible:border-sky-700";

export const adminSidebarStatusTileClass =
  "flex min-h-[96px] flex-col items-center justify-center gap-2 rounded-[1.25rem] border border-sidebar-border bg-white/80 px-4 py-4 text-center backdrop-blur-md dark:bg-slate-950/80";

export const adminSidebarSecondaryButtonClass =
  "w-full justify-start rounded-xl border border-[var(--cm-sidebar-border)] bg-transparent px-3.5 py-5 text-[13px] font-bold text-sidebar-foreground outline-none transition-[border-color,background-color,color] hover:border-sky-300 hover:bg-[var(--cm-control-bg)] hover:text-sky-700 focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 dark:hover:border-sky-700 dark:hover:text-sky-300 dark:focus-visible:border-sky-700";

export const adminSummaryRowClass =
  "flex flex-col items-start gap-3 rounded-[1.25rem] border border-slate-200/60 bg-white/40 p-3.5 transition-[border-color,background-color,box-shadow] hover:border-sky-200 sm:flex-row sm:items-center sm:justify-between dark:border-slate-800/60 dark:bg-slate-950/40 dark:hover:border-sky-900";

export const adminSummaryIconChipClass = "rounded-xl p-2.5 shadow-sm";

export const adminSummaryIconToneClassByTone = {
  success: "bg-emerald-50 text-emerald-600 dark:bg-emerald-900/20 dark:text-emerald-400",
  info: "bg-sky-50 text-sky-600 dark:bg-sky-900/20 dark:text-sky-400",
  neutral: "bg-slate-100 text-slate-600 dark:bg-slate-800/40 dark:text-slate-400",
} as const;

export const adminSummaryWarningRowClass =
  "flex flex-col items-start gap-3 rounded-[1.25rem] border border-amber-200/60 bg-amber-50/40 p-3.5 sm:flex-row sm:items-center sm:justify-between dark:border-amber-900/40 dark:bg-amber-950/40";

export const adminSummaryWarningIconChipClass =
  "rounded-xl bg-amber-100 p-2.5 text-amber-600 shadow-sm dark:bg-amber-900/40 dark:text-amber-300";

export const adminSummaryWarningTitleClass =
  "font-bold text-amber-900 dark:text-amber-100";

export const adminSummaryWarningTextClass =
  "mt-0.5 text-xs leading-relaxed text-amber-700/80 dark:text-amber-200/70";

export const adminWarningOutlineButtonClass =
  "h-9 rounded-full border border-amber-200 bg-white/80 text-amber-700 px-4 text-xs font-bold outline-none transition-[border-color,background-color,color] hover:bg-amber-50 focus-visible:border-amber-300 focus-visible:ring-2 focus-visible:ring-amber-300/60 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200 dark:hover:bg-amber-900 dark:focus-visible:border-amber-700";

export const adminQuickActionButtonClass =
  "inline-flex h-11 w-full items-center justify-start gap-3 rounded-xl border border-slate-200 bg-white/60 px-4 text-sm font-bold text-slate-800 outline-none transition-[border-color,background-color,color,transform] hover:border-sky-300 hover:bg-slate-50 hover:text-sky-700 focus-visible:border-sky-300 focus-visible:ring-2 focus-visible:ring-sky-400/60 active:scale-[0.98] dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-200 dark:hover:border-sky-700 dark:hover:text-sky-400 dark:focus-visible:border-sky-700";

export const adminWorkspaceMetaGridClass =
  "grid gap-3 text-xs text-slate-500 dark:text-slate-400 md:grid-cols-2 xl:grid-cols-4";

export const adminWorkspaceMetaCardClass =
  "rounded-xl border border-slate-200/60 bg-slate-50/40 px-4 py-3 dark:border-slate-800/60 dark:bg-slate-900/40";

export const adminWorkspaceMetaLabelClass =
  "text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-slate-500";

export const adminWorkspaceStackClass = "space-y-3";

export const adminWorkspaceNestedItemClass =
  "rounded-[1.25rem] border border-slate-200 bg-white/50 p-4 dark:border-slate-800 dark:bg-slate-900/50";

export const adminEmptyStateClass =
  "rounded-[2rem] border-2 border-dashed border-[var(--cm-panel-border)] bg-[var(--cm-muted-surface)] px-6 py-12 text-center";

export const adminInlineEmptyStateClass =
  "rounded-xl border border-dashed border-slate-200 bg-slate-50/40 px-4 py-6 text-center text-xs text-slate-400 dark:border-slate-800 dark:bg-slate-900/40";

export const adminSubtleOutlineBadgeClass =
  "border-slate-200/80 text-slate-500 dark:border-slate-700/80 dark:text-slate-400";

export const adminDangerIconButtonClass =
  "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-rose-100 bg-rose-50/80 text-rose-500 transition-[border-color,background-color,color,transform] hover:border-rose-300 hover:bg-rose-100 hover:text-rose-600 active:scale-90 dark:border-rose-900/40 dark:bg-rose-950/40 dark:text-rose-400 dark:hover:bg-rose-900/60";

export const adminInfoAlertClass =
  "rounded-xl border border-sky-100 bg-sky-50/60 p-4 text-sky-900 dark:border-sky-900/40 dark:bg-sky-950/40 dark:text-sky-100";

export const adminInfoAlertTitleClass = "font-bold text-sky-800 dark:text-sky-50";

export const adminInfoAlertDescriptionClass = "mt-1 text-xs leading-relaxed text-sky-700/90 dark:text-sky-200/80";

export const adminWarningAlertClass =
  "rounded-xl border border-amber-100 bg-amber-50/60 p-4 text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/40 dark:text-amber-100";

export const adminWarningAlertTitleClass = "font-bold text-amber-800 dark:text-amber-50";

export const adminWarningAlertDescriptionClass = "mt-1 text-xs leading-relaxed text-amber-700/90 dark:text-amber-200/80";

export const adminDangerAlertClass =
  "rounded-xl border border-rose-100 bg-rose-50/60 p-4 text-rose-900 dark:border-rose-900/40 dark:bg-rose-950/40 dark:text-rose-100";

export const adminDangerAlertTitleClass = "font-bold text-rose-800 dark:text-rose-50";

export const adminDangerAlertDescriptionClass = "mt-1 text-xs leading-relaxed text-rose-700/90 dark:text-rose-200/80";
