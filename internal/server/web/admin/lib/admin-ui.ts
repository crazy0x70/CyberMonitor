
export const adminPageShellClass =
  "mx-auto w-full max-w-[1200px] space-y-12 text-slate-900 dark:text-neutral-100";

export const adminPageHeaderClass =
  "flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between";

export const adminPageTitleClass =
  "text-[28px] font-semibold leading-tight tracking-[-0.02em] text-slate-900 dark:text-neutral-100";

export const adminPageActionsClass = "flex flex-wrap items-center gap-2";

export const adminSectionHeaderClass =
  "flex flex-wrap items-center justify-between gap-x-4 gap-y-2 pb-4";

export const adminMutedTextClass = "text-slate-500 dark:text-neutral-400";

export const adminDirtyBadgeClass =
  "rounded-full border border-amber-200 bg-amber-50/80 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200";

export const adminSuccessBadgeClass =
  "bg-emerald-100/80 text-emerald-700 hover:bg-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:hover:bg-emerald-900";

export const adminDangerBadgeClass =
  "bg-rose-100/80 text-rose-700 hover:bg-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:hover:bg-rose-900";

export const adminWarningBadgeClass =
  "border-amber-200 bg-amber-50/80 text-amber-700 hover:bg-amber-100 dark:border-amber-900 dark:bg-amber-950/80 dark:text-amber-300 dark:hover:bg-amber-900";

export const adminNeutralBadgeClass =
  "bg-slate-100/80 text-slate-700 hover:bg-slate-200 dark:bg-neutral-800/80 dark:text-neutral-300 dark:hover:bg-neutral-700";

export const adminPrimaryButtonClass =
  "inline-flex h-9 min-w-[110px] items-center justify-center rounded-full border border-transparent bg-slate-900 px-4 text-sm font-medium text-white outline-none transition-[background-color] duration-150 ease-out hover:bg-slate-800 focus-visible:border-[var(--primary-border)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] active:bg-slate-950 disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white";

export const adminOutlineButtonClass =
  "h-9 rounded-full border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-slate-700 backdrop-blur-md outline-none transition-[border-color,background-color,color,opacity] duration-150 ease-out hover:border-[var(--primary-border)] hover:bg-[var(--cm-control-hover)] hover:text-primary focus-visible:border-[var(--primary-border)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] active:opacity-90 dark:text-neutral-200";

export const adminActionButtonClass =
  `${adminOutlineButtonClass} inline-flex min-w-[110px] items-center justify-center px-4`;

export const adminCompactActionButtonClass =
  `${adminOutlineButtonClass} inline-flex items-center justify-center gap-1 h-9 whitespace-nowrap px-4 text-xs font-medium leading-none`;

export const adminDangerOutlineButtonClass =
  "h-9 rounded-full border-rose-200/80 bg-rose-50/80 text-rose-600 backdrop-blur-sm transition-colors duration-150 hover:bg-rose-100 hover:text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300 dark:hover:bg-rose-900/60";

export const adminStatCardClass = "flex flex-col";

export const adminStatEyebrowClass =
  "text-xs font-medium text-slate-500 dark:text-neutral-400";

export const adminLoadingCardClass =
  "w-full max-w-md rounded-2xl border border-[var(--cm-panel-border)] bg-[var(--surface-1)] backdrop-blur-2xl";

export const adminLoadingCardContentClass =
  "flex items-center justify-center gap-4 py-8 text-sm font-medium text-slate-500 dark:text-neutral-400";

export const adminInputClass =
  "h-9 rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 text-sm text-slate-900 backdrop-blur-sm transition-[border-color,background-color,color,box-shadow] placeholder:text-slate-500 dark:placeholder:text-neutral-400 focus:border-[var(--primary)] focus:ring-2 focus:ring-[var(--primary-ring)] dark:text-neutral-50";

export const adminWideInputClass = `max-w-xl ${adminInputClass}`;

export const adminTextareaClass =
  "rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 py-2 text-sm leading-relaxed text-slate-700 backdrop-blur-sm transition-[border-color,background-color,color,box-shadow] placeholder:text-slate-500 dark:placeholder:text-neutral-400 focus:border-[var(--primary)] focus:ring-2 focus:ring-[var(--primary-ring)] dark:text-neutral-50";

export const adminSelectTriggerClass =
  "h-9 rounded-xl border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] px-4 text-sm text-slate-900 backdrop-blur-sm dark:text-neutral-50";

export const adminSelectContentClass =
  "rounded-xl border border-[var(--cm-control-border)] bg-[var(--surface-3)] text-slate-900 backdrop-blur-2xl dark:text-neutral-50";

export const adminDialogContentClass =
  "overflow-hidden rounded-[2rem] border-slate-200/60 bg-[var(--surface-3)] p-0 gap-0 dark:border-neutral-800/60 shadow-[var(--cm-elev-2)]";

export const adminDialogHeaderClass =
  "grid-rows-[auto] space-y-2 border-b-0 px-8 pt-4 pb-0 text-left";

export const adminDialogFooterClass =
  "m-0 border-t-0 bg-transparent px-8 pt-4 pb-4 dark:bg-transparent";

export const adminDialogCancelClass =
  "h-9 rounded-full border-slate-300 bg-white px-4 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-neutral-700 dark:bg-[var(--surface-2)] dark:text-neutral-300 dark:hover:bg-neutral-800";

export const adminDialogDangerActionClass =
  "h-9 rounded-full bg-rose-600 px-4 text-sm font-medium text-white hover:bg-rose-700 dark:bg-rose-500 dark:hover:bg-rose-400";

export const adminCodeBlockPanelClass =
  "rounded-[1.5rem] border border-slate-200 bg-slate-50/50 p-4 data-text text-[12px] leading-relaxed text-slate-800 dark:border-neutral-800 dark:bg-[var(--surface-2)] dark:text-neutral-200";

export const adminSidebarNavItemClass =
  "group relative flex min-h-9 w-full items-center gap-2.5 rounded-lg px-3 text-[13px] font-medium text-slate-600 outline-none transition-colors duration-150 hover:bg-[var(--cm-control-hover)] hover:text-slate-900 focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:text-neutral-300 dark:hover:text-neutral-100";

export const adminSidebarNavLabelClass = "flex min-w-0 items-center gap-2";

export const adminSidebarIconButtonClass =
  "h-9 w-9 rounded-full border border-[var(--cm-sidebar-border)] bg-[var(--cm-control-bg)] text-sidebar-foreground backdrop-blur-md outline-none transition-[border-color,background-color,color] duration-150 hover:border-[var(--primary-border)] hover:bg-[var(--cm-control-hover)] focus-visible:border-[var(--primary-border)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]";

export const adminThemeToggleButtonClass =
  "h-9 w-10 rounded-full border border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-slate-600 backdrop-blur-md outline-none transition-[border-color,background-color,color] duration-150 hover:border-[var(--primary-border)] hover:bg-[var(--cm-control-hover)] hover:text-primary focus-visible:border-[var(--primary-border)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:text-neutral-300";

export const adminSidebarSecondaryButtonClass =
  "w-full justify-start rounded-lg px-3 py-2.5 text-[13px] font-medium text-slate-600 outline-none transition-colors hover:bg-[var(--cm-control-hover)] hover:text-slate-900 focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:text-neutral-300 dark:hover:text-neutral-100";

export const adminSubtleOutlineBadgeClass =
  "border-slate-200/80 text-slate-500 dark:border-neutral-700/80 dark:text-neutral-400";

export const adminDangerIconButtonClass =
  "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-rose-100 bg-rose-50/80 text-rose-500 transition-[border-color,background-color,color] duration-150 hover:border-rose-300 hover:bg-rose-100 hover:text-rose-600 active:opacity-90 dark:border-rose-900/40 dark:bg-rose-950/40 dark:text-rose-400 dark:hover:bg-rose-900/60";
