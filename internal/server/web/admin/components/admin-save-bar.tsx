import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  adminDialogCancelClass,
  adminDialogDangerActionClass,
  adminDialogContentClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
} from "@/lib/admin-ui";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// =====================================================================
// A-12 浮动保存条（evolution_log §6 A-12；第 4 轮 0.1.2「条内不放放弃按钮」
// 的裁定已被第 5 轮 A-03 作废）——「草稿 + 保存」设置页（基础设置 / 通知告警 /
// 分组管理 / 探测设置 / 运维助手）的统一交互，替代页头的「保存更改」按钮与
// 「有未保存的修改」徽标。只改呈现位置：onClick、禁用条件（isBusy、
// settingsLoaded…）与确认弹窗完全复用页面现有逻辑。
//
// - 由使用方在 isDirty 为真时条件渲染（isDirty 为假时页头不显示保存按钮，0.1.2）；
// - 玻璃胶囊：--mat-bar-bg + --blur-regular + 1px --hairline 边 + 上沿内高光 + --shadow-3，
//   --r-full、高 52px、内边距 8px 8px 8px 20px；
// - 左侧 8px 琥珀点（--warn）+「有未保存的修改」13px/500；
// - A-03：「保存更改」左侧新增次级文字按钮「放弃修改」（--label-2，hover --label-1，
//   高度与主按钮一致），saving 时禁用；点击弹出二次确认（D-07，不做撤销），
//   复用 App.tsx 离开确认弹窗的组件与样式，确认后调用 onDiscard 并 toast「已放弃修改」；
// - 右侧「保存更改」主按钮（A-05 规格），saving 时显示「保存中…」并禁用；
// - position: sticky; bottom: 16px；手机（<sm）宽 calc(100% - 24px)、
//   bottom: calc(12px + env(safe-area-inset-bottom))（解决 E-05）；
// - 出现：translateY(24px)→0 + opacity，--dur-4 / --ease-spring（tw-animate-css
//   的 animate-in；prefers-reduced-motion 下由 index.css 的全局规则关闭）。
// =====================================================================
type AdminSaveBarProps = {
  // 「保存更改」点击处理：与原页头按钮完全相同（直接保存或打开确认弹窗）。
  onSave: () => void;
  // A-03「放弃修改」确认后的处理：调用页面的 discard（回到服务端当前配置）
  // 并清空该页的校验错误 / 侧栏红点。
  onDiscard: () => void;
  // 保存进行中：按钮显示「保存中…」并禁用。
  saving?: boolean;
  // 透传页面原有禁用条件（isBusy、settingsLoaded 等）。
  disabled?: boolean;
  saveLabel?: string;
  savingLabel?: string;
  className?: string;
};

export function AdminSaveBar({
  onSave,
  onDiscard,
  saving = false,
  disabled = false,
  saveLabel = "保存更改",
  savingLabel = "保存中…",
  className,
}: AdminSaveBarProps) {
  return (
    <div
      className={cn(
        "sticky bottom-4 z-30 mx-auto flex h-[52px] w-fit items-center justify-between gap-4 rounded-[var(--r-full)] border border-[var(--hairline)] bg-[var(--mat-bar-bg)] pl-5 pr-2 shadow-[inset_0_1px_0_var(--glass-edge),var(--shadow-3)] [-webkit-backdrop-filter:var(--blur-regular)] [backdrop-filter:var(--blur-regular)]",
        "animate-in fade-in slide-in-from-bottom-6 [animation-duration:var(--dur-4)] [animation-timing-function:var(--ease-spring)]",
        "max-sm:w-[calc(100%-24px)] max-sm:bottom-[calc(12px+env(safe-area-inset-bottom))]",
        className,
      )}
    >
      <span className="flex min-w-0 items-center gap-2 whitespace-nowrap text-[13px] font-medium text-[var(--label-1)]">
        <span aria-hidden="true" className="size-2 shrink-0 rounded-full bg-[var(--warn)]" />
        有未保存的修改
      </span>
      <div className="flex shrink-0 items-center gap-2">
        {/* A-03 / D-07：次级文字按钮，高度与主按钮一致（h-9）；点击走二次确认。 */}
        <AlertDialog>
          <AlertDialogTrigger
            render={
              <Button
                type="button"
                variant={null}
                disabled={saving}
                className="inline-flex h-9 items-center rounded-full px-4 text-sm font-medium text-[var(--label-2)] outline-none transition-colors duration-[var(--dur-2)] hover:bg-[var(--mat-control-bg)] hover:text-[var(--label-1)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--accent-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50"
              />
            }
          >
            放弃修改
          </AlertDialogTrigger>
          <AlertDialogContent className={adminDialogContentClass}>
            <AlertDialogHeader className={adminDialogHeaderClass}>
              <AlertDialogTitle>放弃未保存的修改？</AlertDialogTitle>
              <AlertDialogDescription>
                本页所有未保存的修改将丢失，恢复为当前已保存的配置。
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className={adminDialogFooterClass}>
              <AlertDialogCancel className={`${adminDialogCancelClass} ${adminOutlineButtonClass}`}>
                继续编辑
              </AlertDialogCancel>
              <AlertDialogAction
                className={adminDialogDangerActionClass}
                onClick={() => {
                  onDiscard();
                  toast.success("已放弃修改");
                }}
              >
                放弃修改
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
        <Button className={adminPrimaryButtonClass} onClick={onSave} disabled={disabled || saving}>
          {saving ? savingLabel : saveLabel}
        </Button>
      </div>
    </div>
  );
}
