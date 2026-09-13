import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { AdminApiError } from "@/lib/admin-api";
import { getErrorMessage } from "@/lib/admin-format";

/**
 * 页面层 busy/try/catch/toast 样板的收敛点：busy 状态由调用点注入 setter
 * （页面 busy 多为派生值或实体级标记，不由 hook 持有），hook 只拥有
 * try/catch/toast 骨架。成功后依次执行 onSuccess；successToast 为函数时
 * 返回 falsy 表示不弹（如"删除成功但有历史错误"条件分支）；fixedErrorText
 * 为 true 时错误文案固定用 fallbackError（如剪贴板失败的浏览器原始报错
 * 对用户无可操作性）。失败不 rethrow，
 * 返回 undefined——401 由 apiFetch 集中处理后统一登出，页面无需感知。
 * App.tsx handler 层（有 rethrow + 401 特判语义）不适用本 hook。
 */
export function useAsyncAction() {
  return useCallback(
    async <T>(spec: {
      action: () => Promise<T>;
      fallbackError: string;
      fixedErrorText?: boolean;
      successToast?: string | ((data: T) => string | null | undefined);
      onSuccess?: (data: T) => void;
      setBusy?: (on: boolean) => void;
    }): Promise<T | undefined> => {
      const { action, fallbackError, fixedErrorText, successToast, onSuccess, setBusy } = spec;
      setBusy?.(true);
      try {
        const data = await action();
        if (typeof successToast === "function") {
          const message = successToast(data);
          if (message) {
            toast.success(message);
          }
        } else if (successToast) {
          toast.success(successToast);
        }
        onSuccess?.(data);
        return data;
      } catch (error) {
        // 401 已由登出流程展示过期提示，页面层不再重复弹错误。
        if (!(error instanceof AdminApiError && error.status === 401)) {
          const message = fixedErrorText ? fallbackError : getErrorMessage(error, fallbackError);
          toast.error(message);
        }
        return undefined;
      } finally {
        setBusy?.(false);
      }
    },
    [],
  );
}

/**
 * 通知父组件草稿 dirty 状态变化，并在卸载时归位。
 * 六个设置页逐字相同的两段 effect 的收敛点。
 */
export function useDirtyNotification(
  onDirtyChange: ((dirty: boolean) => void) | undefined,
  isDirty: boolean,
) {
  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
}

/**
 * settings 服务端签名与本地草稿的 reconcile：
 * - 草稿未变（签名一致）时吸收服务端更新（清 dirty）；
 * - 草稿有未保存修改时保留并 toast 提醒；
 * - 服务端无变化时按需重置草稿。
 *
 * 返回 [已吸收的 source 签名, absorb(next)]：前者供派生 dirty 的页面
 * （GroupManagement）比较，后者供保存成功路径推进到 canonical 签名。BasicSettings（adminPass 不入签名的特判）与
 * ServerManagement（按实体切换的结构变体）不适用本 hook，保留手写实现。
 */
export function useDraftReconcile(options: {
  draftSignature: string;
  nextSourceSignature: string;
  isBusy: boolean;
  resetDraft: () => void;
  warningText: string;
  onCleaned?: () => void;
}): [string, (next: string) => void] {
  const { draftSignature, nextSourceSignature, isBusy, warningText } = options;
  const [sourceSignature, setSourceSignature] = useState(nextSourceSignature);
  // dirty 一律派生自"已吸收签名 vs 草稿签名"：消除调用方各传一套语义
  // （用户编辑标志 vs 服务端差异）导致的分叉；回调经 ref 持最新引用，
  // 使 effect 依赖只剩签名/布尔，避免内联闭包引发每渲染重跑。
  const resetDraftRef = useRef(options.resetDraft);
  resetDraftRef.current = options.resetDraft;
  const onCleanedRef = useRef(options.onCleaned);
  onCleanedRef.current = options.onCleaned;

  useEffect(() => {
    const isDirty = sourceSignature !== draftSignature;
    if (isBusy) {
      return;
    }
    if (isDirty && draftSignature === nextSourceSignature) {
      setSourceSignature(nextSourceSignature);
      onCleanedRef.current?.();
      return;
    }
    if (nextSourceSignature === sourceSignature) {
      return;
    }
    if (isDirty) {
      setSourceSignature(nextSourceSignature);
      toast.warning(warningText);
      return;
    }
    resetDraftRef.current();
    setSourceSignature(nextSourceSignature);
    onCleanedRef.current?.();
  }, [draftSignature, isBusy, nextSourceSignature, sourceSignature, warningText]);

  // 供保存成功路径把 source 签名推到 canonical 值（等价于原 setSourceSignature）。
  const absorbSourceSignature = useCallback((next: string) => {
    setSourceSignature(next);
  }, []);
  return [sourceSignature, absorbSourceSignature];
}
