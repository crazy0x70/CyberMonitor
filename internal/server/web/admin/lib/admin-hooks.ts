import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { AdminApiError } from "@/lib/admin-api";
import { getErrorMessage } from "@/lib/admin-format";

export const draftSignature = (serializable: unknown): string => JSON.stringify(serializable);

export const sourceSignature = <T>(make: (src: T) => unknown, src: T): string =>
  JSON.stringify(make(src));

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

export function useDirtyNotification(
  onDirtyChange: ((dirty: boolean) => void) | undefined,
  isDirty: boolean,
) {
  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
}

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

  const absorbSourceSignature = useCallback((next: string) => {
    setSourceSignature(next);
  }, []);
  return [sourceSignature, absorbSourceSignature];
}
