import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, Lock, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  adminFieldErrorClass,
  adminHelpTextClass,
  adminInputClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
} from "@/lib/admin-ui";
import { getErrorMessage } from "@/lib/admin-format";
import type { OAuthLoginProvider } from "@/lib/admin-types";
import { cn } from "@/lib/utils";

declare global {
  interface Window {
    turnstile?: {
      render: (
        container: HTMLElement,
        options: {
          sitekey: string;
          theme?: "light" | "dark";
          callback?: (token: string) => void;
          "expired-callback"?: () => void;
          "error-callback"?: () => void;
        },
      ) => string | number;
      reset: (widgetID?: string | number) => void;
      remove?: (widgetID?: string | number) => void;
    };
  }
}

const TURNSTILE_SCRIPT_ID = "cm-turnstile-script";
let turnstileScriptPromise: Promise<void> | null = null;

// A-20 第 3 条：顶部 56px Logo 方块，样式同侧栏品牌 Logo 规范（0.1.1：站点图标 <img>）。
// 登录页未接入 App.tsx 的 siteIcon 属性，从 boot payload 读取同一数据源（只读内存，不发请求）；
// 未配置自定义图标时回退内置图标（与 App.tsx 的 DEFAULT_SITE_ICON 保持一致）。
const DEFAULT_LOGIN_SITE_ICON =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%231f5dff'/%3E%3Cpath d='M18 40L28 24l8 10 10-14' fill='none' stroke='white' stroke-width='6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";

// 与 App.tsx 的 normalizePublicIconURL 同语义的本地校验（该函数未导出，本页不能改 App.tsx）
function normalizeLoginSiteIcon(value: string | undefined | null) {
  const raw = String(value || "").trim();
  if (!raw || raw.startsWith("//") || raw.includes("\\") || /[\u0000-\u001F\u007F]/.test(raw)) {
    return "";
  }
  try {
    const parsed = new URL(raw, window.location.href);
    return parsed.protocol === "http:" || parsed.protocol === "https" ? raw : "";
  } catch {
    return "";
  }
}

function loadTurnstileScript() {
  if (typeof window === "undefined") {
    return Promise.resolve();
  }
  if (window.turnstile) {
    return Promise.resolve();
  }
  if (turnstileScriptPromise) {
    return turnstileScriptPromise;
  }

  turnstileScriptPromise = new Promise<void>((resolve, reject) => {
    const existing = document.getElementById(TURNSTILE_SCRIPT_ID) as HTMLScriptElement | null;
    if (existing) {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("Turnstile 脚本加载失败")), {
        once: true,
      });
      return;
    }

    const script = document.createElement("script");
    script.id = TURNSTILE_SCRIPT_ID;
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Turnstile 脚本加载失败"));
    document.head.appendChild(script);
  }).catch((error) => {
    turnstileScriptPromise = null;
    throw error;
  });

  return turnstileScriptPromise;
}

type ThemeMode = "light" | "dark";

export interface LoginProps {
  onLogin: (username: string, password: string, turnstileToken?: string) => Promise<void>;
  onOAuthLogin?: (providerID: string) => void;
  errorMessage?: string;
  errorType?: "none" | "invalid" | "expired" | "locked";
  homeSubtitle?: string;
  homeTitle?: string;
  oauthProviders?: OAuthLoginProvider[];
  passwordLoginEnabled?: boolean;

  loginConfigLoaded?: boolean;
  retryAfterSec?: number;
  theme: ThemeMode;
  topControls?: ReactNode;
  turnstileSiteKey?: string;
}

export default function Login({
  onLogin,
  onOAuthLogin,
  errorMessage = "",
  errorType = "none",
  homeSubtitle = "主机监控",
  homeTitle = "CyberMonitor",
  oauthProviders = [],
  passwordLoginEnabled = true,
  loginConfigLoaded = true,
  retryAfterSec = 0,
  theme,
  topControls,
  turnstileSiteKey = "",
}: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [lockTimeLeft, setLockTimeLeft] = useState(retryAfterSec);
  const [turnstileToken, setTurnstileToken] = useState("");
  const [turnstileError, setTurnstileError] = useState("");
  const turnstileContainerRef = useRef<HTMLDivElement | null>(null);
  const turnstileWidgetIDRef = useRef<string | number | null>(null);

  useEffect(() => {
    setLockTimeLeft(retryAfterSec);
  }, [retryAfterSec]);

  useEffect(() => {
    if (errorType !== "locked" || lockTimeLeft <= 0) return;
    const timer = window.setTimeout(() => {
      setLockTimeLeft((current) => Math.max(current - 1, 0));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [errorType, lockTimeLeft]);

  useEffect(() => {
    if (!passwordLoginEnabled || !turnstileSiteKey) {
      setTurnstileToken("");
      setTurnstileError("");
      return;
    }

    let cancelled = false;

    const mountTurnstile = async () => {
      try {
        await loadTurnstileScript();
        if (cancelled || !window.turnstile || !turnstileContainerRef.current) {
          return;
        }

        turnstileContainerRef.current.innerHTML = "";
        turnstileWidgetIDRef.current = window.turnstile.render(turnstileContainerRef.current, {
          sitekey: turnstileSiteKey,
          theme,
          callback: (token) => {
            setTurnstileToken(token);
            setTurnstileError("");
          },
          "expired-callback": () => {
            setTurnstileToken("");
            setTurnstileError("人机验证已过期，请重新完成验证。");
          },
          "error-callback": () => {
            setTurnstileToken("");
            setTurnstileError("人机验证加载失败，请稍后重试。");
          },
        });
      } catch (error) {
        if (!cancelled) {
          setTurnstileToken("");
          setTurnstileError(getErrorMessage(error, "Turnstile 加载失败"));
        }
      }
    };

    void mountTurnstile();

    return () => {
      cancelled = true;
      if (turnstileWidgetIDRef.current != null) {
        window.turnstile?.remove?.(turnstileWidgetIDRef.current);
        turnstileWidgetIDRef.current = null;
      }
    };
  }, [passwordLoginEnabled, theme, turnstileSiteKey]);

  useEffect(() => {
    if (!turnstileSiteKey || errorType === "none") {
      return;
    }
    setTurnstileToken("");
    setTurnstileError("");
    if (turnstileWidgetIDRef.current != null) {
      window.turnstile?.reset(turnstileWidgetIDRef.current);
    }
  }, [errorMessage, errorType, turnstileSiteKey]);

  // A-20 第 5 条（0.1.2 裁定做 shake）：以已有错误状态为触发，错误信息变化时给卡片
  // 切换 class 重播 CSS 抖动动画（见 index.css .cm-login-card-shake）。
  // 纯展示逻辑：不改登录流程、不换 key（避免重挂载丢 Turnstile 挂载点），
  // 双 requestAnimationFrame 保证先移除再添加 class，动画得以重放。
  const [cardShaking, setCardShaking] = useState(false);
  const prevLoginErrorRef = useRef({ message: errorMessage, type: errorType });
  useEffect(() => {
    const prev = prevLoginErrorRef.current;
    if (prev.type === errorType && prev.message === errorMessage) {
      return;
    }
    prevLoginErrorRef.current = { message: errorMessage, type: errorType };
    if (errorType === "none") {
      return;
    }
    setCardShaking(false);
    let raf = 0;
    raf = requestAnimationFrame(() => {
      raf = requestAnimationFrame(() => setCardShaking(true));
    });
    const timer = window.setTimeout(() => setCardShaking(false), 400);
    return () => {
      cancelAnimationFrame(raf);
      window.clearTimeout(timer);
    };
  }, [errorMessage, errorType]);

  const siteIcon = useMemo(
    () =>
      typeof window === "undefined"
        ? ""
        : normalizeLoginSiteIcon(window.__CM_ADMIN_BOOT__?.settings?.site_icon),
    [],
  );

  // A-20 第 4 条：入场动画类（.cm-login-card-enter，见 index.css）在入场结束后移除，
  // 之后失败抖动切换 .cm-login-card-shake 时不会把 animation-name 变回入场动画重放
  const [cardEntered, setCardEntered] = useState(false);
  useEffect(() => {
    const timer = window.setTimeout(() => setCardEntered(true), 800);
    return () => window.clearTimeout(timer);
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!passwordLoginEnabled) {
      return;
    }
    if (turnstileSiteKey && !turnstileToken) {
      setTurnstileError("请先完成人机验证。");
      return;
    }
    setSubmitting(true);
    try {
      await onLogin(username.trim(), password, turnstileToken);
    } finally {
      setSubmitting(false);
    }
  };

  const labelClass = "text-[13px] font-medium text-[var(--label-2)]";

  return (
    // A-20：登录页外壳 —— 后台唯一允许动态背景的地方，流光画布见 index.css .cm-login-shell::before
    <div className="cm-login-shell relative flex min-h-screen items-center justify-center px-4 py-20 sm:py-16">
      {/* 右上角语言/主题按钮：topControls 由 App.tsx 传入，已按圆形玻璃按钮规格（A-03/A-02）渲染。
          地标：登录页不经过 App.tsx 外壳，页内需要自带 header + main 才能满足
          axe 的 landmark-one-main / region 规则（样式与原来的 div 完全一致）。 */}
      <header className="absolute right-4 top-4 z-20 flex items-center gap-2 sm:right-6 sm:top-4">
        {topControls}
      </header>
      {/* A-20 第 2 条：.glass + --mat-sheet-bg + --blur-thick + --shadow-4、--r-2xl、宽 380px、内边距 32px。
          入场动画（cm-login-card-enter）与失败抖动（cm-login-card-shake）见 index.css。
          用 <main> 而非 <div> 承载登录主体：这是页面唯一的主要内容区。 */}
      <main
        className={cn(
          "glass cm-login-card w-[380px] max-w-full space-y-8 rounded-[var(--r-2xl)] p-8",
          "[--mat-bg:var(--mat-sheet-bg)] [--mat-blur:var(--blur-thick)] [--mat-shadow:var(--shadow-4)]",
          !cardEntered && "cm-login-card-enter",
          cardShaking && "cm-login-card-shake",
        )}
      >
        <div className="flex flex-col items-center text-center">
          {/* 56px Logo 方块（同侧栏品牌 Logo 规范，0.1.1：站点图标 <img>），--shadow-2；
              入场延迟 80ms scale(.8)→1（--ease-bounce），见 index.css .cm-login-logo。
              装饰性图片：站点名已在下方 <h1>，alt 留空避免重复朗读 */}
          <span className="cm-login-logo flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-[16px] shadow-[var(--shadow-2)]">
            <img
              alt=""
              className="h-full w-full object-cover"
              src={siteIcon || DEFAULT_LOGIN_SITE_ICON}
              width={56}
              height={56}
              referrerPolicy="no-referrer"
            />
          </span>
          <h1 className="mt-5 text-[var(--label-1)] [font:var(--t-display)] tracking-[var(--t-display-ls)]">
            {homeTitle}
          </h1>
          <p className="mt-2 text-[15px] leading-relaxed text-[var(--label-2)]">{homeSubtitle}</p>
        </div>

        <div className="space-y-5">
          {oauthProviders.length > 0 ? (
            <div className="space-y-5">
              <div className="grid gap-2">
                {oauthProviders.map((provider) => {
                  return (
                    <Button
                      key={provider.id}
                      type="button"
                      variant="outline"
                      className={cn(adminOutlineButtonClass, "h-9 w-full min-w-0 justify-center gap-2 px-4 font-medium")}
                      disabled={errorType === "locked" && lockTimeLeft > 0}
                      onClick={() => onOAuthLogin?.(provider.id)}
                    >
                      <ShieldCheck className="h-4 w-4 shrink-0" />
                      {`使用 ${provider.display_name || provider.id} 登录`}
                    </Button>
                  );
                })}
              </div>
              {passwordLoginEnabled ? (
                <div className="flex items-center gap-3 text-xs font-medium text-[var(--label-3)]">
                  <span className="h-px flex-1 bg-[var(--separator)]" />
                  <span>或使用管理员密码</span>
                  <span className="h-px flex-1 bg-[var(--separator)]" />
                </div>
              ) : null}
            </div>
          ) : null}

          {loginConfigLoaded && !passwordLoginEnabled && oauthProviders.length === 0 ? (
            <Alert className="rounded-xl border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100">
              <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
              <AlertTitle className="text-amber-800 dark:text-amber-100">没有可用登录方式</AlertTitle>
              <AlertDescription className="text-amber-700 dark:text-amber-200">
                请联系管理员启用密码登录或 OAuth / OIDC 登录。
              </AlertDescription>
            </Alert>
          ) : null}

          {passwordLoginEnabled ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="username" className={labelClass}>
                  账号
                </Label>
                <Input
                  id="username"
                  autoComplete="username"
                  name="username"
                  className={cn(adminInputClass, "h-11")}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={errorType === "locked" && lockTimeLeft > 0}
                  spellCheck={false}
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password" className={labelClass}>
                  密码
                </Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  name="password"
                  className={cn(adminInputClass, "data-text h-11")}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={errorType === "locked" && lockTimeLeft > 0}
                />
              </div>

              {turnstileSiteKey ? (
                <div className="space-y-1.5">
                  <Label className={labelClass}>人机验证</Label>
                  <div className="overflow-hidden rounded-lg border border-[var(--separator)] bg-[var(--surface-1)] p-2 dark:bg-[var(--surface-2)]">
                    <div ref={turnstileContainerRef} />
                  </div>
                  {turnstileError ? (
                      <p className={adminFieldErrorClass} aria-live="polite">{turnstileError}</p>
                    ) : (
                      <p className={adminHelpTextClass}>
                        完成验证后再提交管理员凭证。
                      </p>
                    )}
                </div>
              ) : null}

              {/* A-20 第 5 条：错误文字出现在按钮上方（错误状态原样复用，只挪了呈现位置） */}
              {errorType === "invalid" && (
                <Alert variant="destructive" className="rounded-xl border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-100">
                  <AlertCircle className="h-4 w-4 text-rose-600 dark:text-rose-300" />
                  <AlertTitle className="text-rose-800 dark:text-rose-100">登录失败</AlertTitle>
                  <AlertDescription className="text-rose-700 dark:text-rose-200">
                    {errorMessage || "账号或密码错误，请检查后重试。"}
                  </AlertDescription>
                </Alert>
              )}

              {errorType === "expired" && (
                <Alert className="rounded-xl border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100">
                  <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
                  <AlertTitle className="text-amber-800 dark:text-amber-100">登录已失效</AlertTitle>
                  <AlertDescription className="text-amber-700 dark:text-amber-200">
                    {errorMessage || "您的登录状态已过期或后台凭证已被修改，请重新登录。"}
                  </AlertDescription>
                </Alert>
              )}

              {errorType === "locked" && (
                <Alert variant="destructive" className="rounded-xl border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-100">
                  <Lock className="h-4 w-4 text-rose-600 dark:text-rose-300" />
                  <AlertTitle className="text-rose-800 dark:text-rose-100">账号已锁定</AlertTitle>
                  <AlertDescription className="text-rose-700 dark:text-rose-200">
                    {errorMessage || "连续登录失败次数过多，触发防爆破保护。"}
                    {lockTimeLeft > 0 ? (
                      <span>{` 请在 ${Math.floor(lockTimeLeft / 60)} 分 ${(lockTimeLeft % 60).toString().padStart(2, "0")} 秒后重试。`}</span>
                    ) : null}
                  </AlertDescription>
                </Alert>
              )}

              <Button
                type="submit"
                className={cn(
                  adminPrimaryButtonClass,
                  "h-11 w-full font-medium tracking-tight",
                )}
                disabled={submitting || (errorType === "locked" && lockTimeLeft > 0)}
              >
                {submitting ? "正在验证身份…" : "确认登录"}
              </Button>
            </form>
          ) : null}
        </div>
      </main>
    </div>
  );
}
