import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, Lock, Moon, Sun, User } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  adminInputClass,
  adminPrimaryButtonClass,
  adminSurfaceCardClass,
  adminThemeToggleButtonClass,
} from "@/lib/admin-ui";
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
  onToggleTheme: () => void;
  errorMessage?: string;
  errorType?: "none" | "invalid" | "expired" | "locked";
  homeSubtitle?: string;
  homeTitle?: string;
  retryAfterSec?: number;
  theme: ThemeMode;
  turnstileSiteKey?: string;
}

export default function Login({
  onLogin,
  onToggleTheme,
  errorMessage = "",
  errorType = "none",
  homeSubtitle = "主机监控",
  homeTitle = "CyberMonitor",
  retryAfterSec = 0,
  theme,
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
  const isDark = theme === "dark";

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
    if (!turnstileSiteKey) {
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
          setTurnstileError(error instanceof Error ? error.message : "Turnstile 加载失败");
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
  }, [theme, turnstileSiteKey]);

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

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
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

  return (
    <div className="relative flex min-h-screen items-center justify-center px-4 py-10">
      <div className="absolute right-4 top-4 sm:right-6 sm:top-6">
        <Button
          aria-label={isDark ? "切换到浅色模式" : "切换到深色模式"}
          className={adminThemeToggleButtonClass}
          size="icon"
          variant="outline"
          onClick={onToggleTheme}
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
      <div className="w-full max-w-md space-y-10 animate-in fade-in slide-in-from-bottom-8 duration-1000 ease-out">
        <div className="flex flex-col items-center text-center">
          <h1 className="text-5xl font-black tracking-tighter text-slate-900 dark:text-slate-100 italic">
            {homeTitle}
          </h1>
          <p className="mt-4 text-base font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">
            {homeSubtitle}
          </p>
        </div>

        <Card className={cn("overflow-hidden border-none shadow-[0_48px_96px_-48px_rgba(15,23,42,0.3)] dark:shadow-[0_48px_96px_-48px_rgba(2,8,23,0.8)]", adminSurfaceCardClass)}>
          <form onSubmit={handleSubmit}>
            <CardHeader className="border-b border-slate-200/40 bg-white/40 px-8 py-8 text-center dark:border-slate-800/40 dark:bg-slate-950/40">
              <CardTitle className="text-2xl font-black tracking-tight">欢迎回来</CardTitle>
              <CardDescription className="mt-2 text-sm font-medium text-slate-500">验证管理员凭证以继续</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 px-8 pt-8 pb-6">
              {errorType === "invalid" && (
                <Alert variant="destructive" className="border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-100">
                  <AlertCircle className="h-4 w-4 text-rose-600 dark:text-rose-300" />
                  <AlertTitle className="text-rose-800 dark:text-rose-100">登录失败</AlertTitle>
                  <AlertDescription className="text-rose-700 dark:text-rose-200">
                    {errorMessage || "用户名或密码错误，请检查后重试。"}
                  </AlertDescription>
                </Alert>
              )}

              {errorType === "expired" && (
                <Alert className="border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100">
                  <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
                  <AlertTitle className="text-amber-800 dark:text-amber-100">登录已失效</AlertTitle>
                  <AlertDescription className="text-amber-700 dark:text-amber-200">
                    {errorMessage || "您的登录状态已过期或后台凭证已被修改，请重新登录。"}
                  </AlertDescription>
                </Alert>
              )}

              {errorType === "locked" && (
                <Alert variant="destructive" className="border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-100">
                  <Lock className="h-4 w-4 text-rose-600 dark:text-rose-300" />
                  <AlertTitle className="text-rose-800 dark:text-rose-100">账号已锁定</AlertTitle>
                  <AlertDescription className="text-rose-700 dark:text-rose-200">
                    {errorMessage || "连续登录失败次数过多，触发防爆破保护。"}
                    {lockTimeLeft > 0 ? (
                      <>
                        {" "}
                        请在{" "}
                        <strong className="font-mono">
                          {Math.floor(lockTimeLeft / 60)} 分 {(lockTimeLeft % 60).toString().padStart(2, "0")} 秒
                        </strong>{" "}
                        后重试。
                      </>
                    ) : null}
                  </AlertDescription>
                </Alert>
              )}

              <div className="space-y-2">
                <Label htmlFor="username">用户名</Label>
                <div className="relative">
                  <User className="absolute left-3.5 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="username"
                    autoComplete="username"
                    placeholder="admin"
                    className={cn(adminInputClass, "pl-10")}
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    disabled={errorType === "locked" && lockTimeLeft > 0}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">密码</Label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    className={cn(adminInputClass, "pl-10")}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    disabled={errorType === "locked" && lockTimeLeft > 0}
                  />
                </div>
              </div>

              {turnstileSiteKey ? (
                <div className="space-y-2">
                  <Label>人机验证</Label>
                  <div className="rounded-[1rem] border border-slate-200 bg-white/90 px-3 py-3 dark:border-slate-800 dark:bg-slate-950/90">
                    <div ref={turnstileContainerRef} />
                  </div>
                  {turnstileError ? (
                    <p className="text-sm text-rose-600 dark:text-rose-300">{turnstileError}</p>
                  ) : (
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      完成验证后再提交管理员凭证。
                    </p>
                  )}
                </div>
              ) : null}
            </CardContent>
            <CardFooter className="border-t border-slate-200/40 bg-white/40 px-8 py-6 dark:border-slate-800/40 dark:bg-slate-950/40">
              <Button
                type="submit"
                className={cn(adminPrimaryButtonClass, "h-12 w-full font-black tracking-tight shadow-xl shadow-sky-500/20 active:scale-95 transition-all duration-300")}
                disabled={submitting || (errorType === "locked" && lockTimeLeft > 0)}
              >
                {submitting ? "正在验证身份..." : "确 认 登 录"}
              </Button>
            </CardFooter>
          </form>
        </Card>
      </div>
    </div>
  );
}
