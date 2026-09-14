"use client";

import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { motion, AnimatePresence } from "motion/react";
import {
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  Loader2,
  ShieldCheck,
  Activity,
  HardDrive,
} from "lucide-react";
import { LanguageSwitcher } from "@/components/app-shell/language-switcher";
import { NetqmonLogo, NetqmonBrandText } from "@/components/brand/logo";
import { NetworkTrafficIllustration } from "@/components/auth/network-traffic-illustration";

type AuthFormProps = { mode: "setup" | "login" };

export function AuthForm({ mode }: AuthFormProps) {
  const t = useTranslations("auth");
  const router = useRouter();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    fetch("/api/auth/status", { cache: "no-store" })
      .then((response) => response.json())
      .then((payload) => {
        const required = payload?.data?.setup_required;
        if (mode === "setup" && required === false) router.replace("/login");
        if (mode === "login" && required === true) router.replace("/setup");
      })
      .catch(() => setError(t("errors.cannotConnectCollector")));
  }, [mode, router, t]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const data = new FormData(event.currentTarget);
    try {
      const response = await fetch(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: data.get("username"),
          password: data.get("password"),
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload?.error?.message ?? t("errors.failed"));
        return;
      }
      router.replace("/netqmon");
      router.refresh();
    } catch {
      setError(t("errors.serviceUnavailable"));
    } finally {
      setPending(false);
    }
  }

  const setup = mode === "setup";

  return (
    <main className="auth-canvas fixed inset-0 flex items-center justify-center p-3 sm:p-5 lg:p-6 text-slate-100 bg-[#06090e] overflow-y-auto lg:overflow-hidden select-none">
      {/* Background ambient lighting effects */}
      <div className="pointer-events-none absolute -top-24 left-1/4 h-80 w-80 rounded-full bg-blue-600/10 blur-[100px]" />
      <div className="pointer-events-none absolute -bottom-24 right-1/4 h-80 w-80 rounded-full bg-cyan-600/10 blur-[100px]" />

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: "easeOut" }}
        className="mx-auto my-auto grid w-full max-w-5xl overflow-hidden rounded-2xl sm:rounded-3xl border border-white/10 bg-slate-950/80 shadow-2xl shadow-black/90 backdrop-blur-2xl lg:grid-cols-[1.12fr_0.88fr]"
      >
        {/* Left Side: Brand, Network Traffic Visualization, Value Props */}
        <section className="relative hidden flex-col justify-between border-r border-white/10 p-6 lg:p-7 lg:flex">
          {/* Top Status & Brand Header */}
          <div className="relative z-10 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <NetqmonLogo size={30} />
              <NetqmonBrandText className="text-xl" />
            </div>
            <div className="flex items-center gap-2 rounded-full border border-blue-500/20 bg-blue-500/10 px-3 py-1 font-mono text-[11px] font-medium text-blue-400">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </span>
              <span>{t("nodeTitle")}</span>
            </div>
          </div>

          {/* Center: Title & Dynamic Traffic Flow Illustration */}
          <div className="relative z-10 my-auto py-2">
            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl lg:text-[32px] lg:leading-[1.2] whitespace-pre-line">
              {t("heroTitle")}
            </h1>
            <p className="mt-2 max-w-md text-xs sm:text-sm leading-relaxed text-slate-400">
              {t("heroSubtitle")}
            </p>

            {/* Dynamic Network Traffic Illustration */}
            <div className="mt-4 flex w-full justify-center">
              <NetworkTrafficIllustration className="w-full" />
            </div>
          </div>

          {/* Bottom: Feature Badges */}
          <div className="relative z-10 grid grid-cols-3 gap-2.5 border-t border-white/5 pt-3.5 font-mono text-[11px]">
            <div className="flex items-center gap-2 rounded-lg bg-white/[0.02] p-2 border border-white/5">
              <HardDrive className="size-4 text-sky-400 shrink-0" />
              <div>
                <span className="block text-[10px] text-slate-500 uppercase">
                  01
                </span>
                <span className="text-slate-300 font-medium text-[11px]">
                  {t("badge01")}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-white/[0.02] p-2 border border-white/5">
              <Activity className="size-4 text-emerald-400 shrink-0" />
              <div>
                <span className="block text-[10px] text-slate-500 uppercase">
                  02
                </span>
                <span className="text-slate-300 font-medium text-[11px]">
                  {t("badge02")}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-white/[0.02] p-2 border border-white/5">
              <ShieldCheck className="size-4 text-cyan-400 shrink-0" />
              <div>
                <span className="block text-[10px] text-slate-500 uppercase">
                  03
                </span>
                <span className="text-slate-300 font-medium text-[11px]">
                  {t("badge03")}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Right Side: Auth Form Console */}
        <section className="relative flex flex-col justify-between p-6 sm:p-8 lg:p-8">
          {/* Top Bar with Language Switcher */}
          <div className="flex items-center justify-between lg:justify-end">
            <div className="flex items-center gap-2.5 lg:hidden">
              <NetqmonLogo size={26} />
              <NetqmonBrandText className="text-lg" />
            </div>
            <div className="rounded-full border border-white/10 bg-slate-900/60 px-3 py-1 backdrop-blur">
              <LanguageSwitcher variant="auth" />
            </div>
          </div>

          {/* Form Container */}
          <div className="my-auto w-full max-w-sm mx-auto py-3">
            <div className="mb-4 flex size-11 items-center justify-center rounded-2xl border border-blue-500/30 bg-gradient-to-br from-blue-500/20 to-sky-500/10 text-sky-400 shadow-inner shadow-blue-500/20">
              <LockKeyhole className="size-5" />
            </div>

            <span className="font-mono text-[11px] font-semibold tracking-wider text-sky-400 uppercase">
              {setup ? t("setupStep") : t("loginStep")}
            </span>

            {/* Heading required for Playwright E2E */}
            <h2 className="mt-1.5 text-xl font-bold tracking-tight text-white sm:text-2xl">
              {setup ? t("createAdmin") : t("enterConsole")}
            </h2>

            <p className="mt-1.5 text-xs sm:text-sm leading-relaxed text-slate-400">
              {setup ? t("setupDesc") : t("loginDesc")}
            </p>

            <form className="mt-6 space-y-3.5" onSubmit={submit}>
              <div>
                <label
                  htmlFor="username"
                  className="block text-xs font-medium text-slate-300"
                >
                  {t("username")}
                </label>
                <input
                  id="username"
                  name="username"
                  autoComplete="username"
                  className="auth-input mt-1.5"
                  minLength={3}
                  maxLength={32}
                  pattern="[A-Za-z0-9._-]+"
                  required
                  placeholder="admin"
                />
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-xs font-medium text-slate-300"
                >
                  {t("password")}
                </label>
                <div className="relative mt-1.5">
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete={setup ? "new-password" : "current-password"}
                    className="auth-input pr-10"
                    minLength={setup ? 12 : 1}
                    maxLength={128}
                    required
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    className="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-200 focus:outline-none transition-colors cursor-pointer"
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                  >
                    {showPassword ? (
                      <EyeOff className="size-4" />
                    ) : (
                      <Eye className="size-4" />
                    )}
                  </button>
                </div>
              </div>

              <AnimatePresence>
                {error && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-xs leading-5 text-red-300"
                    role="alert"
                  >
                    {error}
                  </motion.div>
                )}
              </AnimatePresence>

              <button
                type="submit"
                disabled={pending}
                className="group relative mt-2 flex h-10 w-full items-center justify-center gap-2 overflow-hidden rounded-lg bg-gradient-to-r from-blue-600 via-blue-500 to-sky-500 text-sm font-semibold text-white shadow-lg shadow-blue-600/30 transition-all hover:shadow-blue-600/50 hover:brightness-110 active:scale-[0.99] cursor-pointer disabled:cursor-wait disabled:opacity-60"
              >
                {pending ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    <span>{t("establishingSession")}</span>
                  </>
                ) : (
                  <>
                    <span>{setup ? t("setupButton") : t("loginButton")}</span>
                    <ArrowRight className="size-4 transition-transform group-hover:translate-x-1" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-5 flex items-center justify-center gap-1.5 font-mono text-[11px] text-slate-500 text-center">
              <ShieldCheck className="size-3.5 text-emerald-400 shrink-0" />
              <span>{t("sessionFooter")}</span>
            </div>
          </div>

          {/* Bottom subtle note on small screens */}
          <div className="lg:hidden text-center text-[10px] font-mono text-slate-500">
            netqmon · router native telemetry
          </div>
        </section>
      </motion.div>
    </main>
  );
}
