"use client";

import React, { useState } from "react";
import {
  Menu,
  Sun,
  Moon,
  Laptop,
  LogOut,
  User,
  Server,
  Loader2,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useTheme } from "@/components/theme-provider";
import { StatusBadge } from "@/components/network/status-badge";
import { LanguageSwitcher } from "@/components/app-shell/language-switcher";

interface HeaderProps {
  title?: string;
  subtitle?: string;
  gatewayName?: string;
  gatewayStatus?: "online" | "offline" | "degraded" | "loading";
  isLive?: boolean | "loading";
  username?: string;
  onMobileMenuToggle?: () => void;
  actions?: React.ReactNode;
}

export function Header({
  title = "Overview",
  subtitle,
  gatewayName = "OpenWrt Gateway",
  gatewayStatus = "online",
  isLive = true,
  username = "admin",
  onMobileMenuToggle,
  actions,
}: HeaderProps) {
  const t = useTranslations("common");
  const tA11y = useTranslations("accessibility.sidebar");
  const { theme, setTheme } = useTheme();
  const router = useRouter();
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  };

  const cycleTheme = () => {
    if (theme === "light") setTheme("dark");
    else if (theme === "dark") setTheme("system");
    else setTheme("light");
  };

  const getThemeIcon = () => {
    if (theme === "light") return <Sun className="size-4" />;
    if (theme === "dark") return <Moon className="size-4" />;
    return <Laptop className="size-4" />;
  };

  return (
    <header className="sticky top-0 z-10 flex h-[52px] w-full shrink-0 items-center justify-between border-b border-border bg-surface/95 px-4 lg:px-6 backdrop-blur-xs select-none">
      {/* Left: Mobile Menu Toggle & Title */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onMobileMenuToggle}
          className="md:hidden flex size-8 items-center justify-center rounded-md border border-border bg-surface-subtle text-foreground-secondary hover:bg-surface-hover hover:text-foreground cursor-pointer"
          aria-label={tA11y("open")}
        >
          <Menu className="size-4" />
        </button>

        <div className="flex items-baseline gap-2 truncate">
          <h1 className="text-sm font-semibold tracking-tight text-foreground truncate">
            {title}
          </h1>
          {subtitle && (
            <span className="hidden sm:inline text-xs text-foreground-muted truncate">
              {subtitle}
            </span>
          )}
        </div>
      </div>

      {/* Right: Status Indicators, Page Actions, Language Switcher, Theme Toggle, User Menu */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* Gateway Status Badge */}
        <div
          className="hidden md:flex items-center gap-1.5 px-2 py-1 rounded-md border border-border bg-surface-subtle text-xs text-foreground-secondary"
          title={
            gatewayStatus === "loading"
              ? t("status.loading")
              : `Connected to ${gatewayName}`
          }
        >
          <Server className="size-3.5 text-foreground-muted" />
          <span className="font-medium truncate max-w-[120px]">
            {gatewayName}
          </span>
          <StatusBadge
            status={gatewayStatus}
            className="h-4 px-1.5 text-[10px]"
          />
        </div>

        {/* Realtime Live Indicator */}
        <div className="flex items-center">
          {isLive === "loading" ? (
            <span
              className="inline-flex h-[22px] items-center gap-1.5 rounded-[5px] border border-border bg-surface-subtle px-2 text-[11px] font-medium text-foreground-muted"
              title="Connecting to Realtime Stream..."
            >
              <Loader2 className="size-2.5 animate-spin text-foreground-muted" />
              <span>{t("status.connecting")}</span>
            </span>
          ) : isLive ? (
            <span
              className="inline-flex h-[22px] items-center gap-1.5 rounded-[5px] border border-success/30 bg-success-soft px-2 text-[11px] font-medium text-success"
              title="Realtime SSE Stream Active"
            >
              <span className="size-1.5 rounded-full bg-success animate-pulse" />
              <span>{t("status.live")}</span>
            </span>
          ) : (
            <span
              className="inline-flex h-[22px] items-center gap-1.5 rounded-[5px] border border-warning/30 bg-warning-soft px-2 text-[11px] font-medium text-warning"
              title="Realtime Stream Delayed or Offline"
            >
              <span className="size-1.5 rounded-full bg-warning" />
              <span>{t("status.delayed")}</span>
            </span>
          )}
        </div>

        {/* Custom Header Actions Slot */}
        {actions && <div className="flex items-center gap-1.5">{actions}</div>}

        {/* Language Switcher */}
        <LanguageSwitcher variant="header" />

        {/* Theme Switcher Button */}
        <button
          onClick={cycleTheme}
          className="flex size-8 items-center justify-center rounded-md border border-border bg-surface text-foreground-secondary hover:bg-surface-hover hover:text-foreground transition-colors cursor-pointer"
          aria-label={t("theme.switchTheme", { theme })}
          title={t("theme.themeTitle", { theme })}
        >
          {getThemeIcon()}
        </button>

        {/* User Menu & Logout */}
        <div className="relative">
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className="flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-2 text-xs font-medium text-foreground hover:bg-surface-hover transition-colors cursor-pointer"
            aria-expanded={userMenuOpen}
            aria-haspopup="true"
            aria-label={t("user.userMenu")}
          >
            <User className="size-3.5 text-foreground-muted" />
            <span className="hidden sm:inline">{username}</span>
          </button>

          {/* User Dropdown */}
          {userMenuOpen && (
            <>
              <div
                className="fixed inset-0 z-20"
                onClick={() => setUserMenuOpen(false)}
                aria-hidden="true"
              />
              <div className="absolute right-0 mt-1.5 w-48 rounded-md border border-border bg-surface p-1 shadow-lg z-30 animate-in fade-in-50 zoom-in-95 duration-100">
                <div className="px-2 py-1.5 text-xs text-foreground-muted border-b border-border">
                  {t("user.signedInAs")}{" "}
                  <span className="font-semibold text-foreground">
                    {username}
                  </span>
                </div>
                <div className="mt-1">
                  <button
                    type="button"
                    onClick={logout}
                    className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-danger hover:bg-danger-soft transition-colors cursor-pointer"
                  >
                    <LogOut className="size-3.5" />
                    <span>{t("user.logout")}</span>
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
