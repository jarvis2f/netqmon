"use client";

import React, { useEffect, useRef, useSyncExternalStore } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import {
  LayoutDashboard,
  Activity,
  Boxes,
  MonitorSmartphone,
  Globe2,
  Network,
  Lightbulb,
  Settings,
  X,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { NetqmonLogo, NetqmonBrandText } from "@/components/brand/logo";
import {
  EASE_OUT,
  SPRING_LAYOUT,
  SPRING_PANEL,
  SPRING_PRESS,
} from "@/lib/ease";
import { cn } from "@/lib/utils";

export interface NavItem {
  key:
    | "overview"
    | "traffic"
    | "applications"
    | "clients"
    | "destinations"
    | "flows"
    | "insights"
    | "settings";
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string | number;
}

const NAV_ITEMS: NavItem[] = [
  { key: "overview", href: "/netqmon", icon: LayoutDashboard },
  { key: "traffic", href: "/traffic", icon: Activity },
  { key: "applications", href: "/applications", icon: Boxes },
  { key: "clients", href: "/clients", icon: MonitorSmartphone },
  { key: "destinations", href: "/destinations", icon: Globe2 },
  { key: "flows", href: "/flows", icon: Network },
  { key: "insights", href: "/insights", icon: Lightbulb },
  { key: "settings", href: "/settings", icon: Settings },
];

interface SidebarProps {
  mobileOpen?: boolean;
  onMobileClose?: () => void;
  gatewayStatus?: "online" | "offline" | "degraded" | "loading";
}

const SIDEBAR_COLLAPSED_KEY = "netqmon_sidebar_collapsed";
const SIDEBAR_CHANGE_EVENT = "netqmon-sidebar-change";

function readCollapsedPreference() {
  try {
    return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "true";
  } catch {
    return false;
  }
}

function subscribeToCollapsedPreference(onStoreChange: () => void) {
  window.addEventListener("storage", onStoreChange);
  window.addEventListener(SIDEBAR_CHANGE_EVENT, onStoreChange);
  return () => {
    window.removeEventListener("storage", onStoreChange);
    window.removeEventListener(SIDEBAR_CHANGE_EVENT, onStoreChange);
  };
}

export function Sidebar({
  mobileOpen = false,
  onMobileClose,
  gatewayStatus = "online",
}: SidebarProps) {
  const t = useTranslations("navigation");
  const tCommon = useTranslations("common");
  const pathname = usePathname();
  const reduce = useReducedMotion();
  const mobilePanelRef = useRef<HTMLElement>(null);
  const collapsed = useSyncExternalStore(
    subscribeToCollapsedPreference,
    readCollapsedPreference,
    () => false,
  );

  useEffect(() => {
    if (!mobileOpen) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const panel = mobilePanelRef.current;
    const focusableSelector =
      'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';
    panel?.querySelector<HTMLElement>("button[aria-label]")?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onMobileClose?.();
        return;
      }
      if (event.key !== "Tab" || !panel) return;

      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(focusableSelector),
      );
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus();
    };
  }, [mobileOpen, onMobileClose]);

  const toggleCollapsed = () => {
    const next = !collapsed;
    try {
      localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(next));
      window.dispatchEvent(new Event(SIDEBAR_CHANGE_EVENT));
    } catch {
      // ignore
    }
  };

  const isExpanded = !collapsed || mobileOpen;

  const renderNavItem = (item: NavItem) => {
    const Icon = item.icon;
    const label = t(item.key);
    const isActive =
      item.href === "/netqmon"
        ? pathname === "/netqmon" ||
          pathname === "/" ||
          pathname === "/overview"
        : pathname.startsWith(item.href);

    return (
      <Link
        key={item.key}
        href={item.href}
        onClick={onMobileClose}
        title={label}
        className={cn(
          "group relative flex h-9 items-center gap-2.5 rounded-lg px-2 text-xs font-medium outline-none transition-colors duration-150 focus-visible:ring-1 focus-visible:ring-ring",
          isActive
            ? "text-accent font-semibold"
            : "text-foreground-secondary hover:text-foreground hover:bg-surface-hover/50",
          !isExpanded && "justify-center px-0",
        )}
      >
        {isActive ? (
          <motion.span
            layoutId="sidebar-active-indicator"
            transition={reduce ? { duration: 0 } : SPRING_LAYOUT}
            className="absolute inset-0 rounded-lg bg-accent-soft shadow-2xs"
          />
        ) : null}

        <Icon
          className={cn(
            "relative z-10 size-[18px] shrink-0 transition-colors",
            isActive
              ? "text-accent"
              : "text-foreground-muted group-hover:text-foreground",
          )}
        />

        {isExpanded && (
          <motion.span
            initial={false}
            animate={{ opacity: 1, x: 0 }}
            transition={
              reduce ? { duration: 0 } : { duration: 0.18, ease: EASE_OUT }
            }
            className="relative z-10 truncate flex-1 tracking-tight"
          >
            {label}
          </motion.span>
        )}

        {isExpanded && item.badge !== undefined && (
          <span className="relative z-10 ml-auto rounded-full bg-rose-500/90 text-white px-1.5 py-0.5 text-[10px] font-medium leading-none shadow-2xs">
            {item.badge}
          </span>
        )}
      </Link>
    );
  };

  const statusColor =
    gatewayStatus === "loading"
      ? "bg-foreground-muted animate-pulse shadow-[0_0_8px_rgba(150,150,150,0.4)]"
      : gatewayStatus === "online"
        ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"
        : gatewayStatus === "degraded"
          ? "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.4)]"
          : "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]";

  const statusTitle =
    gatewayStatus === "loading"
      ? tCommon("status.loading")
      : gatewayStatus === "online"
        ? t("statusNormal")
        : gatewayStatus === "degraded"
          ? t("statusDegraded")
          : t("statusOffline");

  const statusDesc =
    gatewayStatus === "loading"
      ? tCommon("status.connecting")
      : gatewayStatus === "online"
        ? t("statusNormalDesc")
        : gatewayStatus === "degraded"
          ? t("statusDegradedDesc")
          : t("statusOfflineDesc");

  const sidebarContent = (
    <div className="flex h-full flex-col justify-between p-2.5">
      {/* Top Branding and Navigation */}
      <div>
        {/* Top Header: Logo (Centered) */}
        {isExpanded ? (
          <div className="relative flex h-10 items-center justify-center mb-3">
            <Link
              href="/netqmon"
              className="flex items-center justify-center gap-2 outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm group min-w-0"
            >
              <NetqmonLogo
                size={24}
                className="size-6 transition-transform group-hover:scale-105 shrink-0"
              />
              <NetqmonBrandText />
            </Link>

            {mobileOpen && (
              <button
                onClick={onMobileClose}
                className="absolute right-1 p-1 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-hover transition-colors cursor-pointer"
                aria-label={t("closeNavigation")}
              >
                <X className="size-4" />
              </button>
            )}
          </div>
        ) : (
          <div className="flex h-10 items-center justify-center mb-3">
            <Link
              href="/netqmon"
              title="netqmon"
              className="flex items-center justify-center size-8 rounded-md hover:bg-surface-hover transition-colors"
            >
              <NetqmonLogo size={24} className="size-6" />
            </Link>
          </div>
        )}

        {/* Navigation List: all menu items with beUI active indicator */}
        <nav className="space-y-1" aria-label={t("mainNavigation")}>
          {NAV_ITEMS.map(renderNavItem)}
        </nav>
      </div>

      {/* Bottom Section: System Status */}
      <div className="pt-2.5">
        {isExpanded ? (
          <div className="rounded-xl border border-border/60 bg-surface-subtle/50 p-2.5 shadow-2xs">
            <div className="flex items-center gap-1.5 text-xs font-medium text-foreground-muted mb-1">
              <span
                className={cn("size-2 rounded-full shrink-0", statusColor)}
              />
              <span>{t("systemStatus")}</span>
            </div>
            <div className="text-xs font-bold text-foreground">
              {statusTitle}
            </div>
            <div className="text-[10px] text-foreground-muted mt-0.5 leading-snug">
              {statusDesc}
            </div>
          </div>
        ) : (
          <div
            className="flex flex-col items-center justify-center p-2 rounded-lg border border-border/60 bg-surface-subtle/50 text-center"
            title={`${t("systemStatus")}: ${statusTitle} (${statusDesc})`}
          >
            <span className={cn("size-2.5 rounded-full", statusColor)} />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Fixed Sidebar with Spring-animated width */}
      <motion.aside
        aria-label={t("primaryNavigationSidebar")}
        initial={false}
        animate={{ width: collapsed ? 64 : 180 }}
        transition={
          reduce
            ? { duration: 0 }
            : { type: "spring", stiffness: 380, damping: 35, mass: 0.75 }
        }
        className="relative hidden md:flex flex-col shrink-0 border-r border-border bg-surface select-none will-change-[width] z-20 h-screen sticky top-0 overflow-visible"
      >
        {/* Subtle border collapse/expand button */}
        <motion.button
          onClick={toggleCollapsed}
          whileTap={reduce ? undefined : { scale: 0.9 }}
          transition={SPRING_PRESS}
          className={cn(
            "absolute -right-2.5 top-1/2 -translate-y-1/2 z-30 hidden md:flex",
            "size-5 items-center justify-center rounded-full",
            "border border-border/80 bg-surface text-foreground-muted shadow-2xs",
            "hover:border-accent hover:bg-accent-soft hover:text-accent",
            "transition-colors outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer",
          )}
          aria-label={collapsed ? t("expandSidebar") : t("collapseSidebar")}
          title={collapsed ? t("expandSidebar") : t("collapseSidebar")}
        >
          {collapsed ? (
            <ChevronRight className="size-3" />
          ) : (
            <ChevronLeft className="size-3" />
          )}
        </motion.button>

        {sidebarContent}
      </motion.aside>

      {/* Mobile Drawer with Backdrop and Spring Slide-in */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 bg-black/50 backdrop-blur-xs z-40 md:hidden"
              onClick={onMobileClose}
              aria-hidden="true"
            />

            <motion.aside
              ref={mobilePanelRef}
              role="dialog"
              aria-modal="true"
              aria-label={t("mobileNavigation")}
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={reduce ? { duration: 0.15 } : SPRING_PANEL}
              className="fixed inset-y-0 left-0 z-50 w-64 bg-surface border-r border-border shadow-xl md:hidden"
            >
              {sidebarContent}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
