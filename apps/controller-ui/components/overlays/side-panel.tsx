"use client";

import React, { useEffect, useId, useRef } from "react";
import { X, Copy, Check, ExternalLink } from "lucide-react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

interface SidePanelProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  statusBadge?: React.ReactNode;
  children: React.ReactNode;
  footerActions?: React.ReactNode;
  width?: "sm" | "md" | "lg";
  className?: string;
}

export function SidePanel({
  open,
  onClose,
  title,
  subtitle,
  statusBadge,
  children,
  footerActions,
  width = "md",
  className,
}: SidePanelProps) {
  const tA11y = useTranslations("accessibility.panel");
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  // Trap focus, support Escape, and restore focus when the sheet closes.
  useEffect(() => {
    if (!open) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const focusableSelector =
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const panel = panelRef.current;
    panel?.querySelector<HTMLElement>(focusableSelector)?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panel) return;

      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(focusableSelector),
      );
      if (focusable.length === 0) {
        e.preventDefault();
        panel.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previouslyFocused?.focus();
    };
  }, [open, onClose]);

  // Prevent background scrolling when panel is open
  useEffect(() => {
    if (open) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  if (!open) return null;

  const widthClass =
    width === "sm"
      ? "sm:w-[400px]"
      : width === "lg"
        ? "sm:w-[560px]"
        : "sm:w-[480px]";

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity duration-200 animate-in fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over Drawer Panel */}
      <div className="fixed inset-y-0 right-0 flex max-w-full sm:pl-10">
        <div
          ref={panelRef}
          tabIndex={-1}
          className={cn(
            "flex w-screen flex-col border-l border-border bg-surface shadow-2xl transition-transform duration-200 ease-out animate-in slide-in-from-right",
            widthClass,
            className,
          )}
        >
          {/* Header */}
          <div className="flex h-[52px] items-center justify-between border-b border-border px-5 shrink-0 bg-surface/90 backdrop-blur-xs">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="flex flex-col min-w-0">
                <div className="flex items-center gap-2 truncate">
                  <h2
                    id={titleId}
                    className="text-sm font-semibold tracking-tight text-foreground truncate"
                  >
                    {title}
                  </h2>
                  {statusBadge}
                </div>
                {subtitle && (
                  <span className="text-[11px] text-foreground-muted truncate">
                    {subtitle}
                  </span>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              className="flex size-7 items-center justify-center rounded-md text-foreground-muted hover:bg-surface-hover hover:text-foreground transition-colors cursor-pointer"
              aria-label={tA11y("close")}
            >
              <X className="size-4" />
            </button>
          </div>

          {/* Scrollable Content Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs text-foreground">
            {children}
          </div>

          {/* Footer Actions */}
          {footerActions && (
            <div className="flex items-center justify-between border-t border-border bg-surface-subtle/50 px-5 py-3 shrink-0">
              {footerActions}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Property Row Helper for Side Panel
 */
export function PropertyRow({
  label,
  value,
  copyable = false,
  mono = false,
  className,
  href,
  external = false,
}: {
  label: string;
  value: React.ReactNode;
  copyable?: boolean;
  mono?: boolean;
  className?: string;
  href?: string;
  external?: boolean;
}) {
  const tA11y = useTranslations("accessibility.panel");
  const tActions = useTranslations("common.actions");
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    if (typeof value === "string" || typeof value === "number") {
      void navigator.clipboard.writeText(String(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const textContent = (
    <span className={cn(mono && "font-mono tabular-nums")}>{value ?? "—"}</span>
  );

  return (
    <div
      className={cn(
        "flex items-center justify-between py-1.5 border-b border-border/50 text-xs",
        className,
      )}
    >
      <span className="text-foreground-muted font-medium">{label}</span>
      <div className="flex items-center gap-1.5 font-medium text-foreground">
        {href ? (
          <a
            href={href}
            target={external ? "_blank" : undefined}
            rel={external ? "noopener noreferrer" : undefined}
            className="group inline-flex items-center gap-1 text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-ring rounded-xs"
          >
            {textContent}
            {external && (
              <ExternalLink className="size-3 shrink-0 opacity-70 group-hover:opacity-100 transition-opacity" />
            )}
          </a>
        ) : (
          textContent
        )}
        {copyable && typeof value === "string" && (
          <button
            type="button"
            onClick={handleCopy}
            className="p-1 rounded text-foreground-muted hover:text-foreground hover:bg-surface-hover cursor-pointer"
            aria-label={tA11y("copy", { label })}
            title={copied ? tActions("copied") : tActions("copy")}
          >
            {copied ? (
              <Check className="size-3 text-success" />
            ) : (
              <Copy className="size-3" />
            )}
          </button>
        )}
      </div>
    </div>
  );
}
