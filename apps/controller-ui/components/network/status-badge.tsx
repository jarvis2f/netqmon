"use client";

import React from "react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

export type EntityStatus =
  | "online"
  | "offline"
  | "degraded"
  | "active"
  | "idle"
  | "ended"
  | "unknown"
  | "live"
  | "warning"
  | "loading";

interface StatusBadgeProps {
  status: EntityStatus;
  label?: string;
  className?: string;
}

const STATUS_CONFIG: Record<
  EntityStatus,
  { bg: string; text: string; border: string; dot: string }
> = {
  online: {
    bg: "bg-success-soft text-success",
    text: "text-success",
    border: "border-success/20",
    dot: "bg-success",
  },
  live: {
    bg: "bg-success-soft text-success",
    text: "text-success",
    border: "border-success/30",
    dot: "bg-success animate-pulse",
  },
  active: {
    bg: "bg-accent-soft text-accent",
    text: "text-accent",
    border: "border-accent/25",
    dot: "bg-accent",
  },
  idle: {
    bg: "bg-surface-hover text-foreground-secondary",
    text: "text-foreground-secondary",
    border: "border-border",
    dot: "bg-foreground-muted",
  },
  ended: {
    bg: "bg-surface-subtle text-foreground-muted",
    text: "text-foreground-muted",
    border: "border-border",
    dot: "bg-foreground-muted/60",
  },
  degraded: {
    bg: "bg-warning-soft text-warning",
    text: "text-warning",
    border: "border-warning/30",
    dot: "bg-warning",
  },
  warning: {
    bg: "bg-warning-soft text-warning",
    text: "text-warning",
    border: "border-warning/30",
    dot: "bg-warning",
  },
  offline: {
    bg: "bg-danger-soft text-danger",
    text: "text-danger",
    border: "border-danger/25",
    dot: "bg-danger",
  },
  unknown: {
    bg: "bg-surface-subtle text-foreground-muted",
    text: "text-foreground-muted",
    border: "border-border",
    dot: "bg-foreground-muted",
  },
  loading: {
    bg: "bg-surface-subtle text-foreground-muted",
    text: "text-foreground-muted",
    border: "border-border",
    dot: "bg-foreground-muted animate-pulse",
  },
};

/**
 * Compact Status Badge (22px height) for dashboards and inspector panels
 */
export function StatusBadge({ status, label, className }: StatusBadgeProps) {
  const t = useTranslations("common.status");
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.unknown;
  const displayLabel = label ?? (status in STATUS_CONFIG ? t(status) : status);

  return (
    <span
      className={cn(
        "inline-flex h-[22px] items-center gap-1.5 rounded-[5px] border px-2 text-[11px] font-medium tracking-tight shrink-0 whitespace-nowrap",
        config.bg,
        config.border,
        className,
      )}
      role="status"
    >
      <span className={cn("size-1.5 rounded-full shrink-0", config.dot)} />
      <span className="whitespace-nowrap">{displayLabel}</span>
    </span>
  );
}

/**
 * Dot Status (6px dot + text) for high-density table rows
 */
export function DotStatus({
  status,
  label,
  className,
}: {
  status: EntityStatus;
  label?: string;
  className?: string;
}) {
  const t = useTranslations("common.status");
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.unknown;
  const displayLabel = label ?? (status in STATUS_CONFIG ? t(status) : status);

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-xs text-foreground-secondary shrink-0 whitespace-nowrap",
        className,
      )}
      role="status"
    >
      <span
        className={cn("size-1.5 rounded-full shrink-0", config.dot)}
        aria-hidden="true"
      />
      <span className="tabular-nums whitespace-nowrap">{displayLabel}</span>
    </span>
  );
}
