"use client";

import type { LucideIcon } from "lucide-react";
import { dashboardIcons } from "@/lib/dashboard-icons";
import { cn } from "@/lib/utils";

export type IconSize = "table" | "sm" | "md" | "lg";

const sizeClass: Record<IconSize, string> = {
  table: "size-5",
  sm: "size-5",
  md: "size-6",
  lg: "size-8",
};

const glyphClass: Record<IconSize, string> = {
  table: "size-3",
  sm: "size-3",
  md: "size-3.5",
  lg: "size-4.5",
};

export function iconContainerClass(size: IconSize = "sm", className?: string) {
  return cn(
    "inline-flex shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-surface-subtle text-foreground-muted",
    sizeClass[size],
    className,
  );
}

export function IconFallback({
  icon: Icon = dashboardIcons.unknown,
  size = "sm",
  className,
}: {
  icon?: LucideIcon;
  size?: IconSize;
  className?: string;
}) {
  return (
    <span className={iconContainerClass(size, className)} aria-hidden="true">
      <Icon className={glyphClass[size]} />
    </span>
  );
}
