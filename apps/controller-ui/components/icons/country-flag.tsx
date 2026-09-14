"use client";

import { dashboardIcons } from "@/lib/dashboard-icons";
import { cn } from "@/lib/utils";
import { IconFallback, type IconSize } from "./icon-fallback";

const sizeClass: Record<IconSize, string> = {
  table: "h-3.5 w-5",
  sm: "h-3.5 w-5",
  md: "h-4 w-6",
  lg: "h-5 w-8",
};

export function CountryFlag({
  code,
  size = "sm",
  label,
}: {
  code?: string | null;
  size?: IconSize;
  label?: string;
}) {
  const normalized = code?.trim().toLowerCase();
  if (!normalized || !/^[a-z]{2}$/.test(normalized)) {
    return <IconFallback icon={dashboardIcons.country} size={size} />;
  }
  return (
    <span
      className={cn(
        "fi rounded-[2px] shadow-[0_0_0_1px_rgba(0,0,0,0.12)]",
        `fi-${normalized}`,
        sizeClass[size],
      )}
      aria-hidden={label ? undefined : true}
      aria-label={label}
    />
  );
}
