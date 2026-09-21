"use client";

import { dashboardIcons } from "@/lib/dashboard-icons";
import { getCategoryIcon } from "@/lib/category-icons";
import type { IconMetadata } from "@/lib/network-types";
import { hasSimpleBrandIcon, SimpleBrandIcon } from "./simple-brand-icon";
import {
  iconContainerClass,
  IconFallback,
  type IconSize,
} from "./icon-fallback";
import { LazyRemoteIcon } from "./lazy-remote-icon";

export function ApplicationIcon({
  applicationId,
  category,
  icon,
  size = "sm",
}: {
  applicationId: string;
  category?: string | null;
  icon?: IconMetadata | null;
  size?: IconSize;
}) {
  if (!applicationId || applicationId === "unknown") {
    if (category && category !== "unknown") {
      return <IconFallback icon={getCategoryIcon(category)} size={size} />;
    }
    return <IconFallback icon={dashboardIcons.unknown} size={size} />;
  }

  const brandKey = hasSimpleBrandIcon(icon?.local_fallback)
    ? icon?.local_fallback
    : hasSimpleBrandIcon(applicationId)
      ? applicationId
      : null;

  if (brandKey) {
    return (
      <span
        className={iconContainerClass(size, "text-foreground")}
        aria-hidden="true"
      >
        <SimpleBrandIcon iconKey={brandKey} />
      </span>
    );
  }

  const fallbackIcon =
    category && category !== "unknown"
      ? getCategoryIcon(category)
      : dashboardIcons.genericApplication;

  if (icon?.domain || (icon?.fallback_domains?.length ?? 0) > 0) {
    return (
      <LazyRemoteIcon
        src={`/api/icons/application/${encodeURIComponent(applicationId)}`}
        size={size}
        fallback={<IconFallback icon={fallbackIcon} size={size} />}
      />
    );
  }

  return <IconFallback icon={fallbackIcon} size={size} />;
}
