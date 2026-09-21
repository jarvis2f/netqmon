"use client";

import { dashboardIcons } from "@/lib/dashboard-icons";
import type { IconMetadata } from "@/lib/network-types";
import { hasSimpleBrandIcon, SimpleBrandIcon } from "./simple-brand-icon";
import {
  iconContainerClass,
  IconFallback,
  type IconSize,
} from "./icon-fallback";
import { LazyRemoteIcon } from "./lazy-remote-icon";

export function OrganizationIcon({
  organizationId,
  icon,
  size = "sm",
}: {
  organizationId: string;
  icon?: IconMetadata | null;
  size?: IconSize;
}) {
  if (!organizationId || organizationId === "unknown") {
    return <IconFallback icon={dashboardIcons.unknown} size={size} />;
  }

  const brandKey = hasSimpleBrandIcon(icon?.local_fallback)
    ? icon?.local_fallback
    : hasSimpleBrandIcon(organizationId)
      ? organizationId
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
  if (icon?.domain || (icon?.fallback_domains?.length ?? 0) > 0) {
    return (
      <LazyRemoteIcon
        src={`/api/icons/organization/${encodeURIComponent(organizationId)}`}
        size={size}
        fallback={
          <IconFallback icon={dashboardIcons.genericOrganization} size={size} />
        }
      />
    );
  }
  return <IconFallback icon={dashboardIcons.genericOrganization} size={size} />;
}
