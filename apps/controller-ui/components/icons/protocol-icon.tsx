"use client";

import { protocolIcon } from "@/lib/protocol-icons";
import { IconFallback, type IconSize } from "./icon-fallback";

export function ProtocolIcon({
  protocol,
  size = "sm",
}: {
  protocol: string;
  size?: IconSize;
}) {
  return <IconFallback icon={protocolIcon(protocol)} size={size} />;
}
