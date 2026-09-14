"use client";

import {
  Camera,
  CircleHelp,
  Cpu,
  Gamepad2,
  HardDrive,
  Laptop,
  Monitor,
  Printer,
  Router,
  Server,
  Smartphone,
  Speaker,
  Tablet,
  Tv,
} from "lucide-react";
import { resolveDeviceIconType } from "@/lib/device-icon-resolver";
import { IconFallback, type IconSize } from "./icon-fallback";

interface ClientLike {
  name?: string | null;
  mac?: string | null;
  vendor?: string | null;
  identity?: {
    device_type?: string | null;
    model?: string | null;
    os_family?: string | null;
    vendor?: string | null;
  } | null;
}

export function ClientDeviceIcon({
  client,
  size = "sm",
}: {
  client: ClientLike;
  size?: IconSize;
}) {
  const type = resolveDeviceIconType(client);
  const Icon =
    type === "smartphone"
      ? Smartphone
      : type === "tablet"
        ? Tablet
        : type === "laptop"
          ? Laptop
          : type === "desktop"
            ? Monitor
            : type === "tv"
              ? Tv
              : type === "nas"
                ? HardDrive
                : type === "server"
                  ? Server
                  : type === "printer"
                    ? Printer
                    : type === "camera"
                      ? Camera
                      : type === "game-console"
                        ? Gamepad2
                        : type === "speaker"
                          ? Speaker
                          : type === "router"
                            ? Router
                            : type === "iot"
                              ? Cpu
                              : CircleHelp;
  return <IconFallback icon={Icon} size={size} />;
}
