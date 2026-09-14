"use client";

import React from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, CornerDownRight } from "lucide-react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

export type FlowDirectionType =
  "upload" | "download" | "bidirectional" | "local" | "unknown";

interface FlowDirectionProps {
  direction: FlowDirectionType;
  showLabel?: boolean;
  className?: string;
}

export function FlowDirection({
  direction,
  showLabel = true,
  className,
}: FlowDirectionProps) {
  const t = useTranslations("common.direction");

  switch (direction) {
    case "upload":
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-xs font-medium text-success",
            className,
          )}
          title="Upload (LAN -> WAN)"
        >
          <ArrowUp className="size-3.5 stroke-[2.2]" />
          {showLabel && <span>{t("upload")}</span>}
        </span>
      );
    case "download":
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-xs font-medium text-accent",
            className,
          )}
          title="Download (WAN -> LAN)"
        >
          <ArrowDown className="size-3.5 stroke-[2.2]" />
          {showLabel && <span>{t("download")}</span>}
        </span>
      );
    case "bidirectional":
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-xs font-medium text-purple",
            className,
          )}
          title="Bidirectional Traffic"
        >
          <ArrowUpDown className="size-3.5 stroke-[2.2]" />
          {showLabel && <span>{t("bidirectional")}</span>}
        </span>
      );
    case "local":
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-xs font-medium text-foreground-muted",
            className,
          )}
          title="Gateway Local / Router Generated"
        >
          <CornerDownRight className="size-3.5 stroke-[2.2]" />
          {showLabel && <span>{t("local")}</span>}
        </span>
      );
    default:
      return (
        <span
          className={cn(
            "inline-flex items-center gap-1 text-xs font-medium text-foreground-muted",
            className,
          )}
          title="Unknown Direction"
        >
          <span>—</span>
        </span>
      );
  }
}
