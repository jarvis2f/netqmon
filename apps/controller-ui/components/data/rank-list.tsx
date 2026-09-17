"use client";

import React from "react";
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { useTranslations } from "next-intl";
import { formatBytes, formatBitrate, formatPercent } from "@/lib/formatters";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export interface RankItem {
  id: string;
  name: string;
  subtitle?: string;
  value: number; // bytes or bps
  unitType?: "bytes" | "bitrate";
  percentage?: number; // 0 to 1 or 0 to 100
  icon?: React.ReactNode;
}

interface RankListProps {
  title: string;
  items: RankItem[];
  maxItems?: number;
  viewAllHref?: string;
  viewAllLabel?: string;
  loading?: boolean;
  onItemClick?: (item: RankItem) => void;
  className?: string;
  emptyMessage?: string;
  compact?: boolean;
}

export function RankList({
  title,
  items,
  maxItems = 5,
  viewAllHref,
  viewAllLabel,
  loading = false,
  onItemClick,
  className,
  emptyMessage,
  compact = false,
}: RankListProps) {
  const tActions = useTranslations("common.actions");
  const tEmpty = useTranslations("states.empty");

  const displayViewAll = viewAllLabel ?? tActions("viewAll");
  const displayEmpty = emptyMessage ?? tEmpty("noItems");

  if (loading) {
    return (
      <Card
        className={cn(
          "flex flex-col select-none",
          compact ? "p-3" : "p-4",
          className,
        )}
      >
        <div
          className={cn(
            "flex items-center justify-between",
            compact ? "mb-2" : "mb-3",
          )}
        >
          <div className="h-4 w-28 rounded bg-surface-subtle animate-pulse" />
          <div className="h-3 w-16 rounded bg-surface-subtle animate-pulse" />
        </div>
        <div className={compact ? "space-y-2" : "space-y-3"}>
          {Array.from({ length: maxItems }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="size-4 rounded bg-surface-subtle animate-pulse" />
              <div className="flex-1 space-y-1">
                <div className="h-3.5 w-32 rounded bg-surface-subtle animate-pulse" />
                <div className="h-1.5 w-full rounded bg-surface-subtle animate-pulse" />
              </div>
              <div className="h-3.5 w-16 rounded bg-surface-subtle animate-pulse" />
            </div>
          ))}
        </div>
      </Card>
    );
  }

  const displayedItems = items
    .filter((item) => item.value > 0)
    .sort((left, right) => right.value - left.value)
    .slice(0, maxItems);
  const maxValue = Math.max(...displayedItems.map((i) => i.value), 1);

  return (
    <Card
      className={cn(
        "flex flex-col select-none",
        compact ? "p-3" : "p-4",
        className,
      )}
    >
      {/* Header */}
      <div
        className={cn(
          "flex items-center justify-between",
          compact ? "mb-2" : "mb-3",
        )}
      >
        <h3 className="text-xs font-semibold text-foreground tracking-tight">
          {title}
        </h3>
        {viewAllHref && (
          <Link
            href={viewAllHref}
            className="flex items-center gap-0.5 text-xs font-medium text-accent hover:text-accent-hover transition-colors"
          >
            <span>{displayViewAll}</span>
            <ChevronRight className="size-3.5" />
          </Link>
        )}
      </div>

      {/* Item List */}
      {displayedItems.length === 0 ? (
        <div
          className={cn(
            "flex items-center justify-center text-xs text-foreground-muted",
            compact ? "h-24" : "h-32",
          )}
        >
          {displayEmpty}
        </div>
      ) : (
        <div className={compact ? "space-y-1.5" : "space-y-2.5"}>
          {displayedItems.map((item, index) => {
            const pct =
              item.percentage !== undefined
                ? item.percentage > 1
                  ? item.percentage
                  : item.percentage * 100
                : (item.value / maxValue) * 100;
            const percentageLabel =
              pct > 0 && pct < 0.1
                ? "<0.1%"
                : formatPercent(pct, pct < 1 ? 1 : 0, false);

            const formattedValue =
              item.unitType === "bitrate"
                ? formatBitrate(item.value)
                : formatBytes(item.value);
            const itemKey = `${item.id || "item"}-${index}`;

            return (
              <div
                key={itemKey}
                onClick={() => onItemClick?.(item)}
                className={cn(
                  "group flex flex-col gap-1 rounded p-1 -mx-1 transition-colors",
                  onItemClick && "cursor-pointer hover:bg-surface-hover",
                )}
              >
                <div className="flex items-center justify-between text-xs gap-2">
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <span className="text-[11px] font-mono text-foreground-muted w-3.5 shrink-0 text-right">
                      {index + 1}
                    </span>
                    {item.icon && <span className="shrink-0">{item.icon}</span>}
                    <div className="flex flex-col min-w-0">
                      <span className="font-medium text-foreground truncate">
                        {item.name}
                      </span>
                      {item.subtitle && (
                        <span className="text-[10px] text-foreground-muted truncate">
                          {item.subtitle}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 tabular-nums">
                    <span className="text-xs font-medium text-foreground">
                      {formattedValue}
                    </span>
                    <span className="text-[10px] text-foreground-muted w-9 text-right">
                      {percentageLabel}
                    </span>
                  </div>
                </div>

                {/* Progress Bar (2px height) */}
                <div className="h-1 w-full rounded-full bg-surface-subtle overflow-hidden">
                  <div
                    style={{ width: `${Math.min(pct, 100)}%` }}
                    className="h-full rounded-full bg-accent transition-all duration-300"
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
