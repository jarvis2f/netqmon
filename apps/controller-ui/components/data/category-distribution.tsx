"use client";

import React, { useState } from "react";
import { useTranslations } from "next-intl";
import { formatBytes, formatPercent } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { CategoryIcon } from "@/components/icons/category-icon";
import { CountryFlag } from "@/components/icons/country-flag";

export interface CategoryItem {
  id: string;
  name: string;
  value: number;
  icon?: React.ReactNode;
}

interface CategoryDistributionProps {
  items: CategoryItem[];
  variant?: "category" | "country";
  loading?: boolean;
  className?: string;
  title?: string;
  emptyMessage?: string;
  compact?: boolean;
}

const COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--foreground-muted)",
];

export function CategoryDistribution({
  items,
  variant = "category",
  loading = false,
  className,
  title,
  emptyMessage,
  compact = false,
}: CategoryDistributionProps) {
  const tOverview = useTranslations("overview");
  const tTraffic = useTranslations("traffic.columns");
  const tApps = useTranslations("applications");
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const displayTitle = title ?? tOverview("categoryDistribution");
  const displayEmptyMessage = emptyMessage ?? tApps("notFoundEmpty");

  if (loading) {
    return (
      <section
        className={cn(
          "flex flex-col rounded-md border border-border bg-surface select-none",
          compact ? "p-3" : "p-4",
          className,
        )}
        aria-label="Loading category distribution"
      >
        <div className="flex items-center justify-between pb-2 border-b border-border/60">
          <div className="h-4 w-32 animate-pulse rounded bg-surface-subtle" />
          <div className="h-3 w-16 animate-pulse rounded bg-surface-subtle" />
        </div>
        <div className="flex flex-1 flex-col sm:flex-row items-center gap-5 mt-3">
          <div className="flex items-center justify-center shrink-0 my-auto">
            <div
              className={cn(
                "animate-pulse rounded-full bg-surface-subtle shrink-0",
                compact ? "size-24" : "size-32",
              )}
            />
          </div>
          <div className="flex-1 w-full space-y-2.5 my-auto">
            {Array.from({ length: compact ? 4 : 5 }).map((_, index) => (
              <div key={index} className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="h-3 w-24 animate-pulse rounded bg-surface-subtle" />
                  <div className="h-3 w-12 animate-pulse rounded bg-surface-subtle" />
                </div>
                <div className="h-1.5 w-full animate-pulse rounded bg-surface-subtle" />
              </div>
            ))}
          </div>
        </div>
      </section>
    );
  }

  const total = items.reduce((sum, item) => sum + item.value, 0);
  if (!total) {
    return (
      <section
        className={cn(
          "flex flex-col rounded-md border border-border bg-surface select-none",
          compact ? "p-3" : "p-4",
          className,
        )}
      >
        <div className="flex items-center justify-between pb-2 border-b border-border/60">
          <h3 className="text-xs font-semibold tracking-tight text-foreground">
            {displayTitle}
          </h3>
        </div>
        <div
          className={cn(
            "flex flex-1 items-center justify-center rounded border border-dashed border-border text-xs text-foreground-muted",
            compact ? "mt-2 min-h-36" : "mt-3 min-h-48",
          )}
        >
          {displayEmptyMessage}
        </div>
      </section>
    );
  }

  const segments = items.map((item, index) => {
    const percentage = item.value / total;
    const offset = items
      .slice(0, index)
      .reduce((sum, previous) => sum + (previous.value / total) * 100, 0);
    return {
      ...item,
      percentage,
      offset,
      color: COLORS[index % COLORS.length],
    };
  });
  const summary = segments
    .map((item) => `${item.name} ${formatPercent(item.percentage, 0)}`)
    .join(", ");

  const donutSize = compact ? 100 : 132;
  const radius = 15.9;
  const strokeWidth = compact ? 4.5 : 5;

  return (
    <section
      className={cn(
        "flex flex-col rounded-md border border-border bg-surface select-none",
        compact ? "p-3" : "p-4",
        className,
      )}
      aria-label={`Category distribution. ${summary}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-border/60 shrink-0">
        <h3 className="text-xs font-semibold tracking-tight text-foreground">
          {displayTitle}
        </h3>
        <span className="text-[11px] font-medium text-foreground-muted tabular-nums">
          {tTraffic("total")}:{" "}
          <span className="font-semibold text-foreground">
            {formatBytes(total)}
          </span>
        </span>
      </div>

      {/* Main Content: Left-Right Layout */}
      <div
        className={cn(
          "flex flex-1 flex-col sm:flex-row items-center mt-3 min-h-0",
          compact ? "gap-3 sm:gap-4" : "gap-5",
        )}
      >
        {/* Left: Donut Chart Centered */}
        <div className="flex items-center justify-center shrink-0 my-auto">
          <div
            className="relative shrink-0"
            style={{ width: donutSize, height: donutSize }}
          >
            <svg
              viewBox="0 0 42 42"
              className="size-full -rotate-90"
              role="img"
              aria-label={summary}
            >
              <circle
                cx="21"
                cy="21"
                r={radius}
                fill="none"
                stroke="var(--surface-subtle)"
                strokeWidth={strokeWidth}
              />
              {segments.map((item) => {
                const isHovered = hoveredId === item.id;
                const hasHover = Boolean(hoveredId);
                return (
                  <circle
                    key={item.id}
                    cx="21"
                    cy="21"
                    r={radius}
                    fill="none"
                    pathLength="100"
                    stroke={item.color}
                    strokeWidth={isHovered ? strokeWidth + 1.5 : strokeWidth}
                    strokeDasharray={`${item.percentage * 100} ${100 - item.percentage * 100}`}
                    strokeDashoffset={-item.offset}
                    className="transition-all duration-200"
                    style={{
                      opacity: hasHover && !isHovered ? 0.45 : 1,
                    }}
                    onMouseEnter={() => setHoveredId(item.id)}
                    onMouseLeave={() => setHoveredId(null)}
                  />
                );
              })}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
              <span className="text-[9px] font-medium uppercase tracking-wider text-foreground-muted truncate max-w-[70px]">
                {segments[0]?.name ?? tTraffic("total")}
              </span>
              <span
                className={cn(
                  "font-semibold tabular-nums text-foreground",
                  compact ? "text-xs" : "text-sm",
                )}
              >
                {formatPercent(segments[0]?.percentage ?? 0, 0)}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Detailed Distribution List */}
        <ol className="flex flex-1 flex-col justify-center space-y-2 w-full min-w-0 my-auto">
          {segments.map((item) => {
            const isCountry = variant === "country";
            const isHovered = hoveredId === item.id;
            const hasHover = Boolean(hoveredId);

            return (
              <li
                key={item.id}
                className={cn(
                  "group flex flex-col gap-1 rounded-sm px-1.5 py-0.5 transition-colors cursor-default",
                  isHovered
                    ? "bg-surface-hover/70"
                    : "hover:bg-surface-hover/40",
                )}
                style={{
                  opacity: hasHover && !isHovered ? 0.6 : 1,
                }}
                onMouseEnter={() => setHoveredId(item.id)}
                onMouseLeave={() => setHoveredId(null)}
              >
                <div className="flex items-center justify-between text-xs">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span
                      className="size-2 shrink-0 rounded-sm"
                      style={{ backgroundColor: item.color }}
                      aria-hidden="true"
                    />
                    <span className="shrink-0 flex items-center justify-center">
                      {item.icon ??
                        (isCountry ? (
                          <CountryFlag code={item.id} size="sm" />
                        ) : (
                          <CategoryIcon category={item.id} size="sm" />
                        ))}
                    </span>
                    <span className="truncate font-medium text-foreground-secondary group-hover:text-foreground">
                      {item.name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 pl-2 shrink-0">
                    <span className="text-[11px] tabular-nums text-foreground-muted">
                      {formatBytes(item.value)}
                    </span>
                    <span className="w-9 text-right font-mono text-[11px] tabular-nums font-semibold text-foreground">
                      {formatPercent(item.percentage, 0)}
                    </span>
                  </div>
                </div>
                {/* Progress track */}
                <div className="h-1 w-full rounded-full bg-surface-subtle overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-300"
                    style={{
                      width: `${Math.max(item.percentage * 100, 1.5)}%`,
                      backgroundColor: item.color,
                    }}
                  />
                </div>
              </li>
            );
          })}
        </ol>
      </div>
    </section>
  );
}
