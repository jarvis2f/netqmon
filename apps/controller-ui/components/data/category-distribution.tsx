"use client";

import { useTranslations } from "next-intl";
import { formatBytes, formatPercent } from "@/lib/formatters";
import { cn } from "@/lib/utils";

export interface CategoryItem {
  id: string;
  name: string;
  value: number;
}

interface CategoryDistributionProps {
  items: CategoryItem[];
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
  loading = false,
  className,
  title,
  emptyMessage,
  compact = false,
}: CategoryDistributionProps) {
  const tOverview = useTranslations("overview");
  const tTraffic = useTranslations("traffic.columns");
  const tApps = useTranslations("applications");

  const displayTitle = title ?? tOverview("categoryDistribution");
  const displayEmptyMessage = emptyMessage ?? tApps("notFoundEmpty");

  if (loading) {
    return (
      <section
        className={cn(
          "rounded-md border border-border bg-surface",
          compact ? "p-3" : "p-4",
          className,
        )}
        aria-label="Loading category distribution"
      >
        <div className="h-4 w-36 animate-pulse rounded bg-surface-subtle" />
        <div
          className={cn(
            "flex items-center",
            compact ? "mt-2 gap-4" : "mt-4 gap-8",
          )}
        >
          <div
            className={cn(
              "animate-pulse rounded-full bg-surface-subtle",
              compact ? "size-24" : "size-36",
            )}
          />
          <div className={cn("flex-1", compact ? "space-y-2" : "space-y-3")}>
            {Array.from({ length: 4 }).map((_, index) => (
              <div
                key={index}
                className="h-3 animate-pulse rounded bg-surface-subtle"
              />
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
          "rounded-md border border-border bg-surface",
          compact ? "p-3" : "p-4",
          className,
        )}
      >
        <h3 className="text-xs font-semibold tracking-tight text-foreground">
          {displayTitle}
        </h3>
        <div
          className={cn(
            "flex items-center justify-center rounded border border-dashed border-border text-xs text-foreground-muted",
            compact ? "mt-2 h-28" : "mt-3 h-44",
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

  return (
    <section
      className={cn(
        "rounded-md border border-border bg-surface",
        compact ? "p-3" : "p-4",
        className,
      )}
      aria-label={`Category distribution. ${summary}`}
    >
      <h3 className="text-xs font-semibold tracking-tight text-foreground">
        {displayTitle}
      </h3>
      <div
        className={cn(
          "grid items-center",
          compact
            ? "mt-2 gap-3 sm:grid-cols-[112px_1fr]"
            : "mt-3 gap-5 sm:grid-cols-[160px_1fr]",
        )}
      >
        <div
          className={cn("relative mx-auto", compact ? "size-28" : "size-36")}
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
              r="15.9"
              fill="none"
              stroke="var(--surface-subtle)"
              strokeWidth="5"
            />
            {segments.map((item) => (
              <circle
                key={item.id}
                cx="21"
                cy="21"
                r="15.9"
                fill="none"
                pathLength="100"
                stroke={item.color}
                strokeWidth="5"
                strokeDasharray={`${item.percentage * 100} ${100 - item.percentage * 100}`}
                strokeDashoffset={-item.offset}
              />
            ))}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
              {tTraffic("total")}
            </span>
            <span
              className={cn(
                "font-semibold tabular-nums text-foreground",
                compact ? "mt-0 text-xs" : "mt-0.5 text-sm",
              )}
            >
              {formatBytes(total)}
            </span>
          </div>
        </div>
        <ol className={compact ? "space-y-1.5" : "space-y-2.5"}>
          {segments.map((item) => (
            <li
              key={item.id}
              className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 text-xs"
            >
              <span
                className="size-2 rounded-sm"
                style={{ backgroundColor: item.color }}
                aria-hidden="true"
              />
              <span className="truncate font-medium text-foreground-secondary">
                {item.name}
              </span>
              <span className="font-mono tabular-nums text-foreground">
                {formatPercent(item.percentage, 0)}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
