"use client";

import React from "react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

interface LoadingSkeletonProps {
  className?: string;
}

export function SkeletonBox({ className }: LoadingSkeletonProps) {
  return (
    <div className={cn("rounded bg-surface-subtle animate-pulse", className)} />
  );
}

export function MetricCardSkeleton({ className }: LoadingSkeletonProps) {
  return (
    <div
      className={cn(
        "flex flex-col justify-between h-[108px] rounded-md border border-border bg-surface p-4",
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <SkeletonBox className="h-3 w-20" />
        <SkeletonBox className="size-4" />
      </div>
      <SkeletonBox className="h-7 w-32 my-1" />
      <SkeletonBox className="h-3 w-24" />
    </div>
  );
}

export function TableSkeleton({
  rows = 5,
  cols = 5,
  className,
}: {
  rows?: number;
  cols?: number;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-md border border-border bg-surface overflow-hidden",
        className,
      )}
    >
      <div className="h-9 border-b border-border bg-surface-subtle/50 px-3.5 flex items-center gap-4">
        {Array.from({ length: cols }).map((_, i) => (
          <SkeletonBox key={i} className="h-3 w-16" />
        ))}
      </div>
      <div className="divide-y divide-border">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="h-11 px-3.5 flex items-center gap-4">
            {Array.from({ length: cols }).map((_, c) => (
              <SkeletonBox
                key={c}
                className={cn(
                  "h-3.5",
                  c === 0 ? "w-32" : c === cols - 1 ? "w-16 ml-auto" : "w-20",
                )}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function ChartSkeleton({
  height = 240,
  className,
}: {
  height?: number;
  className?: string;
}) {
  const t = useTranslations("states.loading");

  return (
    <div
      className={cn(
        "rounded-md border border-border bg-surface p-4",
        className,
      )}
    >
      <div className="flex items-center justify-between mb-4">
        <SkeletonBox className="h-4 w-32" />
        <div className="flex gap-2">
          <SkeletonBox className="h-4 w-16" />
          <SkeletonBox className="h-4 w-16" />
        </div>
      </div>
      <div
        style={{ height }}
        className="w-full rounded bg-surface-subtle/60 animate-pulse flex items-center justify-center text-xs text-foreground-muted"
      >
        {t("chart")}
      </div>
    </div>
  );
}
