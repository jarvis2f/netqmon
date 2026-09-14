import React from "react";
import { ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  unit?: string;
  icon?: React.ComponentType<{ className?: string }>;
  delta?: {
    value: string | number;
    trend?: "up" | "down" | "neutral";
    comparisonLabel?: string;
    invertColor?: boolean; // If true, up is bad (red) and down is good (green)
  };
  subtext?: string;
  badge?: React.ReactNode;
  loading?: boolean;
  className?: string;
  onClick?: () => void;
}

export function MetricCard({
  label,
  value,
  unit,
  icon: Icon,
  delta,
  subtext,
  badge,
  loading = false,
  className,
  onClick,
}: MetricCardProps) {
  if (loading) {
    return (
      <Card
        className={cn("flex flex-col justify-between h-[108px] p-4", className)}
      >
        <div className="flex items-center justify-between">
          <div className="h-3 w-20 rounded bg-surface-subtle animate-pulse" />
          <div className="size-4 rounded bg-surface-subtle animate-pulse" />
        </div>
        <div className="h-7 w-32 rounded bg-surface-subtle animate-pulse my-1" />
        <div className="h-3 w-24 rounded bg-surface-subtle animate-pulse" />
      </Card>
    );
  }

  const getDeltaColor = () => {
    if (!delta || !delta.trend || delta.trend === "neutral")
      return "text-foreground-muted";
    const isPositive = delta.trend === "up";
    const isGood = delta.invertColor ? !isPositive : isPositive;
    return isGood ? "text-success" : "text-danger";
  };

  const getDeltaIcon = () => {
    if (!delta || !delta.trend || delta.trend === "neutral") {
      return <Minus className="size-3 stroke-[2.5]" />;
    }
    return delta.trend === "up" ? (
      <ArrowUpRight className="size-3.5 stroke-[2.5]" />
    ) : (
      <ArrowDownRight className="size-3.5 stroke-[2.5]" />
    );
  };

  return (
    <Card
      onClick={onClick}
      className={cn(
        "flex flex-col justify-between min-h-[108px] p-4 transition-colors select-none",
        onClick &&
          "cursor-pointer hover:bg-surface-hover hover:border-border-strong",
        className,
      )}
    >
      {/* Top Label & Icon / Badge */}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold tracking-wider text-foreground-muted uppercase truncate">
          {label}
        </span>
        <div className="flex items-center gap-1.5 shrink-0">
          {badge}
          {Icon && <Icon className="size-4 text-foreground-muted" />}
        </div>
      </div>

      {/* Metric Main Value */}
      <div className="flex items-baseline gap-1 my-1">
        <span className="text-2xl font-bold tracking-tight text-foreground tabular-nums">
          {value ?? "—"}
        </span>
        {unit && (
          <span className="text-xs font-medium text-foreground-secondary">
            {unit}
          </span>
        )}
      </div>

      {/* Bottom Subtext or Delta Indicator */}
      <div className="flex items-center gap-1.5 text-xs truncate">
        {delta ? (
          <div
            className={cn(
              "inline-flex items-center gap-0.5 font-medium tabular-nums",
              getDeltaColor(),
            )}
          >
            {getDeltaIcon()}
            <span>{delta.value}</span>
            {delta.comparisonLabel && (
              <span className="text-foreground-muted font-normal ml-1">
                {delta.comparisonLabel}
              </span>
            )}
          </div>
        ) : subtext ? (
          <span className="text-foreground-muted text-[11px] truncate">
            {subtext}
          </span>
        ) : (
          <span className="text-transparent text-[11px] select-none">—</span>
        )}
      </div>
    </Card>
  );
}
