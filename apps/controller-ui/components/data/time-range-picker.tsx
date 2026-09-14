"use client";

import React from "react";
import { Calendar } from "lucide-react";
import { useLocale, useTranslations } from "next-intl";
import { zhCN, enUS } from "date-fns/locale";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import {
  DateTimePickerRange,
  type DateTimeRange,
} from "@/components/ui/datetime-picker-range";

export type TimeRangeValue = "15m" | "1h" | "24h" | "7d" | "30d" | "custom";

export interface CustomDateRange {
  from: string; // ISO string
  to: string; // ISO string
}

interface TimeRangePickerProps {
  value: TimeRangeValue;
  onChange: (value: TimeRangeValue, customRange?: CustomDateRange) => void;
  customRange?: CustomDateRange;
  options?: { value: TimeRangeValue; label: string }[];
  showRealtimeOption?: boolean;
  className?: string;
}

export function TimeRangePicker({
  value,
  onChange,
  customRange,
  options,
  showRealtimeOption = false,
  className,
}: TimeRangePickerProps) {
  const t = useTranslations("common.timeRange");
  const tActions = useTranslations("common.actions");
  const tA11y = useTranslations("accessibility.customTimeRange");
  const localeCode = useLocale();
  const dateFnsLocale = localeCode === "zh-CN" ? zhCN : enUS;

  const defaultOptions: { value: TimeRangeValue; label: string }[] = [
    { value: "1h", label: t("range1h") },
    { value: "24h", label: t("range24h") },
    { value: "7d", label: t("range7d") },
    { value: "30d", label: t("range30d") },
  ];

  const rangeOptions =
    options ??
    (showRealtimeOption
      ? [
          { value: "15m" as TimeRangeValue, label: t("live15m") },
          ...defaultOptions,
        ]
      : defaultOptions);

  const parsedCustomRange: DateTimeRange | undefined = React.useMemo(() => {
    if (!customRange?.from || !customRange?.to) return undefined;
    const fromDate = new Date(customRange.from);
    const toDate = new Date(customRange.to);
    if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) return undefined;
    return { from: fromDate, to: toDate };
  }, [customRange]);

  const handleRangeChange = (range: DateTimeRange) => {
    if (range.from && range.to) {
      onChange("custom", {
        from: range.from.toISOString(),
        to: range.to.toISOString(),
      });
    }
  };

  return (
    <Tabs
      value={value}
      onValueChange={(val) => {
        if (val === "custom") {
          if (customRange?.from && customRange?.to) {
            onChange("custom", customRange);
          }
        } else {
          onChange(val as TimeRangeValue);
        }
      }}
      variant="pill"
      className={cn("w-auto inline-flex items-center", className)}
    >
      <TabsList className="h-8 p-0.5 bg-surface-subtle/80 border border-border">
        {rangeOptions.map((opt) => (
          <TabsTrigger
            key={opt.value}
            value={opt.value}
            className="h-7 px-2.5 text-xs font-medium"
          >
            {opt.label}
          </TabsTrigger>
        ))}

        {/* Custom Option: DateTimePickerRange */}
        <DateTimePickerRange
          value={parsedCustomRange}
          onChange={handleRangeChange}
          fromLabel={tA11y("startTime")}
          toLabel={tA11y("endTime")}
          applyLabel={tActions("applyRange")}
          placeholder={tA11y("title")}
          locale={dateFnsLocale}
          renderTrigger={({ hasSelection, displayText }) => (
            <TabsTrigger
              value="custom"
              className="h-7 gap-1 px-2 text-xs font-medium"
            >
              <Calendar className="size-3.5" />
              <span className="hidden sm:inline">
                {value === "custom" && hasSelection ? displayText : t("custom")}
              </span>
            </TabsTrigger>
          )}
        />
      </TabsList>
    </Tabs>
  );
}
