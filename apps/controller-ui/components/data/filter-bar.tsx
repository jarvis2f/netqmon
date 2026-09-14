"use client";

import React, { useState, useEffect, useRef } from "react";
import { Search, X, SlidersHorizontal, RotateCw } from "lucide-react";
import { useTranslations } from "next-intl";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { SimpleTooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface FilterChip {
  key: string;
  label: string;
  value: string;
  displayValue?: string;
}

interface FilterBarProps {
  searchPlaceholder?: string;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  activeFilters?: FilterChip[];
  onRemoveFilter?: (filter: FilterChip) => void;
  onClearFilters?: () => void;
  filterOptions?: {
    key: string;
    label: string;
    options: { value: string; label: string }[];
  }[];
  onSelectFilter?: (key: string, value: string, label: string) => void;
  onRefresh?: () => void;
  rightSlot?: React.ReactNode;
  customFilterContent?: React.ReactNode;
  popoverClassName?: string;
  className?: string;
}

export function FilterBar({
  searchPlaceholder = "Search IP, domain, client, port...",
  searchValue = "",
  onSearchChange,
  activeFilters = [],
  onRemoveFilter,
  onClearFilters,
  filterOptions = [],
  onSelectFilter,
  onRefresh,
  rightSlot,
  customFilterContent,
  popoverClassName,
  className,
}: FilterBarProps) {
  const t = useTranslations("common.actions");
  const tA11y = useTranslations("accessibility");
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [filterMenuOpen, setFilterMenuOpen] = useState(false);

  // Global hotkey: press '/' to focus search input (Section 64)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === "/" &&
        document.activeElement?.tagName !== "INPUT" &&
        document.activeElement?.tagName !== "TEXTAREA"
      ) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className={cn("flex flex-col gap-2 w-full", className)}>
      {/* Top Query Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        {/* Left: Search & Filter Menu Button */}
        <div className="flex items-center gap-2 flex-1 min-w-[240px] max-w-lg">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-foreground-muted pointer-events-none z-10" />
            <Input
              ref={searchInputRef}
              type="text"
              value={searchValue}
              onChange={(e) => onSearchChange?.(e.target.value)}
              placeholder={searchPlaceholder}
              className="pl-8 pr-12"
            />
            {searchValue ? (
              <button
                onClick={() => onSearchChange?.("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-foreground-muted hover:text-foreground p-0.5 cursor-pointer"
                aria-label={tA11y("search.clear")}
              >
                <X className="size-3.5" />
              </button>
            ) : (
              <kbd className="hidden sm:inline-block absolute right-2 top-1/2 -translate-y-1/2 rounded border border-border bg-surface-subtle px-1.5 text-[10px] font-mono text-foreground-muted">
                /
              </kbd>
            )}
          </div>

          {/* Filter Popover Trigger */}
          {(filterOptions.length > 0 || customFilterContent) && (
            <Popover open={filterMenuOpen} onOpenChange={setFilterMenuOpen}>
              <PopoverTrigger
                render={
                  <button
                    className={cn(
                      "flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors cursor-pointer",
                      activeFilters.length > 0
                        ? "border-accent bg-accent-soft text-accent font-semibold shadow-2xs"
                        : "border-border bg-surface text-foreground-secondary hover:bg-surface-hover hover:text-foreground",
                    )}
                    aria-label={tA11y("filter.filterRecords")}
                  >
                    <SlidersHorizontal className="size-3.5" />
                    <span>{t("filter")}</span>
                    {activeFilters.length > 0 && (
                      <span className="flex size-4 items-center justify-center rounded-full bg-accent text-[10px] font-semibold text-white">
                        {activeFilters.length}
                      </span>
                    )}
                  </button>
                }
              />

              <PopoverContent
                align="start"
                side="bottom"
                sideOffset={6}
                className={cn(
                  "w-88 sm:w-[410px] rounded-xl border border-border/80 bg-surface p-3.5 shadow-xl space-y-3.5 z-50",
                  popoverClassName,
                )}
              >
                {/* Header */}
                <div className="flex items-center justify-between border-b border-border/60 pb-2">
                  <div className="flex items-center gap-1.5">
                    <SlidersHorizontal className="size-3.5 text-accent" />
                    <span className="text-xs font-semibold text-foreground">
                      {t("filter")}
                    </span>
                    {activeFilters.length > 0 && (
                      <span className="rounded-full bg-accent-soft px-1.5 py-0.2 text-[10px] font-medium text-accent">
                        {activeFilters.length}
                      </span>
                    )}
                  </div>
                  {activeFilters.length > 0 && onClearFilters && (
                    <button
                      type="button"
                      onClick={() => {
                        onClearFilters();
                        setFilterMenuOpen(false);
                      }}
                      className="text-[11px] text-foreground-muted hover:text-destructive transition-colors font-medium cursor-pointer"
                    >
                      {t("clearAll")}
                    </button>
                  )}
                </div>

                {/* Preset Options (Protocol, Direction) */}
                {filterOptions.length > 0 && (
                  <div className="space-y-2.5">
                    {filterOptions.map((group) => (
                      <div key={group.key} className="space-y-1">
                        <div className="text-[11px] font-medium text-foreground-muted">
                          {group.label}
                        </div>
                        <div className="flex flex-wrap items-center gap-1">
                          {group.options.map((opt) => {
                            const isSelected = activeFilters.some(
                              (f) =>
                                f.key === group.key && f.value === opt.value,
                            );
                            return (
                              <button
                                key={opt.value}
                                type="button"
                                onClick={() => {
                                  onSelectFilter?.(
                                    group.key,
                                    opt.value,
                                    group.label,
                                  );
                                  setFilterMenuOpen(false);
                                }}
                                className={cn(
                                  "inline-flex h-7 items-center rounded-md px-2.5 text-xs font-medium transition-all cursor-pointer border",
                                  isSelected
                                    ? "border-accent bg-accent-soft text-accent font-semibold shadow-2xs"
                                    : "border-border/60 bg-surface-subtle/50 text-foreground-secondary hover:bg-surface-hover hover:text-foreground",
                                )}
                              >
                                {opt.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Custom Filter Content */}
                {customFilterContent && (
                  <div
                    className={cn(
                      filterOptions.length > 0 &&
                        "border-t border-border/60 pt-3",
                    )}
                  >
                    {customFilterContent}
                  </div>
                )}
              </PopoverContent>
            </Popover>
          )}
        </div>

        {/* Right: Time Range & Secondary Controls */}
        <div className="flex items-center gap-2 shrink-0">
          {rightSlot}

          {onRefresh && (
            <SimpleTooltip content={t("refresh")}>
              <button
                onClick={onRefresh}
                className="flex size-8 items-center justify-center rounded-md border border-border bg-surface text-foreground-secondary hover:bg-surface-hover hover:text-foreground transition-colors cursor-pointer"
                aria-label={t("refresh")}
              >
                <RotateCw className="size-3.5" />
              </button>
            </SimpleTooltip>
          )}
        </div>
      </div>

      {/* Removable Active Filter Chips (Section 31) */}
      {activeFilters.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[11px] text-foreground-muted">
            {t("filter")}:
          </span>
          {activeFilters.map((filter) => (
            <span
              key={`${filter.key}-${filter.value}`}
              className="inline-flex h-6 items-center gap-1 rounded border border-border bg-surface-subtle px-2 text-[11px] font-medium text-foreground"
            >
              <span className="text-foreground-muted">{filter.label}:</span>
              <span>{filter.displayValue ?? filter.value}</span>
              <button
                onClick={() => onRemoveFilter?.(filter)}
                className="ml-0.5 rounded text-foreground-muted hover:text-foreground p-0.5 cursor-pointer"
                aria-label={tA11y("filter.removeFilter", {
                  label: filter.label,
                })}
              >
                <X className="size-3" />
              </button>
            </span>
          ))}

          {onClearFilters && (
            <button
              onClick={onClearFilters}
              className="text-[11px] font-medium text-accent hover:text-accent-hover transition-colors ml-1 cursor-pointer"
            >
              {t("clearAll")}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
