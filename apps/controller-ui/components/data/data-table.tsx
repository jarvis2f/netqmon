"use client";

import React, { useState } from "react";
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

export interface ColumnDef<T> {
  id: string;
  header: string | React.ReactNode;
  accessorKey?: keyof T;
  cell?: (row: T, index: number) => React.ReactNode;
  align?: "left" | "right" | "center";
  sortable?: boolean;
  width?: string | number;
  className?: string;
}

export type SortDirection = "asc" | "desc" | null;

export interface SortState {
  columnId: string;
  direction: SortDirection;
}

export interface PaginationState {
  pageIndex: number;
  pageSize: number;
  hasMore?: boolean;
  totalCount?: number;
}

interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string | number;
  loading?: boolean;
  onRowClick?: (row: T) => void;
  sortState?: SortState;
  onSortChange?: (sort: SortState) => void;
  pagination?: {
    pageIndex: number;
    pageSize: number;
    hasPrevious?: boolean;
    hasNext?: boolean;
    onPreviousPage?: () => void;
    onNextPage?: () => void;
    totalDisplay?: string;
  };
  emptyState?: React.ReactNode;
  className?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  loading = false,
  onRowClick,
  sortState,
  onSortChange,
  pagination,
  emptyState,
  className,
}: DataTableProps<T>) {
  const [internalSort, setInternalSort] = useState<SortState>({
    columnId: "",
    direction: null,
  });

  const currentSort = sortState !== undefined ? sortState : internalSort;

  const handleHeaderClick = (column: ColumnDef<T>) => {
    if (!column.sortable) return;

    let nextDir: SortDirection = "asc";
    if (currentSort.columnId === column.id) {
      if (currentSort.direction === "asc") nextDir = "desc";
      else if (currentSort.direction === "desc") nextDir = null;
      else nextDir = "asc";
    }

    const newSortState: SortState = {
      columnId: nextDir ? column.id : "",
      direction: nextDir,
    };

    if (onSortChange) {
      onSortChange(newSortState);
    } else {
      setInternalSort(newSortState);
    }
  };

  const getSortIcon = (column: ColumnDef<T>) => {
    if (!column.sortable) return null;
    if (currentSort.columnId !== column.id || !currentSort.direction) {
      return (
        <ArrowUpDown className="size-3 text-foreground-muted opacity-0 group-hover:opacity-100 transition-opacity" />
      );
    }
    return currentSort.direction === "asc" ? (
      <ArrowUp className="size-3 text-accent" />
    ) : (
      <ArrowDown className="size-3 text-accent" />
    );
  };

  const t = useTranslations("common.pagination");
  const tStates = useTranslations("states.empty");

  return (
    <div
      className={cn(
        "flex flex-col w-full rounded-md border border-border bg-surface overflow-hidden select-none",
        className,
      )}
    >
      {/* Table Container with Horizontal Scroll Support */}
      <div className="w-full overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          {/* Header Row (36px height) */}
          <thead className="border-b border-border bg-surface-subtle/50 text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">
            <tr className="h-9">
              {columns.map((col) => {
                const alignClass =
                  col.align === "right"
                    ? "text-right justify-end"
                    : col.align === "center"
                      ? "text-center justify-center"
                      : "text-left justify-start";

                return (
                  <th
                    key={col.id}
                    style={{ width: col.width }}
                    className={cn(
                      "font-medium whitespace-nowrap",
                      col.className,
                    )}
                    aria-sort={
                      currentSort.columnId === col.id && currentSort.direction
                        ? currentSort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : col.sortable
                          ? "none"
                          : undefined
                    }
                  >
                    {col.sortable ? (
                      <button
                        type="button"
                        onClick={() => handleHeaderClick(col)}
                        className={cn(
                          "group flex h-9 w-full items-center gap-1.5 px-3.5 outline-none hover:text-foreground focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring cursor-pointer",
                          alignClass,
                        )}
                      >
                        <span>{col.header}</span>
                        {getSortIcon(col)}
                      </button>
                    ) : (
                      <div
                        className={cn(
                          "flex h-9 items-center gap-1.5 px-3.5",
                          alignClass,
                        )}
                      >
                        <span>{col.header}</span>
                      </div>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>

          {/* Table Body (40-44px row height) */}
          <tbody className="divide-y divide-border">
            {loading ? (
              // Loading Skeleton Rows
              Array.from({ length: 6 }).map((_, rIdx) => (
                <tr key={rIdx} className="h-11">
                  {columns.map((col, cIdx) => (
                    <td key={cIdx} className="px-3.5">
                      <div
                        className={cn(
                          "h-3.5 rounded bg-surface-subtle animate-pulse",
                          col.align === "right" ? "ml-auto w-16" : "w-24",
                        )}
                      />
                    </td>
                  ))}
                </tr>
              ))
            ) : data.length === 0 ? (
              // Empty State
              <tr>
                <td
                  colSpan={columns.length}
                  className="h-40 text-center text-foreground-muted"
                >
                  {emptyState ?? (
                    <div className="flex flex-col items-center justify-center gap-1 py-8">
                      <span className="text-xs font-medium">
                        {tStates("noRecords")}
                      </span>
                      <span className="text-[11px] text-foreground-muted">
                        {tStates("adjustFilters")}
                      </span>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              // Data Rows
              data.map((row, rIdx) => {
                const key = keyExtractor(row, rIdx);
                const rowKey = `${key}-${rIdx}`;
                return (
                  <tr
                    key={rowKey}
                    onClick={() => onRowClick?.(row)}
                    tabIndex={onRowClick ? 0 : undefined}
                    onKeyDown={(e) => {
                      if (onRowClick && (e.key === "Enter" || e.key === " ")) {
                        e.preventDefault();
                        onRowClick(row);
                      }
                    }}
                    className={cn(
                      "h-11 transition-colors outline-none",
                      onRowClick &&
                        "cursor-pointer hover:bg-surface-hover focus-visible:bg-surface-hover",
                    )}
                  >
                    {columns.map((col) => {
                      const alignClass =
                        col.align === "right"
                          ? "text-right tabular-nums font-mono"
                          : col.align === "center"
                            ? "text-center"
                            : "text-left";

                      let content: React.ReactNode = null;
                      if (col.cell) {
                        content = col.cell(row, rIdx);
                      } else if (col.accessorKey) {
                        content = String(row[col.accessorKey] ?? "");
                      }

                      return (
                        <td
                          key={col.id}
                          className={cn(
                            "px-3.5 text-foreground whitespace-nowrap",
                            alignClass,
                            col.className,
                          )}
                        >
                          {content}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {pagination && (
        <div className="flex items-center justify-between border-t border-border bg-surface-subtle/30 px-3.5 py-2 text-xs text-foreground-muted">
          <div>
            {pagination.totalDisplay ??
              t("showingCount", { count: data.length })}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={pagination.onPreviousPage}
              disabled={!pagination.hasPrevious}
              className="flex h-7 items-center gap-1 rounded border border-border bg-surface px-2 text-xs font-medium text-foreground hover:bg-surface-hover disabled:opacity-40 disabled:pointer-events-none transition-colors cursor-pointer"
              aria-label={t("previous")}
            >
              <ChevronLeft className="size-3.5" />
              <span>{t("previous")}</span>
            </button>

            <button
              onClick={pagination.onNextPage}
              disabled={!pagination.hasNext}
              className="flex h-7 items-center gap-1 rounded border border-border bg-surface px-2 text-xs font-medium text-foreground hover:bg-surface-hover disabled:opacity-40 disabled:pointer-events-none transition-colors cursor-pointer"
              aria-label={t("next")}
            >
              <span>{t("next")}</span>
              <ChevronRight className="size-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
