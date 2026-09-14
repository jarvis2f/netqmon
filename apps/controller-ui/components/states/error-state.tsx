"use client";

import React from "react";
import { AlertTriangle, RotateCw } from "lucide-react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  title?: string;
  message?: string;
  affectedScope?: string;
  onRetry?: () => void;
  action?: React.ReactNode;
  className?: string;
}

export function ErrorState({
  title,
  message,
  affectedScope,
  onRetry,
  action,
  className,
}: ErrorStateProps) {
  const t = useTranslations("states.error");

  const displayTitle = title ?? t("defaultTitle");
  const displayMessage = message ?? t("defaultMessage");

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-md border border-danger/30 bg-danger-soft/30 p-8 text-center",
        className,
      )}
      role="alert"
    >
      <div className="flex size-10 items-center justify-center rounded-full bg-danger-soft border border-danger/40 text-danger mb-3">
        <AlertTriangle className="size-5" />
      </div>

      <h4 className="text-xs font-semibold text-danger tracking-tight mb-1">
        {displayTitle}
      </h4>

      <p className="text-xs text-foreground-secondary max-w-md mb-2 leading-relaxed">
        {displayMessage}
      </p>

      {affectedScope && (
        <p className="text-[11px] text-foreground-muted max-w-sm mb-4">
          {t("affectedScope", { scope: affectedScope })}
        </p>
      )}

      <div className="flex items-center gap-2 mt-2">
        {onRetry && (
          <button
            onClick={onRetry}
            className="flex h-7 items-center gap-1.5 rounded border border-border bg-surface px-3 text-xs font-medium text-foreground hover:bg-surface-hover transition-colors cursor-pointer"
          >
            <RotateCw className="size-3" />
            <span>{t("retry")}</span>
          </button>
        )}
        {action}
      </div>
    </div>
  );
}
