"use client";

import React, { useTransition } from "react";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import { Globe } from "lucide-react";
import {
  locales,
  localeLabels,
  LOCALE_COOKIE,
  type AppLocale,
} from "@/i18n/config";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface LanguageSwitcherProps {
  variant?: "header" | "select" | "auth";
  className?: string;
}

function setLocalePreference(newLocale: AppLocale) {
  if (typeof document !== "undefined") {
    document.cookie = `${LOCALE_COOKIE}=${newLocale};path=/;max-age=31536000;SameSite=Lax`;
    document.documentElement.lang = newLocale;
  }
}

export function LanguageSwitcher({
  variant = "header",
  className,
}: LanguageSwitcherProps) {
  const currentLocale = useLocale() as AppLocale;
  const t = useTranslations("common.language");
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const handleLocaleChange = (newLocale: AppLocale) => {
    if (!newLocale || newLocale === currentLocale) return;

    setLocalePreference(newLocale);

    startTransition(() => {
      router.refresh();
    });
  };

  if (variant === "select") {
    return (
      <div className={cn("inline-flex items-center gap-2", className)}>
        <Select
          value={currentLocale}
          disabled={isPending}
          onValueChange={(val) => handleLocaleChange(val as AppLocale)}
        >
          <SelectTrigger
            size="sm"
            aria-label={t("switchLanguage")}
            className="min-w-28 text-xs font-medium"
          >
            <SelectValue>{localeLabels[currentLocale]}</SelectValue>
          </SelectTrigger>
          <SelectContent align="start">
            {locales.map((loc) => (
              <SelectItem key={loc} value={loc}>
                {localeLabels[loc]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    );
  }

  if (variant === "auth") {
    return (
      <div
        className={cn(
          "inline-flex items-center gap-1.5 text-xs text-zinc-400",
          className,
        )}
      >
        <Globe className="size-3.5 text-zinc-500" />
        <div className="flex items-center gap-1">
          {locales.map((loc, idx) => (
            <React.Fragment key={loc}>
              {idx > 0 && <span className="text-zinc-600">·</span>}
              <button
                type="button"
                onClick={() => handleLocaleChange(loc)}
                disabled={isPending}
                className={cn(
                  "px-1 py-0.5 rounded transition-colors text-xs font-medium cursor-pointer",
                  currentLocale === loc
                    ? "text-sky-400 font-semibold"
                    : "text-slate-400 hover:text-slate-200",
                )}
                aria-pressed={currentLocale === loc}
              >
                {localeLabels[loc]}
              </button>
            </React.Fragment>
          ))}
        </div>
      </div>
    );
  }

  // Default "header" variant
  return (
    <div className={cn("relative inline-flex items-center", className)}>
      <Select
        value={currentLocale}
        disabled={isPending}
        onValueChange={(val) => handleLocaleChange(val as AppLocale)}
      >
        <SelectTrigger
          size="sm"
          aria-label={t("switchLanguage")}
          className="gap-1.5 px-2 text-xs font-medium text-foreground-secondary hover:text-foreground"
        >
          <Globe className="size-3.5 text-foreground-muted shrink-0" />
          <SelectValue>{localeLabels[currentLocale]}</SelectValue>
        </SelectTrigger>
        <SelectContent align="end">
          {locales.map((loc) => (
            <SelectItem key={loc} value={loc}>
              {localeLabels[loc]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
