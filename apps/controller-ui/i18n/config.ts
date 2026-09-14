export const locales = ["en", "zh-CN"] as const;

export type AppLocale = (typeof locales)[number];

export const defaultLocale: AppLocale = "en";

export const LOCALE_COOKIE = "netqmon_locale";

export const localeLabels: Record<AppLocale, string> = {
  en: "English",
  "zh-CN": "简体中文",
};

export function isValidLocale(
  locale: string | undefined | null,
): locale is AppLocale {
  return (
    typeof locale === "string" &&
    (locales as readonly string[]).includes(locale)
  );
}
