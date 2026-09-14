import { getRequestConfig } from "next-intl/server";
import { cookies, headers } from "next/headers";
import { defaultLocale, isValidLocale, type AppLocale } from "./config";

export default getRequestConfig(async () => {
  let locale: AppLocale = defaultLocale;

  try {
    const cookieStore = await cookies();
    const cookieValue = cookieStore.get("netqmon_locale")?.value;

    if (isValidLocale(cookieValue)) {
      locale = cookieValue;
    } else {
      const headerStore = await headers();
      const acceptLanguage = headerStore.get("accept-language")?.toLowerCase();
      if (acceptLanguage) {
        if (
          acceptLanguage.startsWith("zh") ||
          acceptLanguage.includes("zh-cn") ||
          acceptLanguage.includes("zh-hans")
        ) {
          locale = "zh-CN";
        }
      }
    }
  } catch {
    // If request headers/cookies are unavailable during static rendering, fallback gracefully
    locale = defaultLocale;
  }

  const messages = (await import(`./messages/${locale}.json`)).default;

  return {
    locale,
    messages,
  };
});
