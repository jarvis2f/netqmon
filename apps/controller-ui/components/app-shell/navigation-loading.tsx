"use client";

import { LoaderCircle } from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";

export default function NavigationLoading() {
  const t = useTranslations("common.status");
  const label = t("loading");

  return (
    <AppLayout title={label} username={null}>
      <div
        role="status"
        className="flex items-center gap-2 text-sm text-foreground-muted"
      >
        <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
        {label}
      </div>
    </AppLayout>
  );
}
