import { useTranslations } from "next-intl";
import { ApplicationIcon } from "@/components/icons/application-icon";
import { formatIdentifier } from "@/lib/formatters";
import type { IconMetadata } from "@/lib/network-types";

export function ApplicationIdentity({
  id,
  name,
  category,
  icon,
}: {
  id: string;
  name?: string | null;
  category?: string;
  icon?: IconMetadata | null;
}) {
  const t = useTranslations("applications");
  const unknown = id === "unknown";
  const protocolOnly = id === "protocol-only";
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <ApplicationIcon
        applicationId={id}
        category={category}
        icon={icon}
        size="md"
      />
      <div className="min-w-0">
        <div className="truncate font-medium text-foreground">
          {protocolOnly
            ? t("protocolOnlyApp")
            : unknown
              ? "Unknown"
              : name || formatIdentifier(id)}
        </div>
        <div className="truncate text-[10px] text-foreground-muted">
          {protocolOnly
            ? t("protocolOnlyDescription")
            : category || "Unknown category"}
        </div>
      </div>
    </div>
  );
}
