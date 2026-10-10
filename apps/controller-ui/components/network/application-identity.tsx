import { useTranslations } from "next-intl";
import { ProtocolIcon } from "@/components/icons/protocol-icon";
import { ApplicationIcon } from "@/components/icons/application-icon";
import {
  protocolApplicationName,
  protocolFromApplicationId,
} from "@/lib/application-identity";
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
  const protocol = protocolFromApplicationId(id);
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      {protocol ? (
        <ProtocolIcon protocol={protocol} size="md" />
      ) : (
        <ApplicationIcon
          applicationId={id}
          category={category}
          icon={icon}
          size="md"
        />
      )}
      <div className="min-w-0">
        <div className="truncate font-medium text-foreground">
          {protocol
            ? protocolApplicationName(id)
            : unknown
              ? "Unknown"
              : name || formatIdentifier(id)}
        </div>
        <div className="truncate text-[10px] text-foreground-muted">
          {protocol
            ? t("protocolApplicationDescription")
            : category || "Unknown category"}
        </div>
      </div>
    </div>
  );
}
