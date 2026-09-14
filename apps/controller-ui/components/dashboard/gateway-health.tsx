"use client";

import { AlertTriangle, CheckCircle2, RadioTower } from "lucide-react";
import { useTranslations } from "next-intl";
import { StatusBadge } from "@/components/network/status-badge";
import { Card } from "@/components/ui/card";
import { SimpleTooltip } from "@/components/ui/tooltip";
import { formatTimestamp } from "@/lib/formatters";

export interface GatewayHealthData {
  id: string;
  name: string;
  status: "online" | "offline" | "degraded";
  last_seen: number;
  agent_version: string;
  kernel_version: string;
  openwrt_version: string;
  offloading_status: string;
  capture_interface?: string;
  capture_interfaces?: string[];
  interface_counter_sanity?: string;
  interface_delta_bytes?: number;
  flow_delta_bytes?: number;
  capture_warning: string | null;
  offline_after_ms: number;
}

export function GatewayHealth({
  gateway,
}: {
  gateway: GatewayHealthData | null;
}) {
  const t = useTranslations("overview");
  const tStatus = useTranslations("common.status");

  const valueOrUnknown = (value: string) => value || tStatus("unknown");

  return (
    <Card className="p-4" aria-labelledby="gateway-health-title">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
        <div className="flex items-center gap-2">
          <RadioTower
            className="size-4 text-foreground-muted"
            aria-hidden="true"
          />
          <div>
            <h3
              id="gateway-health-title"
              className="text-xs font-semibold tracking-tight text-foreground"
            >
              {t("gatewayHealth")}
            </h3>
            <p className="mt-0.5 text-[11px] text-foreground-muted">
              {gateway?.name ?? t("noGatewayEnrolled")}
            </p>
          </div>
        </div>
        <StatusBadge status={gateway?.status ?? "unknown"} />
      </div>

      <dl className="grid grid-cols-2 gap-x-5 gap-y-3 py-3 text-xs md:grid-cols-6">
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("lastSeen")}
          </dt>
          <SimpleTooltip
            content={formatTimestamp(gateway?.last_seen, "tooltip")}
          >
            <dd className="mt-1 font-medium tabular-nums text-foreground cursor-default">
              {formatTimestamp(gateway?.last_seen, "relative")}
            </dd>
          </SimpleTooltip>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("openwrt")}
          </dt>
          <SimpleTooltip content={gateway?.openwrt_version}>
            <dd className="mt-1 truncate font-mono text-foreground cursor-default">
              {valueOrUnknown(gateway?.openwrt_version ?? "")}
            </dd>
          </SimpleTooltip>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("kernel")}
          </dt>
          <SimpleTooltip content={gateway?.kernel_version}>
            <dd className="mt-1 truncate font-mono text-foreground cursor-default">
              {valueOrUnknown(gateway?.kernel_version ?? "")}
            </dd>
          </SimpleTooltip>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("agent")}
          </dt>
          <dd className="mt-1 truncate font-mono text-foreground">
            {valueOrUnknown(gateway?.agent_version ?? "")}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("offloading")}
          </dt>
          <dd className="mt-1 font-medium capitalize text-foreground">
            {valueOrUnknown(gateway?.offloading_status ?? "")}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
            {t("counterCheck")}
          </dt>
          <SimpleTooltip
            content={(gateway?.capture_interfaces?.length
              ? gateway.capture_interfaces
              : [gateway?.capture_interface]
            )
              .filter(Boolean)
              .join(", ")}
          >
            <dd className="mt-1 font-medium capitalize text-foreground cursor-default">
              {valueOrUnknown(gateway?.interface_counter_sanity ?? "")}
            </dd>
          </SimpleTooltip>
        </div>
      </dl>

      <div className="flex items-start gap-2 border-t border-border pt-3 text-[11px]">
        {gateway?.capture_warning ? (
          <>
            <AlertTriangle
              className="mt-0.5 size-3.5 shrink-0 text-warning"
              aria-hidden="true"
            />
            <span className="text-warning">{gateway.capture_warning}</span>
          </>
        ) : (
          <>
            <CheckCircle2
              className="mt-0.5 size-3.5 shrink-0 text-success"
              aria-hidden="true"
            />
            <span className="text-foreground-muted">
              {t("noCaptureWarnings")}
            </span>
          </>
        )}
      </div>
    </Card>
  );
}
