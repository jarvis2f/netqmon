"use client";

import { useTranslations } from "next-intl";
import { PropertyRow, SidePanel } from "@/components/overlays/side-panel";
import { StatusBadge } from "@/components/network/status-badge";
import {
  FlowDirection,
  type FlowDirectionType,
} from "@/components/network/flow-direction";
import {
  cloudflareDomainUrl,
  formatBytes,
  formatDuration,
  formatIdentifier,
  formatPackets,
  formatPercent,
  formatTimestamp,
  ipInfoUrl,
  isLocalIp,
} from "@/lib/formatters";
import type { FlowSummary } from "@/lib/network-types";
import { useTopologyLabels } from "@/hooks/use-topology-labels";

function protocolName(protocol: number) {
  if (protocol === 6) return "TCP";
  if (protocol === 17) return "UDP";
  return String(protocol);
}

function directionName(direction: number): FlowDirectionType {
  if (direction === 1) return "upload";
  if (direction === 2) return "download";
  return "unknown";
}

function evidenceItems(evidence?: unknown): string[] {
  if (!evidence) return [];
  if (Array.isArray(evidence)) {
    return evidence.map((value) =>
      typeof value === "string"
        ? value
        : (JSON.stringify(value) ?? String(value)),
    );
  }
  if (typeof evidence !== "string") {
    return [JSON.stringify(evidence)];
  }
  if (!evidence.trim()) return [];
  try {
    const parsed: unknown = JSON.parse(evidence);
    const values = Array.isArray(parsed) ? parsed : [parsed];
    return values.map((value) =>
      typeof value === "string"
        ? value
        : (JSON.stringify(value) ?? String(value)),
    );
  } catch {
    return [evidence];
  }
}

export function FlowPanel({
  flow,
  topologyMode = "",
  onClose,
}: {
  flow: FlowSummary | null;
  topologyMode?: string;
  onClose: () => void;
}) {
  const t = useTranslations("flows.panel");
  const tStatus = useTranslations("common.status");
  const topologyLabels = useTopologyLabels();

  if (!flow) return null;
  const duration = Math.max(
    0,
    ((flow.ended_at ?? flow.last_seen) - flow.started_at) / 1_000,
  );
  const evidence = evidenceItems(flow.evidence);
  const applicationName =
    flow.application === "unknown"
      ? tStatus("unknown")
      : flow.application_name || formatIdentifier(flow.application);

  const getResultLabel = () => {
    if (flow.application && flow.application !== "unknown") {
      return t("likelyApp", { app: applicationName });
    }
    if (flow.protocol_id && flow.protocol_id !== "unknown") {
      return t("protocolNamed", { protocol: flow.protocol_id });
    }
    if (flow.organization && flow.organization !== "unknown") {
      return t("organizationNamed", { org: flow.organization });
    }
    return tStatus("unknown");
  };

  return (
    <SidePanel
      open
      onClose={onClose}
      title={flow.domain || flow.remote_ip}
      subtitle={`${flow.client_ip} → ${flow.remote_ip}`}
      statusBadge={
        <StatusBadge
          status={flow.ended_at ? "offline" : "online"}
          label={flow.ended_at ? tStatus("ended") : tStatus("active")}
        />
      }
    >
      <section>
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
          {t("identity")}
        </h3>
        <PropertyRow
          label={t("client")}
          value={flow.client_name || flow.client_ip}
          copyable={!flow.client_name}
          mono={!flow.client_name}
        />
        {flow.client_name && (
          <PropertyRow
            label={t("clientIp")}
            value={flow.client_ip}
            copyable
            mono
          />
        )}
        <PropertyRow
          label={t("remote")}
          value={flow.remote_ip}
          href={
            !flow.domain && !isLocalIp(flow.remote_ip)
              ? ipInfoUrl(flow.remote_ip)
              : undefined
          }
          external={!flow.domain && !isLocalIp(flow.remote_ip)}
          copyable
          mono
        />
        <PropertyRow
          label={t("domain")}
          value={flow.domain || tStatus("unknown")}
          href={flow.domain ? cloudflareDomainUrl(flow.domain) : undefined}
          external
          copyable={Boolean(flow.domain)}
        />
        <PropertyRow
          label={t("organization")}
          value={flow.organization || tStatus("unknown")}
        />
        <PropertyRow label={t("application")} value={applicationName} />
        <PropertyRow
          label={t("trafficClass")}
          value={flow.category || tStatus("unknown")}
        />
        <PropertyRow
          label={t("trafficRole")}
          value={flow.traffic_role || tStatus("unknown")}
        />
      </section>
      <section>
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
          {t("networkPath")}
        </h3>
        <PropertyRow
          label={t("scope")}
          value={
            topologyLabels.value("scope", flow.scope) || tStatus("unknown")
          }
        />
        <PropertyRow
          label={t("path")}
          value={
            topologyLabels.value("path", flow.path_type) || tStatus("unknown")
          }
        />
        <PropertyRow
          label={t("sourceSegment")}
          value={flow.source_segment || tStatus("unknown")}
          mono
        />
        <PropertyRow
          label={t("destinationSegment")}
          value={
            flow.destination_segment ||
            (flow.scope === "internet" ? t("internet") : tStatus("unknown"))
          }
          mono
        />
        <PropertyRow
          label={t("nat")}
          value={topologyLabels.value("nat", flow.nat) || tStatus("unknown")}
        />
        <PropertyRow
          label={t("topology")}
          value={
            topologyLabels.value("mode", topologyMode) || tStatus("unknown")
          }
        />
      </section>
      <section>
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
          {t("session")}
        </h3>
        <PropertyRow
          label={t("transport")}
          value={protocolName(flow.protocol)}
          mono
        />
        <PropertyRow
          label={t("detectedProtocol")}
          value={flow.protocol_id || tStatus("unknown")}
          mono
        />
        <PropertyRow
          label={t("direction")}
          value={<FlowDirection direction={directionName(flow.direction)} />}
        />
        <PropertyRow label={t("clientPort")} value={flow.client_port} mono />
        <PropertyRow label={t("remotePort")} value={flow.remote_port} mono />
        <PropertyRow
          label={t("download")}
          value={formatBytes(flow.download_bytes)}
          mono
        />
        <PropertyRow
          label={t("upload")}
          value={formatBytes(flow.upload_bytes)}
          mono
        />
        <PropertyRow
          label={t("packets")}
          value={formatPackets(flow.packets)}
          mono
        />
        <PropertyRow
          label={t("started")}
          value={formatTimestamp(flow.started_at, "date")}
        />
        <PropertyRow
          label={t("lastSeen")}
          value={formatTimestamp(flow.last_seen, "date")}
        />
        <PropertyRow
          label={t("duration")}
          value={formatDuration(duration)}
          mono
        />
      </section>
      <section>
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
          {t("classification")}
        </h3>
        <PropertyRow label={t("result")} value={getResultLabel()} />
        <PropertyRow
          label={t("overallConfidence")}
          value={formatPercent(flow.confidence)}
          mono
        />
        <PropertyRow
          label={t("organizationConfidence")}
          value={formatPercent(flow.organization_confidence)}
          mono
        />
        <PropertyRow
          label={t("applicationConfidence")}
          value={formatPercent(flow.application_confidence)}
          mono
        />
        <PropertyRow
          label={t("protocolConfidence")}
          value={formatPercent(flow.protocol_confidence)}
          mono
        />
        <PropertyRow
          label={t("reason")}
          value={flow.reason || t("noMatchingRule")}
        />
        <div className="border-b border-border/50 py-1.5">
          <div className="mb-1.5 font-medium text-foreground-muted">
            {t("evidence")}
          </div>
          {evidence.length ? (
            <ul className="flex min-w-0 flex-col gap-1.5">
              {evidence.map((item, index) => (
                <li
                  key={`${item}-${index}`}
                  className="min-w-0 break-all rounded-md bg-surface-subtle px-2.5 py-2 font-mono text-[11px] leading-relaxed text-foreground"
                >
                  {item}
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-foreground-muted">{t("noEvidence")}</div>
          )}
        </div>
      </section>
    </SidePanel>
  );
}
