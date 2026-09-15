"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, ArrowDown, ArrowUp, Users } from "lucide-react";
import { useLocale, useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { MetricCard } from "@/components/data/metric-card";
import { RankList, type RankItem } from "@/components/data/rank-list";
import {
  CategoryDistribution,
  type CategoryItem,
} from "@/components/data/category-distribution";
import {
  GatewayHealth,
  type GatewayHealthData,
} from "@/components/dashboard/gateway-health";
import { ApplicationIcon } from "@/components/icons/application-icon";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import { CountryFlag } from "@/components/icons/country-flag";
import {
  TrafficChart,
  type TrafficDataPoint,
} from "@/components/data/traffic-chart";
import { formatIdentifier, splitBitrate } from "@/lib/formatters";
import type { IconMetadata } from "@/lib/network-types";

const MAX_REALTIME_POINTS = 900;

interface Throughput {
  upload_bytes_per_second: number;
  download_bytes_per_second: number;
}

interface RealtimePoint extends Throughput {
  timestamp: number;
}

interface RealtimeSnapshot {
  generated_at: number;
  total: Throughput;
  internet: Throughput;
  internal: Throughput;
  tunnel: Throughput;
  unknown: Throughput;
  clients: Record<string, Throughput>;
  applications: Record<string, Throughput>;
  active_flows: Array<{ scope?: string }>;
  history: RealtimePoint[];
  gateway_health?: {
    observed_at: number;
    dropped_batches: number;
    dns_dropped_events: number;
    protocol_probe_dropped_events: number;
    agent_version: string;
    kernel_version: string;
    openwrt_version: string;
    hardware_flow_offload: "enabled" | "disabled" | "unknown";
    capture_interface: string;
    capture_interfaces?: string[];
    interface_delta_bytes: number;
    flow_delta_bytes: number;
    interface_counter_sanity: "ok" | "degraded" | "unknown" | "disabled";
  } | null;
}

interface OverviewData {
  gateway_status: string;
  realtime: RealtimeSnapshot;
  device_count: number;
  gateway: GatewayHealthData | null;
}

interface ApiEnvelope<T> {
  schema_version: number;
  data: T;
}

interface SummaryItem {
  application_id?: string;
  category_id?: string;
  remote_ip?: string;
  id?: number;
  name?: string;
  mac?: string;
  country_code?: string | null;
  country_name?: string | null;
  domain?: string | null;
  icon?: IconMetadata | null;
  upload_bytes: number;
  download_bytes: number;
}

const EMPTY_SNAPSHOT: RealtimeSnapshot = {
  generated_at: 0,
  total: { upload_bytes_per_second: 0, download_bytes_per_second: 0 },
  internet: { upload_bytes_per_second: 0, download_bytes_per_second: 0 },
  internal: { upload_bytes_per_second: 0, download_bytes_per_second: 0 },
  tunnel: { upload_bytes_per_second: 0, download_bytes_per_second: 0 },
  unknown: { upload_bytes_per_second: 0, download_bytes_per_second: 0 },
  clients: {},
  applications: {},
  active_flows: [],
  history: [],
  gateway_health: null,
};

function metricRate(bytesPerSecond: number, available: boolean) {
  return available
    ? splitBitrate(bytesPerSecond * 8)
    : { value: "—", unit: "" };
}

export function OverviewDashboard({ username }: { username: string }) {
  const t = useTranslations("overview");
  const tNav = useTranslations("navigation");
  const locale = useLocale();
  const router = useRouter();

  const [snapshot, setSnapshot] = useState<RealtimeSnapshot>(EMPTY_SNAPSHOT);
  const [deviceCount, setDeviceCount] = useState<number | null>(null);
  const [gatewayStatus, setGatewayStatus] = useState<
    "online" | "offline" | "degraded"
  >("offline");
  const [streamConnected, setStreamConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [topApplications, setTopApplications] = useState<RankItem[]>([]);
  const [topClients, setTopClients] = useState<RankItem[]>([]);
  const [topDestinations, setTopDestinations] = useState<RankItem[]>([]);
  const [categories, setCategories] = useState<CategoryItem[]>([]);
  const [gateway, setGateway] = useState<GatewayHealthData | null>(null);
  const mounted = useRef(true);

  const rankItems = useCallback(
    (
      items: SummaryItem[],
      kind: "application" | "client" | "destination",
    ): RankItem[] => {
      const total = items.reduce(
        (sum, item) => sum + item.upload_bytes + item.download_bytes,
        0,
      );
      return items.map((item) => {
        const value = item.upload_bytes + item.download_bytes;
        if (kind === "application") {
          const id = item.application_id ?? "unknown";
          return {
            id,
            name: item.name || formatIdentifier(id),
            subtitle: item.category_id ?? t("other"),
            value,
            percentage: total ? value / total : 0,
            icon: <ApplicationIcon applicationId={id} icon={item.icon} />,
          };
        }
        if (kind === "client") {
          const id = String(item.id ?? item.mac ?? "unknown");
          return {
            id,
            name: item.name || item.mac || t("unknownClient"),
            subtitle: item.mac,
            value,
            percentage: total ? value / total : 0,
            icon: (
              <ClientDeviceIcon
                client={{ name: item.name ?? item.mac, mac: item.mac }}
              />
            ),
          };
        }
        const id = item.remote_ip ?? "unknown";
        const country = item.country_name || item.country_code;
        return {
          id,
          name: item.domain || id,
          subtitle: country || t("destination"),
          value,
          percentage: total ? value / total : 0,
          icon: <CountryFlag code={item.country_code} />,
        };
      });
    },
    [t],
  );

  const categoryItems = useCallback(
    (items: SummaryItem[]): CategoryItem[] => {
      const totals = new Map<string, number>();
      for (const item of items) {
        const category = item.category_id || "unknown";
        totals.set(
          category,
          (totals.get(category) ?? 0) + item.upload_bytes + item.download_bytes,
        );
      }
      const sorted = [...totals.entries()].sort(
        (left, right) => right[1] - left[1],
      );
      if (sorted.length <= 6)
        return sorted.map(([id, value]) => ({ id, name: id, value }));
      const visible = sorted
        .slice(0, 5)
        .map(([id, value]) => ({ id, name: id, value }));
      visible.push({
        id: "other",
        name: t("other"),
        value: sorted.slice(5).reduce((sum, [, value]) => sum + value, 0),
      });
      return visible;
    },
    [t],
  );

  const applySnapshot = useCallback(
    (next: RealtimeSnapshot) => {
      setSnapshot({
        ...next,
        history: next.history.slice(-MAX_REALTIME_POINTS),
      });
      if (next.generated_at) {
        setGateway((current) => {
          if (!current) return current;
          const online =
            Date.now() - next.generated_at <= current.offline_after_ms;
          const health = next.gateway_health;
          const captureReasons = health
            ? [
                ...(health.hardware_flow_offload === "enabled"
                  ? [t("captureDegradedHfo")]
                  : []),
                ...(health.dropped_batches
                  ? [
                      t("captureDegradedBatches", {
                        count: health.dropped_batches,
                      }),
                    ]
                  : []),
                ...(health.dns_dropped_events
                  ? [
                      t("captureDegradedDns", {
                        count: health.dns_dropped_events,
                      }),
                    ]
                  : []),
                ...(health.protocol_probe_dropped_events
                  ? [
                      t("captureDegradedProbes", {
                        count: health.protocol_probe_dropped_events,
                      }),
                    ]
                  : []),
                ...(health.interface_counter_sanity === "degraded"
                  ? [
                      t("captureDegradedCounters", {
                        interfaceDelta: health.interface_delta_bytes,
                        flowDelta: health.flow_delta_bytes,
                      }),
                    ]
                  : []),
              ]
            : [];
          return {
            ...current,
            status: online ? "online" : "offline",
            last_seen: next.generated_at,
            agent_version:
              next.gateway_health?.agent_version || current.agent_version,
            kernel_version:
              next.gateway_health?.kernel_version || current.kernel_version,
            openwrt_version:
              next.gateway_health?.openwrt_version || current.openwrt_version,
            offloading_status:
              health?.hardware_flow_offload || current.offloading_status,
            capture_interface:
              health?.capture_interface || current.capture_interface,
            capture_interfaces: health?.capture_interfaces?.length
              ? health.capture_interfaces
              : current.capture_interfaces,
            interface_counter_sanity:
              health?.interface_counter_sanity ||
              current.interface_counter_sanity,
            interface_delta_bytes:
              health?.interface_delta_bytes ?? current.interface_delta_bytes,
            flow_delta_bytes:
              health?.flow_delta_bytes ?? current.flow_delta_bytes,
            capture_warning: online
              ? health
                ? captureReasons.length
                  ? t("captureDegradedPrefix", {
                      reasons: captureReasons.join("; "),
                    })
                  : null
                : t("captureNoTelemetry")
              : t("offlineThreshold"),
          };
        });
      }
    },
    [t],
  );

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();

    async function loadOverview() {
      try {
        const [overviewRes, appsRes, clientsRes, destsRes] = await Promise.all([
          fetch("/api/overview", { signal: controller.signal }),
          fetch("/api/applications?limit=5", { signal: controller.signal }),
          fetch("/api/clients?limit=5", { signal: controller.signal }),
          fetch(
            `/api/destinations?limit=5&lang=${encodeURIComponent(locale)}`,
            { signal: controller.signal },
          ),
        ]);

        if (overviewRes.ok) {
          const payload =
            (await overviewRes.json()) as ApiEnvelope<OverviewData>;
          if (mounted.current && payload.data) {
            setGateway(payload.data.gateway);
            applySnapshot(payload.data.realtime);
            setDeviceCount(payload.data.device_count);
            setGatewayStatus(
              payload.data.gateway_status as "online" | "offline" | "degraded",
            );
          }
        }

        if (appsRes.ok) {
          const payload = (await appsRes.json()) as ApiEnvelope<
            { items?: SummaryItem[] } | SummaryItem[]
          >;
          const items = Array.isArray(payload.data)
            ? payload.data
            : (payload.data?.items ?? []);
          if (mounted.current) {
            setTopApplications(rankItems(items, "application"));
            setCategories(categoryItems(items));
          }
        }

        if (clientsRes.ok) {
          const payload = (await clientsRes.json()) as ApiEnvelope<
            { items?: SummaryItem[] } | SummaryItem[]
          >;
          const items = Array.isArray(payload.data)
            ? payload.data
            : (payload.data?.items ?? []);
          if (mounted.current) setTopClients(rankItems(items, "client"));
        }

        if (destsRes.ok) {
          const payload = (await destsRes.json()) as ApiEnvelope<
            { items?: SummaryItem[] } | SummaryItem[]
          >;
          const items = Array.isArray(payload.data)
            ? payload.data
            : (payload.data?.items ?? []);
          if (mounted.current)
            setTopDestinations(rankItems(items, "destination"));
        }
      } catch (err) {
        if ((err as Error).name !== "AbortError" && mounted.current) {
          setError(t("loadError"));
          setGatewayStatus("offline");
        }
      } finally {
        if (mounted.current) setLoading(false);
      }
    }

    void loadOverview();
    const events = new EventSource("/api/realtime");
    events.onopen = () => {
      if (!mounted.current) return;
      setStreamConnected(true);
      setError(null);
    };
    events.addEventListener("snapshot", (event) => {
      if (!mounted.current) return;
      try {
        applySnapshot(JSON.parse(event.data) as RealtimeSnapshot);
      } catch {
        setError(t("decodeError"));
      }
    });
    events.addEventListener("gateway_status", (event) => {
      if (!mounted.current) return;
      try {
        const status = (JSON.parse(event.data) as { status?: string }).status;
        setGatewayStatus(status === "online" ? "online" : "degraded");
        setGateway((current) =>
          current
            ? {
                ...current,
                status: status === "online" ? "online" : "degraded",
              }
            : current,
        );
      } catch {
        setGatewayStatus("degraded");
      }
    });
    events.onerror = () => {
      if (!mounted.current) return;
      setStreamConnected(false);
    };

    return () => {
      mounted.current = false;
      controller.abort();
      events.close();
    };
  }, [applySnapshot, categoryItems, locale, rankItems, t]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setGateway((current) => {
        if (
          !current ||
          !current.last_seen ||
          Date.now() - current.last_seen <= current.offline_after_ms
        )
          return current;
        setGatewayStatus("offline");
        const warning = t("offlineThreshold");
        return current.status === "offline" &&
          current.capture_warning === warning
          ? current
          : { ...current, status: "offline", capture_warning: warning };
      });
    }, 5_000);
    return () => window.clearInterval(timer);
  }, [t]);

  const dataAvailable = gatewayStatus === "online" && snapshot.generated_at > 0;
  const download = metricRate(
    snapshot.internet.download_bytes_per_second,
    dataAvailable,
  );
  const upload = metricRate(
    snapshot.internet.upload_bytes_per_second,
    dataAvailable,
  );
  const activeInternetFlows = snapshot.active_flows.filter(
    (flow) => flow.scope === "internet",
  ).length;
  const trafficData: TrafficDataPoint[] = snapshot.history.map((point) => ({
    timestamp: point.timestamp,
    downloadBps: point.download_bytes_per_second * 8,
    uploadBps: point.upload_bytes_per_second * 8,
  }));

  return (
    <AppLayout
      title={tNav("overview")}
      subtitle={t("subtitle")}
      gatewayStatus={gatewayStatus}
      gatewayName={gateway?.name}
      isLive={streamConnected && gatewayStatus === "online"}
      username={username}
      warningBanner={error}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label={t("download")}
          value={download.value}
          unit={download.unit}
          icon={ArrowDown}
          loading={loading}
          subtext={dataAvailable ? t("realtime") : t("waitingTelemetry")}
        />
        <MetricCard
          label={t("upload")}
          value={upload.value}
          unit={upload.unit}
          icon={ArrowUp}
          loading={loading}
          subtext={dataAvailable ? t("realtime") : t("waitingTelemetry")}
        />
        <MetricCard
          label={t("activeFlows")}
          value={dataAvailable ? activeInternetFlows.toLocaleString() : "—"}
          icon={Activity}
          loading={loading}
          subtext={t("currentTrackedSessions")}
        />
        <MetricCard
          label={t("onlineClients")}
          value={
            dataAvailable
              ? Object.keys(snapshot.clients).length.toLocaleString()
              : "—"
          }
          icon={Users}
          loading={loading}
          subtext={
            dataAvailable
              ? t("seenLatestInterval")
              : deviceCount === null
                ? t("waitingTelemetry")
                : t("knownClients", { count: deviceCount })
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
        <TrafficChart
          data={trafficData}
          title={t("trafficLast15m")}
          height={300}
          loading={loading}
          emptyMessage={
            gatewayStatus === "online"
              ? t("waitingTraffic")
              : t("gatewayOffline")
          }
          className="min-w-0"
        />
        <CategoryDistribution
          items={categories}
          loading={loading}
          className="min-w-0 xl:min-h-[364px]"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <RankList
          title={t("topApplications")}
          items={topApplications}
          loading={loading}
          viewAllHref="/applications"
          onItemClick={(item) =>
            router.push(`/applications?id=${encodeURIComponent(item.id)}`)
          }
        />
        <RankList
          title={t("topClients")}
          items={topClients}
          loading={loading}
          viewAllHref="/clients"
          onItemClick={(item) =>
            router.push(`/clients?id=${encodeURIComponent(item.id)}`)
          }
        />
        <RankList
          title={t("topDestinations")}
          items={topDestinations}
          loading={loading}
          viewAllHref="/destinations"
          onItemClick={(item) =>
            router.push(`/destinations?id=${encodeURIComponent(item.id)}`)
          }
        />
      </div>

      <GatewayHealth gateway={gateway} />
    </AppLayout>
  );
}
