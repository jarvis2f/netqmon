"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  Database,
  ExternalLink,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { MetricCard } from "@/components/data/metric-card";
import { ApplicationIdentity } from "@/components/network/application-identity";
import { DotStatus } from "@/components/network/status-badge";
import { FlowPanel } from "@/components/overlays/flow-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import {
  TrafficChart,
  type TrafficDataPoint,
} from "@/components/data/traffic-chart";
import { buttonVariants } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  cloudflareDomainUrl,
  formatBytes,
  formatIdentifier,
  formatPackets,
  formatTimestamp,
  ipInfoUrl,
  isLocalIp,
  splitBitrate,
} from "@/lib/formatters";
import type {
  ApiEnvelope,
  ApplicationSummary,
  ClientSummary,
  DestinationSummary,
  DomainSummary,
  FlowSummary,
} from "@/lib/network-types";

type Tab = "overview" | "applications" | "domains" | "destinations" | "flows";
interface Address {
  ip: string;
  ip_version: number;
  first_seen: number;
  last_seen: number;
  self_host_application?: ClientSummary["self_host_application"];
}
interface ClientDetailPayload {
  client: ClientSummary & { first_seen: number };
  addresses: Address[];
}
interface TrafficPayload {
  bucket_ms: number;
  points: Array<{
    timestamp: number;
    upload_bytes: number;
    download_bytes: number;
  }>;
}
interface Throughput {
  upload_bytes_per_second: number;
  download_bytes_per_second: number;
}
type Scope = "internet" | "internal" | "tunnel" | "all";
interface ScopedThroughput {
  internet: Throughput;
  internal: Throughput;
  tunnel: Throughput;
  unknown: Throughput;
}
interface RealtimeFlow {
  client_ip: string;
  scope?: string;
}
interface RealtimeSnapshot {
  generated_at: number;
  clients: Record<string, Throughput>;
  client_scopes?: Record<string, ScopedThroughput>;
  active_flows: RealtimeFlow[];
}
interface DetailData {
  detail: ClientDetailPayload;
  traffic: TrafficPayload;
  applications: ApplicationSummary[];
  domains: DomainSummary[];
  destinations: DestinationSummary[];
  flows: FlowSummary[];
}
type DeviceEvidence = Record<string, string | number | boolean | null>;

function identityValue(
  client: ClientSummary | undefined,
  key: "vendor" | "device_type" | "os_family" | "model",
) {
  if (!client) return null;
  return client.identity?.[key] ?? (key === "vendor" ? client.vendor : null);
}

function identityConfidence(
  client: ClientSummary,
  key: "vendor" | "device_type" | "os_family" | "model",
) {
  const confidenceKey =
    key === "os_family" ? "os_confidence" : (`${key}_confidence` as const);
  const confidence = client.identity?.[confidenceKey];
  return typeof confidence === "number"
    ? `${Math.round(confidence * 100)}%`
    : "—";
}

function evidenceValue(evidence: DeviceEvidence, key: string) {
  const value = evidence[key];
  return value === null || value === undefined || value === ""
    ? null
    : String(value);
}

export function ClientDetailDashboard({
  username,
  clientId,
  initialTab,
}: {
  username: string;
  clientId: number;
  initialTab: Tab;
}) {
  const t = useTranslations("clients");
  const tNav = useTranslations("navigation");
  const tFlows = useTranslations("flows.columns");
  const tStatus = useTranslations("common.status");
  const router = useRouter();

  const [data, setData] = useState<DetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [realtime, setRealtime] = useState<Throughput | null>(null);
  const [activeFlows, setActiveFlows] = useState(0);
  const [realtimePoints, setRealtimePoints] = useState<TrafficDataPoint[]>([]);
  const [scope, setScope] = useState<Scope>("internet");
  const [scopeRates, setScopeRates] = useState<ScopedThroughput | null>(null);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "overview", label: t("detail.tabs.overview") },
    { id: "applications", label: t("detail.tabs.applications") },
    { id: "domains", label: t("detail.tabs.domains") },
    { id: "destinations", label: t("detail.tabs.destinations") },
    { id: "flows", label: t("detail.tabs.flows") },
  ];

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const base = `/api/clients/${clientId}`;
        const responses = await Promise.all([
          fetch(base, { cache: "no-store", signal: controller.signal }),
          fetch(`${base}/traffic?limit=100&scope=${scope}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`${base}/applications?limit=100&scope=${scope}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`${base}/domains?limit=100&scope=${scope}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`${base}/destinations?limit=100&scope=${scope}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`${base}/flows?limit=100&scope=${scope}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
        ]);
        const envelopes = (await Promise.all(
          responses.map((response) => response.json()),
        )) as Array<ApiEnvelope<unknown>>;
        const failed = responses.findIndex((response) => !response.ok);
        if (failed >= 0)
          throw new Error(
            envelopes[failed].error?.message ??
              `Client detail request failed (${responses[failed].status})`,
          );
        setData({
          detail: envelopes[0].data as ClientDetailPayload,
          traffic: envelopes[1].data as TrafficPayload,
          applications: envelopes[2].data as ApplicationSummary[],
          domains: envelopes[3].data as DomainSummary[],
          destinations: envelopes[4].data as DestinationSummary[],
          flows: envelopes[5].data as FlowSummary[],
        });
        setError(null);
      } catch (loadError) {
        if (!controller.signal.aborted)
          setError(
            loadError instanceof Error ? loadError.message : t("unavailable"),
          );
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [clientId, reloadKey, scope, t]);

  const applySnapshot = useCallback(
    (snapshot: RealtimeSnapshot) => {
      if (!data) return;
      const rates = snapshot.client_scopes?.[data.detail.client.mac] ?? null;
      setScopeRates(rates);
      const client =
        scope === "all"
          ? (snapshot.clients[data.detail.client.mac] ?? null)
          : (rates?.[scope] ?? null);
      setRealtime(client);
      const addresses = new Set(
        data.detail.addresses.map((address) => address.ip),
      );
      setActiveFlows(
        snapshot.active_flows.filter(
          (flow) =>
            addresses.has(flow.client_ip) &&
            (scope === "all" || flow.scope === scope),
        ).length,
      );
      if (client)
        setRealtimePoints((points) =>
          [
            ...points,
            {
              timestamp: snapshot.generated_at,
              downloadBps: client.download_bytes_per_second * 8,
              uploadBps: client.upload_bytes_per_second * 8,
            },
          ].slice(-900),
        );
    },
    [data, scope],
  );

  useEffect(() => {
    if (!data) return;
    const events = new EventSource("/api/realtime");
    events.onopen = () => setStreamConnected(true);
    events.addEventListener("snapshot", (event) => {
      try {
        applySnapshot(JSON.parse(event.data) as RealtimeSnapshot);
      } catch {
        setStreamConnected(false);
      }
    });
    events.onerror = () => setStreamConnected(false);
    return () => events.close();
  }, [applySnapshot, data]);

  const client = data?.detail.client;
  const identityEvidence = client?.identity?.evidence ?? [];
  const online = Boolean(streamConnected && realtime);
  const downloadRate = splitBitrate(
    (realtime?.download_bytes_per_second ?? 0) * 8,
  );
  const uploadRate = splitBitrate((realtime?.upload_bytes_per_second ?? 0) * 8);
  const historical = useMemo<TrafficDataPoint[]>(
    () =>
      (data?.traffic.points ?? []).map((point) => ({
        timestamp: point.timestamp,
        downloadBps:
          point.download_bytes *
          8 *
          (60_000 / (data?.traffic.bucket_ms ?? 60_000)),
        uploadBps:
          point.upload_bytes *
          8 *
          (60_000 / (data?.traffic.bucket_ms ?? 60_000)),
      })),
    [data],
  );
  const selectedTraffic = useMemo(
    () =>
      (data?.traffic.points ?? []).reduce(
        (sum, point) => sum + point.upload_bytes + point.download_bytes,
        0,
      ),
    [data],
  );
  const scopeMix = useMemo(() => {
    if (!scopeRates) return [];
    const values = (["internet", "internal", "tunnel"] as const).map((id) => ({
      id,
      bytes:
        scopeRates[id].upload_bytes_per_second +
        scopeRates[id].download_bytes_per_second,
    }));
    const total = values.reduce((sum, item) => sum + item.bytes, 0);
    return values.map((item) => ({
      ...item,
      percent: total > 0 ? Math.round((item.bytes * 100) / total) : 0,
    }));
  }, [scopeRates]);
  const setTab = (tab: Tab) =>
    router.replace(`/clients/${clientId}?tab=${tab}`, { scroll: false });

  const applicationColumns: ColumnDef<ApplicationSummary>[] = [
    {
      id: "application",
      header: t("columns.name"),
      cell: (row) => (
        <ApplicationIdentity
          id={row.application_id}
          name={row.name}
          category={row.category_id}
          icon={row.icon}
        />
      ),
    },
    {
      id: "download",
      header: t("columns.download"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes),
    },
    {
      id: "upload",
      header: t("columns.upload"),
      align: "right",
      cell: (row) => formatBytes(row.upload_bytes),
    },
    {
      id: "flows",
      header: t("columns.flows"),
      align: "right",
      cell: (row) => formatPackets(row.flow_count),
    },
    {
      id: "last_seen",
      header: t("columns.lastSeen"),
      align: "right",
      cell: (row) => formatTimestamp(row.last_seen, "relative"),
    },
  ];
  const domainColumns: ColumnDef<DomainSummary>[] = [
    {
      id: "domain",
      header: "Domain",
      cell: (row) => (
        <a
          href={cloudflareDomainUrl(row.domain)}
          target="_blank"
          rel="noopener noreferrer"
          className="group inline-flex items-center gap-1 font-medium text-foreground hover:text-accent hover:underline"
        >
          <span>{row.domain}</span>
          <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
        </a>
      ),
    },
    {
      id: "download",
      header: t("columns.download"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes),
    },
    {
      id: "upload",
      header: t("columns.upload"),
      align: "right",
      cell: (row) => formatBytes(row.upload_bytes),
    },
    {
      id: "flows",
      header: t("columns.flows"),
      align: "right",
      cell: (row) => formatPackets(row.flow_count),
    },
    {
      id: "last_seen",
      header: t("columns.lastSeen"),
      align: "right",
      cell: (row) => formatTimestamp(row.last_seen, "relative"),
    },
  ];
  const destinationColumns: ColumnDef<DestinationSummary>[] = [
    {
      id: "destination",
      header: "Destination",
      cell: (row) => (
        <div>
          {row.domain ? (
            <a
              href={cloudflareDomainUrl(row.domain)}
              target="_blank"
              rel="noopener noreferrer"
              className="group inline-flex items-center gap-1 font-medium text-foreground hover:text-accent hover:underline"
            >
              <span>{row.domain}</span>
              <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
            </a>
          ) : !isLocalIp(row.remote_ip) ? (
            <a
              href={ipInfoUrl(row.remote_ip)}
              target="_blank"
              rel="noopener noreferrer"
              className="group inline-flex items-center gap-1 font-mono font-medium text-foreground hover:text-accent hover:underline"
              title={row.remote_ip}
            >
              <span>{row.remote_ip}</span>
              <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
            </a>
          ) : (
            <div className="font-mono">{row.remote_ip}</div>
          )}
          {row.domain && (
            <div className="font-mono text-[10px] text-foreground-muted">
              {row.remote_ip}
            </div>
          )}
        </div>
      ),
    },
    {
      id: "download",
      header: t("columns.download"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes),
    },
    {
      id: "upload",
      header: t("columns.upload"),
      align: "right",
      cell: (row) => formatBytes(row.upload_bytes),
    },
    {
      id: "flows",
      header: t("columns.flows"),
      align: "right",
      cell: (row) => formatPackets(row.flow_count),
    },
    {
      id: "last_seen",
      header: t("columns.lastSeen"),
      align: "right",
      cell: (row) => formatTimestamp(row.last_seen, "relative"),
    },
  ];
  const flowColumns: ColumnDef<FlowSummary>[] = [
    {
      id: "time",
      header: tFlows("time"),
      cell: (row) => formatTimestamp(row.last_seen, "table"),
    },
    {
      id: "application",
      header: tFlows("classification"),
      cell: (row) =>
        row.application === "unknown"
          ? tStatus("unknown")
          : row.application_name || formatIdentifier(row.application),
    },
    {
      id: "destination",
      header: tFlows("destination"),
      cell: (row) => (
        <div>
          {row.domain ? (
            <div>{row.domain}</div>
          ) : !isLocalIp(row.remote_ip) ? (
            <a
              href={ipInfoUrl(row.remote_ip)}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="group inline-flex items-center gap-1 font-mono text-foreground hover:text-accent hover:underline"
              title={row.remote_ip}
            >
              <span>{row.remote_ip}</span>
              <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
            </a>
          ) : (
            <div className="font-mono">{row.remote_ip}</div>
          )}
          {row.domain && (
            <div className="font-mono text-[10px] text-foreground-muted">
              {row.remote_ip}
            </div>
          )}
        </div>
      ),
    },
    {
      id: "protocol",
      header: tFlows("transport"),
      cell: (row) =>
        row.protocol === 6
          ? "TCP"
          : row.protocol === 17
            ? "UDP"
            : String(row.protocol),
    },
    {
      id: "download",
      header: t("columns.download"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes),
    },
    {
      id: "upload",
      header: t("columns.upload"),
      align: "right",
      cell: (row) => formatBytes(row.upload_bytes),
    },
  ];

  const tabContent = () => {
    if (!data) return null;
    if (initialTab === "applications")
      return (
        <DataTable
          columns={applicationColumns}
          data={data.applications}
          keyExtractor={(row) => row.application_id}
          onRowClick={(row) =>
            router.push(
              `/applications?id=${encodeURIComponent(row.application_id)}`,
            )
          }
          emptyState={
            <EmptyState
              title={t("detail.empty.noApps")}
              description={t("detail.empty.noAppsDesc")}
              className="border-0 bg-transparent"
            />
          }
        />
      );
    if (initialTab === "domains")
      return (
        <DataTable
          columns={domainColumns}
          data={data.domains}
          keyExtractor={(row) => row.domain}
          emptyState={
            <EmptyState
              title={t("detail.empty.noDomains")}
              description={t("detail.empty.noDomainsDesc")}
              className="border-0 bg-transparent"
            />
          }
        />
      );
    if (initialTab === "destinations")
      return (
        <DataTable
          columns={destinationColumns}
          data={data.destinations}
          keyExtractor={(row) => row.remote_ip}
          emptyState={
            <EmptyState
              title={t("detail.empty.noDestinations")}
              description={t("detail.empty.noDestinationsDesc")}
              className="border-0 bg-transparent"
            />
          }
        />
      );
    if (initialTab === "flows")
      return (
        <DataTable
          columns={flowColumns}
          data={data.flows}
          keyExtractor={(row) => row.id}
          onRowClick={setSelectedFlow}
          emptyState={
            <EmptyState
              title={t("detail.empty.noFlows")}
              description={t("detail.empty.noFlowsDesc")}
              className="border-0 bg-transparent"
            />
          }
        />
      );
    return null;
  };

  return (
    <AppLayout
      title={
        client?.self_host_application
          ? formatIdentifier(client.self_host_application.application_id)
          : client?.name || t("detail.title")
      }
      subtitle={
        client
          ? `${data?.detail.addresses[0]?.ip || "IP unknown"} · ${client.mac} · ${identityValue(client, "vendor") || tStatus("unknown")}`
          : t("detail.fallbackSubtitle")
      }
      username={username}
      isLive={streamConnected && online}
      headerActions={
        <Link
          href="/clients"
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          <ArrowLeft /> {tNav("clients")}
        </Link>
      }
      toolbar={
        <nav
          className="flex min-w-max items-center gap-1"
          aria-label={t("detail.fallbackSubtitle")}
        >
          <DotStatus status={online ? "online" : "offline"} />
          <div className="mx-2 h-5 w-px bg-border" />
          <Select
            value={scope}
            onValueChange={(value) => {
              setScope(value as Scope);
              setRealtimePoints([]);
            }}
          >
            <SelectTrigger className="h-8 w-32 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="internet">
                {t("detail.scopes.internet")}
              </SelectItem>
              <SelectItem value="internal">
                {t("detail.scopes.internal")}
              </SelectItem>
              <SelectItem value="tunnel">
                {t("detail.scopes.tunnel")}
              </SelectItem>
              <SelectItem value="all">{t("detail.scopes.all")}</SelectItem>
            </SelectContent>
          </Select>
          <Tabs
            value={initialTab}
            onValueChange={(val) => setTab(val as Tab)}
            variant="pill"
          >
            <TabsList className="h-8 p-0.5 bg-surface-subtle/80">
              {tabs.map((tab) => (
                <TabsTrigger
                  key={tab.id}
                  value={tab.id}
                  className="h-7 px-2.5 text-xs"
                >
                  {tab.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </nav>
      }
    >
      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={`Client ${clientId}`}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : initialTab === "overview" ? (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              label={t("detail.realtimeDownload", {
                scope: t(`detail.scopes.${scope}`),
              })}
              value={online && realtime ? downloadRate.value : "—"}
              unit={online && realtime ? downloadRate.unit : ""}
              icon={ArrowDown}
              loading={loading}
              subtext={
                streamConnected
                  ? t("detail.latestInterval")
                  : t("detail.realtimeUnavailable")
              }
            />
            <MetricCard
              label={t("detail.realtimeUpload", {
                scope: t(`detail.scopes.${scope}`),
              })}
              value={online && realtime ? uploadRate.value : "—"}
              unit={online && realtime ? uploadRate.unit : ""}
              icon={ArrowUp}
              loading={loading}
              subtext={
                streamConnected
                  ? t("detail.latestInterval")
                  : t("detail.realtimeUnavailable")
              }
            />
            <MetricCard
              label={t("detail.activeFlows")}
              value={
                online && streamConnected ? activeFlows.toLocaleString() : "—"
              }
              icon={Activity}
              loading={loading}
              subtext={t("detail.currentSessions")}
            />
            <MetricCard
              label={t("detail.totalToday")}
              value={formatBytes(selectedTraffic)}
              icon={Database}
              loading={loading}
              subtext={t("detail.recordedTraffic", {
                scope: t(`detail.scopes.${scope}`),
              })}
            />
          </div>
          <div className="rounded-md border border-border bg-surface p-4">
            <div className="mb-3 text-xs font-semibold">
              {t("detail.scopeMix")}
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              {scopeMix.map((item) => (
                <div key={item.id}>
                  <div className="flex items-center justify-between text-xs">
                    <span>{t(`detail.scopes.${item.id}`)}</span>
                    <span className="font-mono font-semibold">
                      {item.percent}%
                    </span>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-subtle">
                    <div
                      className="h-full rounded-full bg-accent"
                      style={{ width: `${item.percent}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <TrafficChart
            data={realtimePoints}
            title={t("detail.realtimeTraffic15m")}
            height={270}
            loading={loading}
            maxPoints={900}
            emptyMessage={
              online ? t("detail.waitingTraffic") : t("detail.clientOffline")
            }
          />
          <TrafficChart
            data={historical}
            title={t("detail.trafficHistory24h")}
            height={270}
            loading={loading}
            maxPoints={200}
          />
          {client && (
            <div className="rounded-md border border-border bg-surface p-4">
              <h2 className="mb-3 text-xs font-semibold">
                {t("detail.identity")}
              </h2>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {[
                  [
                    t("properties.vendor"),
                    identityValue(client, "vendor"),
                    identityConfidence(client, "vendor"),
                  ],
                  [
                    t("properties.deviceType"),
                    identityValue(client, "device_type"),
                    identityConfidence(client, "device_type"),
                  ],
                  [
                    t("properties.osFamily"),
                    identityValue(client, "os_family"),
                    identityConfidence(client, "os_family"),
                  ],
                  [
                    t("properties.model"),
                    identityValue(client, "model"),
                    identityConfidence(client, "model"),
                  ],
                  [
                    t("properties.privateMac"),
                    client.identity?.private_mac
                      ? t("properties.yes")
                      : t("properties.no"),
                    client.identity?.confidence,
                  ],
                ].map(([label, value, confidence]) => (
                  <div key={label} className="min-w-0">
                    <div className="text-[10px] uppercase tracking-wider text-foreground-muted">
                      {label}
                    </div>
                    <div className="mt-1 truncate text-sm font-medium">
                      {value || tStatus("unknown")}
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-foreground-muted">
                      {confidence || tStatus("unknown")}
                    </div>
                  </div>
                ))}
              </div>
              {identityEvidence.length > 0 && (
                <div className="mt-4 overflow-x-auto rounded border border-border">
                  <div className="grid min-w-[760px] grid-cols-[1fr_1fr_1.4fr_0.8fr_0.7fr_1.2fr] gap-2 border-b border-border bg-surface-subtle px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
                    <span>{t("detail.evidence.source")}</span>
                    <span>{t("detail.evidence.field")}</span>
                    <span>{t("detail.evidence.value")}</span>
                    <span>{t("detail.evidence.confidence")}</span>
                    <span>{t("detail.evidence.hitCount")}</span>
                    <span>{t("detail.evidence.observedAt")}</span>
                  </div>
                  {identityEvidence.map((evidence, index) => {
                    const observedAt = Number(
                      evidence.last_seen ?? evidence.observed_at ?? 0,
                    );
                    return (
                      <div
                        key={`${evidenceValue(evidence, "source")}-${evidenceValue(evidence, "field")}-${index}`}
                        className="grid min-w-[760px] grid-cols-[1fr_1fr_1.4fr_0.8fr_0.7fr_1.2fr] gap-2 border-b border-border px-3 py-2 text-xs last:border-b-0"
                      >
                        <span className="truncate text-foreground-secondary">
                          {evidenceValue(evidence, "source") ||
                            tStatus("unknown")}
                        </span>
                        <span className="truncate font-mono text-[11px]">
                          {evidenceValue(evidence, "field") ||
                            tStatus("unknown")}
                        </span>
                        <span className="truncate font-medium">
                          {evidenceValue(evidence, "value") ||
                            tStatus("unknown")}
                        </span>
                        <span className="font-mono text-[11px]">
                          {evidenceValue(evidence, "confidence") ||
                            tStatus("unknown")}
                        </span>
                        <span className="font-mono text-[11px]">
                          {evidenceValue(evidence, "hit_count") || "1"}
                        </span>
                        <span className="truncate text-foreground-muted">
                          {observedAt > 0
                            ? formatTimestamp(observedAt, "date")
                            : tStatus("unknown")}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
          {data && (
            <div className="rounded-md border border-border bg-surface p-4">
              <h2 className="mb-2 text-xs font-semibold">
                {t("detail.knownAddresses")}
              </h2>
              <div className="flex flex-wrap gap-2">
                {data.detail.addresses.map((address) => (
                  <span
                    key={address.ip}
                    className="rounded border border-border bg-surface-subtle px-2 py-1 font-mono text-[11px]"
                  >
                    IPv{address.ip_version} · {address.ip}
                    {address.self_host_application
                      ? ` · ${formatIdentifier(address.self_host_application.application_id)} (${Math.round(address.self_host_application.confidence * 100)}%)`
                      : ""}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      ) : loading ? (
        <DataTable
          columns={flowColumns}
          data={[]}
          keyExtractor={(row) => row.id}
          loading
        />
      ) : (
        tabContent()
      )}
      <FlowPanel flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
    </AppLayout>
  );
}
