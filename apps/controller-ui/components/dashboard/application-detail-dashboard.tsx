"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  Info,
  Network,
  Users,
  ExternalLink,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { MetricCard } from "@/components/data/metric-card";
import { ApplicationIdentity } from "@/components/network/application-identity";
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
  cloudflareDomainUrl,
  formatBytes,
  formatPackets,
  formatPercent,
  formatTimestamp,
  ipInfoUrl,
  isLocalIp,
} from "@/lib/formatters";
import type {
  ApiEnvelope,
  ApplicationSummary,
  ClientSummary,
  DestinationSummary,
  DomainSummary,
  FlowSummary,
} from "@/lib/network-types";

type Tab = "overview" | "clients" | "domains" | "destinations" | "flows";

interface TrafficPayload {
  bucket_ms: number;
  points: Array<{
    timestamp: number;
    upload_bytes: number;
    download_bytes: number;
  }>;
}

interface DetailData {
  application: ApplicationSummary;
  traffic: TrafficPayload;
  clients: ClientSummary[];
  domains: DomainSummary[];
  destinations: DestinationSummary[];
  flows: FlowSummary[];
}

export function ApplicationDetailDashboard({
  username,
  applicationId,
  categoryId,
  initialTab,
}: {
  username: string;
  applicationId: string;
  categoryId?: string;
  initialTab: Tab;
}) {
  const t = useTranslations("applications");
  const tNav = useTranslations("navigation");
  const tFlows = useTranslations("flows.columns");
  const tStatus = useTranslations("common.status");
  const router = useRouter();

  const [data, setData] = useState<DetailData | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "overview", label: t("detail.tabs.overview") },
    { id: "clients", label: t("detail.tabs.clients") },
    { id: "domains", label: t("detail.tabs.domains") },
    { id: "destinations", label: t("detail.tabs.destinations") },
    { id: "flows", label: t("detail.tabs.flows") },
  ];

  const tabScope = {
    overview: {
      label: t("detail.tabs.overview"),
      description: t("detail.scope.tabs.overview"),
    },
    clients: {
      label: t("detail.tabs.clients"),
      description: t("detail.scope.tabs.clients"),
    },
    domains: {
      label: t("detail.tabs.domains"),
      description: t("detail.scope.tabs.domains"),
    },
    destinations: {
      label: t("detail.tabs.destinations"),
      description: t("detail.scope.tabs.destinations"),
    },
    flows: {
      label: t("detail.tabs.flows"),
      description: t("detail.scope.tabs.flows"),
    },
  }[initialTab];

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const encoded = encodeURIComponent(applicationId);
        const query = new URLSearchParams({ limit: "100" });
        if (categoryId) query.set("category", categoryId);
        const relationQuery = query.toString();
        const responses = await Promise.all([
          fetch(
            `/api/applications/${encoded}${categoryId ? `?category=${encodeURIComponent(categoryId)}` : ""}`,
            { cache: "no-store", signal: controller.signal },
          ),
          fetch(`/api/applications/${encoded}/traffic?${relationQuery}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`/api/applications/${encoded}/clients?${relationQuery}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`/api/applications/${encoded}/domains?${relationQuery}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`/api/applications/${encoded}/destinations?${relationQuery}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch(`/api/applications/${encoded}/flows?${relationQuery}`, {
            cache: "no-store",
            signal: controller.signal,
          }),
        ]);
        const envelopes = (await Promise.all(
          responses.map((response) => response.json()),
        )) as Array<ApiEnvelope<unknown>>;
        const failedIndex = responses.findIndex((response) => !response.ok);
        if (failedIndex >= 0)
          throw new Error(
            envelopes[failedIndex].error?.message ??
              `Application detail request failed (${responses[failedIndex].status})`,
          );
        setData({
          application: envelopes[0].data as ApplicationSummary,
          traffic: envelopes[1].data as TrafficPayload,
          clients: envelopes[2].data as ClientSummary[],
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
  }, [applicationId, categoryId, reloadKey, t]);

  const setTab = (tab: Tab) => {
    const query = new URLSearchParams({ tab });
    if (categoryId) query.set("category", categoryId);
    router.replace(
      `/applications/${encodeURIComponent(applicationId)}?${query}`,
      { scroll: false },
    );
  };
  const chartData = useMemo<TrafficDataPoint[]>(
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

  const clientColumns: ColumnDef<ClientSummary>[] = [
    {
      id: "name",
      header: t("columns.clients"),
      cell: (row) => (
        <div className="flex min-w-0 items-center gap-2">
          <ClientDeviceIcon client={row} size="md" />
          <div className="min-w-0">
            <div className="truncate font-medium">{row.name || row.mac}</div>
            <div className="truncate font-mono text-[10px] text-foreground-muted">
              {row.mac}
            </div>
          </div>
        </div>
      ),
    },
    {
      id: "vendor",
      header: "Vendor",
      cell: (row) => row.vendor || tStatus("unknown"),
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
            <div className="font-medium font-mono">{row.remote_ip}</div>
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
      id: "client",
      header: tFlows("client"),
      cell: (row) => <span className="font-mono">{row.client_ip}</span>,
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

  const tableForTab = () => {
    if (!data) return null;
    if (initialTab === "clients")
      return (
        <DataTable
          columns={clientColumns}
          data={data.clients}
          keyExtractor={(row) => row.id}
          onRowClick={(row) => router.push(`/clients?id=${row.id}`)}
          emptyState={
            <EmptyState
              title={t("detail.empty.noClients")}
              description={t("detail.empty.noClientsDesc")}
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

  const app = data?.application;
  return (
    <AppLayout
      title={
        app?.application_id === "unknown"
          ? t("detail.unknownApp")
          : (app?.application_id ?? applicationId)
      }
      subtitle={
        app
          ? t("detail.subtitle", {
              category: app.category_id,
              confidence: formatPercent(app.confidence ?? 0),
            })
          : t("detail.fallbackSubtitle")
      }
      username={username}
      isLive={false}
      headerActions={
        <Link
          href="/applications"
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          <ArrowLeft /> {tNav("applications")}
        </Link>
      }
      toolbar={
        <nav
          className="flex min-w-max items-center gap-1"
          aria-label={t("detail.fallbackSubtitle")}
        >
          <ApplicationIdentity
            id={applicationId}
            category={app?.category_id}
            icon={app?.icon}
          />
          <div className="mx-2 h-5 w-px bg-border" />
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
      <section
        aria-label={t("detail.scope.title")}
        className="mb-4 rounded-md border border-border bg-surface-subtle/60 px-3 py-2.5"
      >
        <div className="flex items-start gap-2.5">
          <Info className="mt-0.5 size-4 shrink-0 text-foreground-muted" />
          <div className="min-w-0 text-xs">
            <div className="font-semibold text-foreground">
              {t("detail.scope.title")} · {tabScope.label}
            </div>
            <p className="mt-0.5 text-foreground-secondary">
              {tabScope.description}
            </p>
          </div>
        </div>
      </section>
      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={applicationId}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : initialTab === "overview" ? (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              label={t("columns.download")}
              value={formatBytes(app?.download_bytes ?? 0)}
              icon={ArrowDown}
              loading={loading}
              subtext={t("detail.allRecordedTraffic")}
            />
            <MetricCard
              label={t("columns.upload")}
              value={formatBytes(app?.upload_bytes ?? 0)}
              icon={ArrowUp}
              loading={loading}
              subtext={t("detail.allRecordedTraffic")}
            />
            <MetricCard
              label={t("columns.clients")}
              value={formatPackets(app?.client_count ?? 0)}
              icon={Users}
              loading={loading}
              subtext={t("detail.distinctClients")}
            />
            <MetricCard
              label={t("columns.flows")}
              value={formatPackets(app?.flow_count ?? 0)}
              icon={Network}
              loading={loading}
              subtext={t("detail.persistedObservations")}
            />
          </div>
          {app && (
            <section className="rounded-md border border-border bg-surface p-4">
              <h2 className="text-xs font-semibold">
                {t("detail.classification")}
              </h2>
              <dl className="mt-3 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 xl:grid-cols-3">
                <div>
                  <dt className="text-foreground-muted">
                    {t("columns.organization")}
                  </dt>
                  <dd className="mt-1 font-medium">
                    {app.organization_id && app.organization_id !== "unknown"
                      ? app.organization_id
                      : tStatus("unknown")}
                  </dd>
                </div>
                <div>
                  <dt className="text-foreground-muted">
                    {t("columns.trafficClass")}
                  </dt>
                  <dd className="mt-1 font-medium">
                    {app.category_id || tStatus("unknown")}
                  </dd>
                </div>
                <div>
                  <dt className="text-foreground-muted">
                    {t("detail.classifierConfidence")}
                  </dt>
                  <dd className="mt-1 font-mono font-medium">
                    {formatPercent(app.confidence ?? 0)}
                  </dd>
                </div>
                <div>
                  <dt className="text-foreground-muted">
                    {t("detail.classificationSource")}
                  </dt>
                  <dd className="mt-1 font-medium">
                    {app.classifier_reason
                      ? t("detail.rulesSource")
                      : tStatus("unknown")}
                  </dd>
                </div>
                <div>
                  <dt className="text-foreground-muted">
                    {t("detail.domainCount")}
                  </dt>
                  <dd className="mt-1 font-mono font-medium">
                    {formatPackets(app.domain_count ?? 0)}
                  </dd>
                </div>
                <div>
                  <dt className="text-foreground-muted">
                    {t("detail.observedProtocols")}
                  </dt>
                  <dd className="mt-1 font-medium">
                    {(app.observed_protocols ?? [])
                      .map((protocol) => `${protocol.id} (${protocol.flows})`)
                      .join(", ") || tStatus("unknown")}
                  </dd>
                </div>
              </dl>
              <div className="mt-3 text-xs text-foreground-secondary">
                {app.classifier_reason || t("detail.noMatchingRule")}
              </div>
            </section>
          )}
          <TrafficChart
            data={chartData}
            title={t("detail.trafficLast24h")}
            height={300}
            loading={loading}
            maxPoints={200}
          />
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <section className="space-y-2">
              <h2 className="text-xs font-semibold">
                {t("detail.topClients")}
              </h2>
              <DataTable
                columns={clientColumns.slice(0, 4)}
                data={data?.clients.slice(0, 5) ?? []}
                keyExtractor={(row) => row.id}
                loading={loading}
                onRowClick={(row) => router.push(`/clients?id=${row.id}`)}
              />
            </section>
            <section className="space-y-2">
              <h2 className="text-xs font-semibold">
                {t("detail.topDomains")}
              </h2>
              <DataTable
                columns={domainColumns.slice(0, 4)}
                data={data?.domains.slice(0, 5) ?? []}
                keyExtractor={(row) => row.domain}
                loading={loading}
              />
            </section>
          </div>
        </>
      ) : loading ? (
        <DataTable
          columns={flowColumns}
          data={[]}
          keyExtractor={(row) => row.id}
          loading
        />
      ) : (
        tableForTab()
      )}
      <FlowPanel flow={selectedFlow} onClose={() => setSelectedFlow(null)} />
    </AppLayout>
  );
}
