"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Network, Search } from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import {
  ClientTrafficFlowMap,
  type ThroughputRate,
} from "@/components/dashboard/client-traffic-flow-map";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { DotStatus } from "@/components/network/status-badge";
import { PropertyRow, SidePanel } from "@/components/overlays/side-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  formatBytes,
  formatIdentifier,
  formatPackets,
  formatTimestamp,
} from "@/lib/formatters";
import type {
  ApiEnvelope,
  ClientSummary,
  TopologySummary,
} from "@/lib/network-types";

interface RealtimeSnapshot {
  generated_at: number;
  total: ThroughputRate;
  internet: ThroughputRate;
  clients: Record<string, ThroughputRate>;
  active_flows: Array<{ scope?: string }>;
  gateway_health?: { topology?: TopologySummary | null } | null;
}

interface DeviceSeenEvent {
  mac?: string;
  ip?: string;
  observed_at?: number;
}

function online(client: ClientSummary, now: number) {
  const lastTrafficSeen = client.last_traffic_seen ?? 0;
  return now > 0 && lastTrafficSeen > 0 && now - lastTrafficSeen <= 30_000;
}

function clientStatus(
  client: ClientSummary,
  loading: boolean,
  now: number,
): "loading" | "online" | "offline" {
  if (loading || now === 0) return "loading";
  return online(client, now) ? "online" : "offline";
}

function clientName(client: ClientSummary) {
  return client.self_host_application
    ? formatIdentifier(client.self_host_application.application_id)
    : client.name;
}

function identityValue(
  client: ClientSummary,
  key: "vendor" | "device_type" | "os_family" | "model",
) {
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

export function ClientsDashboard({
  username,
  initialSearch,
  initialSelectedId,
}: {
  username: string;
  initialSearch: string;
  initialSelectedId?: number;
}) {
  const t = useTranslations("clients");
  const tNav = useTranslations("navigation");
  const tStatus = useTranslations("common.status");
  const router = useRouter();
  const searchRef = useRef<HTMLInputElement>(null);

  const [items, setItems] = useState<ClientSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState(initialSearch);
  const [reloadKey, setReloadKey] = useState(0);
  const [now, setNow] = useState(0);
  const [showTopology, setShowTopology] = useState(true);
  const [streamConnected, setStreamConnected] = useState(false);
  const [totalThroughput, setTotalThroughput] = useState<ThroughputRate>({
    upload_bytes_per_second: 0,
    download_bytes_per_second: 0,
  });
  const [activeFlowCount, setActiveFlowCount] = useState(0);
  const [realtimeRates, setRealtimeRates] = useState<
    Record<string, ThroughputRate>
  >({});
  const [agentName, setAgentName] = useState(
    t("logicalTopology.agentFallback"),
  );
  const [topology, setTopology] = useState<TopologySummary | null>(null);

  const selected = items.find((item) => item.id === initialSelectedId) ?? null;

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const [clientsRes, overviewRes] = await Promise.all([
          fetch("/api/clients?limit=200", {
            cache: "no-store",
            signal: controller.signal,
          }),
          fetch("/api/overview", {
            cache: "no-store",
            signal: controller.signal,
          }).catch(() => null),
        ]);

        const envelope = (await clientsRes.json()) as ApiEnvelope<
          ClientSummary[]
        >;
        if (!clientsRes.ok) {
          throw new Error(
            envelope.error?.message ??
              `Clients request failed (${clientsRes.status})`,
          );
        }
        setItems(envelope.data);
        setError(null);

        if (overviewRes && overviewRes.ok) {
          const overviewData = (await overviewRes.json()) as ApiEnvelope<{
            gateway?: { name?: string; ip?: string } | null;
          }>;
          if (overviewData.data?.gateway?.name) {
            setAgentName(overviewData.data.gateway.name);
          }
        }
      } catch (loadError) {
        if (!controller.signal.aborted) {
          setError(
            loadError instanceof Error ? loadError.message : t("unavailable"),
          );
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [reloadKey, t]);

  const applySnapshot = useCallback((snapshot: RealtimeSnapshot) => {
    setTotalThroughput(
      snapshot.internet || {
        upload_bytes_per_second: 0,
        download_bytes_per_second: 0,
      },
    );
    setActiveFlowCount(
      snapshot.active_flows?.filter((flow) => flow.scope === "internet")
        .length || 0,
    );
    setRealtimeRates(snapshot.clients ?? {});
    setTopology(snapshot.gateway_health?.topology ?? null);
    setItems((current) =>
      current.map((client) => {
        const rate =
          snapshot.clients?.[client.mac] ??
          snapshot.clients?.[client.mac.toLowerCase()] ??
          (client.ip ? snapshot.clients?.[client.ip] : undefined);
        const hasTraffic =
          (rate?.upload_bytes_per_second ?? 0) > 0 ||
          (rate?.download_bytes_per_second ?? 0) > 0;
        return hasTraffic
          ? {
              ...client,
              last_traffic_seen: Math.max(
                client.last_traffic_seen ?? 0,
                snapshot.generated_at,
              ),
            }
          : client;
      }),
    );
  }, []);

  useEffect(() => {
    const events = new EventSource("/api/realtime");
    events.onopen = () => setStreamConnected(true);
    events.addEventListener("snapshot", (event) => {
      try {
        applySnapshot(JSON.parse(event.data) as RealtimeSnapshot);
      } catch {
        // Ignore decode issues
      }
    });
    events.addEventListener("device_seen", (event) => {
      try {
        const seen = JSON.parse(event.data) as DeviceSeenEvent;
        const observedAt = seen.observed_at;
        if (!seen.mac || typeof observedAt !== "number") return;
        const mac = seen.mac.toLowerCase();
        setItems((current) =>
          current.map((client) =>
            client.mac.toLowerCase() === mac && observedAt > client.last_seen
              ? {
                  ...client,
                  ip: client.ip || seen.ip || null,
                  last_seen: observedAt,
                }
              : client,
          ),
        );
      } catch {
        // Ignore decode issues
      }
    });
    events.onerror = () => setStreamConnected(false);
    return () => events.close();
  }, [applySnapshot]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (event.key === "/" && !(event.target instanceof HTMLInputElement)) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, []);

  const replaceQuery = (next: { search?: string; id?: string }) => {
    const params = new URLSearchParams(window.location.search);
    if (next.search !== undefined) {
      if (next.search) params.set("search", next.search);
      else params.delete("search");
    }
    if (next.id !== undefined) {
      if (next.id) params.set("id", next.id);
      else params.delete("id");
    }
    router.replace(`/clients${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  };

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return items;
    return items.filter((item) =>
      [
        item.name,
        item.ip,
        item.mac,
        item.vendor,
        item.identity?.device_type,
        item.identity?.os_family,
        item.identity?.model,
        item.self_host_application?.application_id,
      ].some((value) => value?.toLowerCase().includes(query)),
    );
  }, [items, search]);
  const onlineClientCount = loading
    ? 0
    : items.filter((client) => online(client, now)).length;

  const columns: ColumnDef<ClientSummary>[] = [
    {
      id: "status",
      header: t("columns.status"),
      cell: (row) => <DotStatus status={clientStatus(row, loading, now)} />,
    },
    {
      id: "name",
      header: t("columns.name"),
      cell: (row) => (
        <div className="flex min-w-0 items-center gap-2">
          <ClientDeviceIcon client={row} size="md" />
          <span className="truncate font-medium">
            {clientName(row) || tStatus("unknown")}
          </span>
        </div>
      ),
    },
    {
      id: "ip",
      header: t("columns.ip"),
      cell: (row) => <span className="font-mono">{row.ip || "—"}</span>,
    },
    {
      id: "mac",
      header: t("columns.mac"),
      cell: (row) => (
        <span className="font-mono text-foreground-secondary">{row.mac}</span>
      ),
    },
    {
      id: "vendor",
      header: t("columns.vendor"),
      cell: (row) => identityValue(row, "vendor") || tStatus("unknown"),
    },
    {
      id: "type",
      header: t("columns.deviceType"),
      cell: (row) => identityValue(row, "device_type") || tStatus("unknown"),
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
    {
      id: "last_traffic_seen",
      header: t("columns.lastTrafficSeen"),
      align: "right",
      cell: (row) =>
        row.last_traffic_seen
          ? formatTimestamp(row.last_traffic_seen, "relative")
          : tStatus("unknown"),
    },
  ];

  const toolbar = (
    <div className="flex items-center justify-between gap-3">
      <label className="relative block w-full max-w-sm">
        <Search className="pointer-events-none absolute left-2.5 top-2 size-3.5 text-foreground-muted z-10" />
        <Input
          ref={searchRef}
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          onBlur={() => replaceQuery({ search })}
          onKeyDown={(event) => {
            if (event.key === "Enter") replaceQuery({ search });
          }}
          placeholder={t("searchPlaceholder")}
          aria-label={t("searchAria")}
          className="pl-8 pr-12"
        />
        <kbd className="pointer-events-none absolute right-2 top-1.5 rounded border border-border bg-surface-subtle px-1.5 py-0.5 text-[10px] text-foreground-muted">
          /
        </kbd>
      </label>
      <div className="flex items-center gap-3">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowTopology((prev) => !prev)}
          className="hidden sm:inline-flex items-center gap-1.5 text-xs text-foreground-secondary hover:text-foreground"
        >
          <Network className="size-3.5 text-accent" />
          {showTopology ? t("topology.hideFlow") : t("topology.showFlow")}
        </Button>
        <span className="shrink-0 text-[11px] text-foreground-muted">
          {t("clientsCount", { count: filtered.length })}
        </span>
      </div>
    </div>
  );

  return (
    <AppLayout
      title={tNav("clients")}
      subtitle={t("subtitle")}
      username={username}
      isLive={streamConnected}
      toolbar={toolbar}
    >
      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={t("inventoryScope")}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : (
        <div className="flex flex-col gap-6">
          {showTopology && (
            <ClientTrafficFlowMap
              clients={filtered}
              topology={topology}
              agentName={agentName}
              internet={totalThroughput}
              realtimeRates={realtimeRates}
              activeInternetFlows={activeFlowCount}
              onlineClientCount={onlineClientCount}
              selectedClientId={selected?.id}
              isLive={streamConnected}
              onSelectClient={(clientId) =>
                replaceQuery({ id: String(clientId) })
              }
            />
          )}

          <DataTable
            columns={columns}
            data={filtered}
            keyExtractor={(row) => row.id}
            loading={loading}
            onRowClick={(row) => replaceQuery({ id: String(row.id) })}
            emptyState={
              <EmptyState
                title={t("notFound")}
                description={search ? t("notFoundSearch") : t("notFoundEmpty")}
                className="border-0 bg-transparent"
              />
            }
          />
        </div>
      )}

      <SidePanel
        open={Boolean(selected)}
        onClose={() => replaceQuery({ id: "" })}
        title={
          selected
            ? clientName(selected) || tStatus("unknown")
            : tStatus("unknown")
        }
        subtitle={selected?.ip || selected?.mac}
        statusBadge={
          selected && (
            <DotStatus status={clientStatus(selected, loading, now)} />
          )
        }
        footerActions={
          selected && (
            <div className="ml-auto">
              <Link
                href={`/clients/${selected.id}`}
                className={buttonVariants({ size: "sm" })}
              >
                {t("openClientDetails")}
              </Link>
            </div>
          )
        }
      >
        {selected && (
          <>
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-md border border-border bg-surface-subtle p-3">
                <div className="text-[10px] text-foreground-muted">
                  {t("columns.download")}
                </div>
                <div className="mt-1 font-mono text-sm font-semibold">
                  {formatBytes(selected.download_bytes)}
                </div>
              </div>
              <div className="rounded-md border border-border bg-surface-subtle p-3">
                <div className="text-[10px] text-foreground-muted">
                  {t("columns.upload")}
                </div>
                <div className="mt-1 font-mono text-sm font-semibold">
                  {formatBytes(selected.upload_bytes)}
                </div>
              </div>
            </div>
            <section>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                {t("properties.identity")}
              </h3>
              <PropertyRow
                label={t("properties.ip")}
                value={selected.ip || tStatus("unknown")}
                copyable={Boolean(selected.ip)}
                mono
              />
              <PropertyRow
                label={t("properties.mac")}
                value={selected.mac}
                copyable
                mono
              />
              {selected.self_host_application && (
                <PropertyRow
                  label={t("properties.serverApplication")}
                  value={`${formatIdentifier(selected.self_host_application.application_id)} · ${Math.round(selected.self_host_application.confidence * 100)}%`}
                />
              )}
              <PropertyRow
                label={t("properties.vendor")}
                value={`${identityValue(selected, "vendor") || tStatus("unknown")} · ${identityConfidence(selected, "vendor")}`}
              />
              <PropertyRow
                label={t("properties.deviceType")}
                value={`${identityValue(selected, "device_type") || tStatus("unknown")} · ${identityConfidence(selected, "device_type")}`}
              />
              <PropertyRow
                label={t("properties.osFamily")}
                value={`${identityValue(selected, "os_family") || tStatus("unknown")} · ${identityConfidence(selected, "os_family")}`}
              />
              <PropertyRow
                label={t("properties.model")}
                value={`${identityValue(selected, "model") || tStatus("unknown")} · ${identityConfidence(selected, "model")}`}
              />
              <PropertyRow
                label={t("properties.confidence")}
                value={selected.identity?.confidence || tStatus("unknown")}
              />
              <PropertyRow
                label={t("properties.privateMac")}
                value={
                  selected.identity?.private_mac
                    ? t("properties.yes")
                    : t("properties.no")
                }
              />
              <PropertyRow
                label={t("properties.flows")}
                value={formatPackets(selected.flow_count)}
                mono
              />
              <PropertyRow
                label={t("properties.lastSeen")}
                value={formatTimestamp(selected.last_seen, "date")}
              />
              <PropertyRow
                label={t("properties.lastTrafficSeen")}
                value={
                  selected.last_traffic_seen
                    ? formatTimestamp(selected.last_traffic_seen, "date")
                    : tStatus("unknown")
                }
              />
            </section>
          </>
        )}
      </SidePanel>
    </AppLayout>
  );
}
