"use client";

import Link from "next/link";
import dynamic from "next/dynamic";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import {
  Table as TableIcon,
  Map as MapIcon,
  Loader2,
  ExternalLink,
} from "lucide-react";
import { AppLayout } from "@/components/app-shell/app-layout";
import { CountryFlag } from "@/components/icons/country-flag";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { RankList } from "@/components/data/rank-list";
import { CategoryDistribution } from "@/components/data/category-distribution";
import { PropertyRow, SidePanel } from "@/components/overlays/side-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { buttonVariants } from "@/components/ui/button";
import {
  TimeRangePicker,
  type CustomDateRange,
  type TimeRangeValue,
} from "@/components/data/time-range-picker";
import {
  cloudflareAsnUrl,
  cloudflareDomainUrl,
  formatBytes,
  formatPackets,
  formatTimestamp,
  ipInfoUrl,
  isLocalIp,
} from "@/lib/formatters";
import type {
  ApiEnvelope,
  DestinationSummary,
  GeoSummary,
} from "@/lib/network-types";

const PAGE_SIZE = 50;
const MAP_FETCH_LIMIT = 200;

const DestinationsMap = dynamic(
  () => import("./destinations-map").then((mod) => mod.DestinationsMap),
  {
    ssr: false,
    loading: () => (
      <div
        className="flex w-full items-center justify-center rounded-xl border border-border bg-[#07131f]"
        style={{ height: "560px", minHeight: "480px" }}
      >
        <Loader2 className="size-6 animate-spin text-primary" />
      </div>
    ),
  },
);

const RANGE_MS: Record<Exclude<TimeRangeValue, "custom" | "15m">, number> = {
  "1h": 60 * 60 * 1_000,
  "24h": 24 * 60 * 60 * 1_000,
  "7d": 7 * 24 * 60 * 60 * 1_000,
  "30d": 30 * 24 * 60 * 60 * 1_000,
};

function rangeBounds(range: TimeRangeValue, from?: string, to?: string) {
  const end = range === "custom" && to ? Date.parse(to) : Date.now();
  const start =
    range === "custom" && from
      ? Date.parse(from)
      : end -
        (range === "15m"
          ? 15 * 60 * 1_000
          : RANGE_MS[range as keyof typeof RANGE_MS] || 24 * 60 * 60 * 1_000);
  return { from: start, to: end };
}

export function DestinationsDashboard({
  username,
  initialPage,
  initialSelectedIp,
  initialRange = "24h",
  initialFrom,
  initialTo,
  initialView = "map",
}: {
  username: string;
  initialPage: number;
  initialSelectedIp?: string;
  initialRange?: TimeRangeValue;
  initialFrom?: string;
  initialTo?: string;
  initialView?: "table" | "map";
}) {
  const t = useTranslations("destinations");
  const tNav = useTranslations("navigation");
  const tStatus = useTranslations("common.status");
  const locale = useLocale();
  const router = useRouter();

  const [items, setItems] = useState<DestinationSummary[]>([]);
  const [mapItems, setMapItems] = useState<DestinationSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [geoSummary, setGeoSummary] = useState<GeoSummary | null>(null);
  const [geoError, setGeoError] = useState<string | null>(null);

  const selected =
    (initialView === "map" ? mapItems : items).find(
      (item) => item.remote_ip === initialSelectedIp,
    ) ??
    mapItems.find((item) => item.remote_ip === initialSelectedIp) ??
    items.find((item) => item.remote_ip === initialSelectedIp) ??
    null;

  const updateUrl = (changes: Record<string, string | number | undefined>) => {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(changes)) {
      if (value !== undefined && value !== "") {
        if (key === "page" && Number(value) <= 1) params.delete("page");
        else if (key === "view" && value === "map") params.delete("view");
        else if (key === "view" && value === "table")
          params.set("view", "table");
        else if (key === "range" && value === "24h") params.delete("range");
        else params.set(key, String(value));
      } else {
        params.delete(key);
      }
    }
    router.replace(
      `/destinations${params.size ? `?${params.toString()}` : ""}`,
      { scroll: false },
    );
  };

  const handleRange = (range: TimeRangeValue, custom?: CustomDateRange) => {
    if (range === "custom" && custom) {
      updateUrl({
        range: "custom",
        from: custom.from,
        to: custom.to,
        page: undefined,
      });
      return;
    }
    updateUrl({ range, from: undefined, to: undefined, page: undefined });
  };

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const bounds = rangeBounds(initialRange, initialFrom, initialTo);
        const timeQuery = `from=${bounds.from}&to=${bounds.to}`;
        const offset = (initialPage - 1) * PAGE_SIZE;

        if (initialView === "map") {
          const [mapResp, geoResponse] = await Promise.all([
            fetch(
              `/api/destinations?limit=${MAP_FETCH_LIMIT}&offset=0&${timeQuery}&lang=${encodeURIComponent(locale)}`,
              { cache: "no-store", signal: controller.signal },
            ),
            fetch(`/api/geo?${timeQuery}&lang=${encodeURIComponent(locale)}`, {
              cache: "no-store",
              signal: controller.signal,
            }),
          ]);
          const mapEnvelope = (await mapResp.json()) as ApiEnvelope<
            DestinationSummary[]
          >;
          if (!mapResp.ok)
            throw new Error(
              mapEnvelope.error?.message ??
                `Destinations request failed (${mapResp.status})`,
            );
          setMapItems(mapEnvelope.data);
          setTotal(mapEnvelope.pagination?.total ?? mapEnvelope.data.length);

          if (geoResponse.ok) {
            const geoEnvelope =
              (await geoResponse.json()) as ApiEnvelope<GeoSummary>;
            setGeoSummary(geoEnvelope.data);
            setGeoError(null);
          } else {
            setGeoError(`Geo summary request failed (${geoResponse.status})`);
          }
        } else {
          const [response, geoResponse] = await Promise.all([
            fetch(
              `/api/destinations?limit=${PAGE_SIZE}&offset=${offset}&${timeQuery}&lang=${encodeURIComponent(locale)}`,
              { cache: "no-store", signal: controller.signal },
            ),
            fetch(`/api/geo?${timeQuery}&lang=${encodeURIComponent(locale)}`, {
              cache: "no-store",
              signal: controller.signal,
            }),
          ]);
          const envelope = (await response.json()) as ApiEnvelope<
            DestinationSummary[]
          >;
          if (!response.ok)
            throw new Error(
              envelope.error?.message ??
                `Destinations request failed (${response.status})`,
            );
          setItems(envelope.data);
          setTotal(envelope.pagination?.total ?? envelope.data.length);

          if (geoResponse.ok) {
            const geoEnvelope =
              (await geoResponse.json()) as ApiEnvelope<GeoSummary>;
            setGeoSummary(geoEnvelope.data);
            setGeoError(null);
          } else {
            setGeoError(`Geo summary request failed (${geoResponse.status})`);
          }
        }

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
  }, [
    initialFrom,
    initialPage,
    initialRange,
    initialTo,
    initialView,
    locale,
    reloadKey,
    t,
  ]);

  const columns: ColumnDef<DestinationSummary>[] = [
    {
      id: "ip",
      header: t("columns.ip"),
      cell: (row) =>
        !row.domain && !isLocalIp(row.remote_ip) ? (
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
          <span className="font-mono">{row.remote_ip}</span>
        ),
    },
    {
      id: "domain",
      header: t("columns.domain"),
      cell: (row) =>
        row.domain ? (
          <a
            href={cloudflareDomainUrl(row.domain)}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="group inline-flex max-w-64 items-center gap-1 truncate text-foreground hover:text-accent hover:underline"
            title={row.domain}
          >
            <span className="truncate">{row.domain}</span>
            <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
          </a>
        ) : (
          <span className="text-foreground-muted">{tStatus("unknown")}</span>
        ),
    },
    {
      id: "asn",
      header: t("columns.asn"),
      cell: (row) =>
        row.asn ? (
          <a
            href={cloudflareAsnUrl(row.asn)}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="group inline-flex items-center gap-1 text-foreground hover:text-accent hover:underline"
          >
            <span>{`AS${row.asn}${row.organization ? ` · ${row.organization}` : ""}`}</span>
            <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
          </a>
        ) : (
          <span className="text-foreground-muted">{t("notEnabled")}</span>
        ),
    },
    {
      id: "country",
      header: t("columns.country"),
      cell: (row) =>
        row.country_name || row.country_code ? (
          <div className="flex min-w-0 items-center gap-2">
            <CountryFlag code={row.country_code} />
            <span className="truncate">
              {row.country_name
                ? `${row.country_name}${row.country_code ? ` (${row.country_code})` : ""}`
                : row.country_code}
            </span>
          </div>
        ) : (
          <span className="text-foreground-muted">{t("notEnabled")}</span>
        ),
    },
    {
      id: "traffic",
      header: t("columns.traffic"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes + row.upload_bytes),
    },
    {
      id: "clients",
      header: t("columns.clients"),
      align: "right",
      cell: (row) => formatPackets(row.client_count),
    },
    {
      id: "flows",
      header: t("columns.flows"),
      align: "right",
      cell: (row) => formatPackets(row.flow_count),
    },
  ];

  const hasPrevious = initialPage > 1;
  const hasNext = initialPage * PAGE_SIZE < total;
  const topCountries =
    geoSummary?.top_countries.map((item) => ({
      id: item.country_code,
      name: item.country_name,
      subtitle: item.country_code,
      value: item.bytes,
      icon: <CountryFlag code={item.country_code} />,
    })) ?? [];
  const topAsns =
    geoSummary?.top_asns.map((item) => ({
      id: String(item.asn),
      name: `AS${item.asn}`,
      subtitle: item.organization,
      value: item.bytes,
    })) ?? [];
  const countryDistribution =
    geoSummary?.country_distribution.map((item) => ({
      id: item.country_code,
      name: item.country_name,
      value: item.bytes,
    })) ?? [];

  const toolbar = (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <Tabs
        value={initialView}
        onValueChange={(val) =>
          updateUrl({ view: val as "table" | "map", page: undefined })
        }
        variant="pill"
        className="w-auto inline-flex items-center"
      >
        <TabsList className="h-8 p-0.5 bg-surface-subtle/80 border border-border">
          <TabsTrigger
            value="table"
            className="h-7 gap-1.5 px-3 text-xs font-medium"
          >
            <TableIcon className="size-3.5" />
            <span>{t("viewTable")}</span>
          </TabsTrigger>
          <TabsTrigger
            value="map"
            className="h-7 gap-1.5 px-3 text-xs font-medium"
          >
            <MapIcon className="size-3.5" />
            <span>{t("viewMap")}</span>
          </TabsTrigger>
        </TabsList>
      </Tabs>

      <TimeRangePicker
        value={initialRange}
        onChange={handleRange}
        customRange={
          initialFrom && initialTo
            ? { from: initialFrom, to: initialTo }
            : undefined
        }
      />
    </div>
  );

  return (
    <AppLayout
      title={tNav("destinations")}
      subtitle={t("subtitle")}
      username={username}
      isLive={false}
      toolbar={toolbar}
    >
      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={t("summariesScope")}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : (
        <>
          {!loading && geoError && (
            <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] text-foreground-secondary">
              {t("geoError", { error: geoError })}
            </div>
          )}
          {!loading && geoSummary && !geoSummary.enabled && (
            <div className="rounded-md border border-border bg-surface-subtle px-3 py-2 text-[11px] text-foreground-secondary">
              {t("geoNotEnabled")}
            </div>
          )}
          {(loading || geoSummary?.enabled) && (
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
              <RankList
                compact
                title={t("topCountries")}
                items={topCountries}
                loading={loading}
                emptyMessage={t("noCountryMatches")}
              />
              <RankList
                compact
                title={t("topAsns")}
                items={topAsns}
                loading={loading}
                emptyMessage={t("noAsnMatches")}
                onItemClick={(item) =>
                  window.open(
                    cloudflareAsnUrl(item.id),
                    "_blank",
                    "noopener,noreferrer",
                  )
                }
              />
              <CategoryDistribution
                compact
                variant="country"
                title={t("countryDistribution")}
                items={countryDistribution}
                loading={loading}
                emptyMessage={t("noCountryMatches")}
              />
            </div>
          )}

          {initialView === "map" ? (
            <DestinationsMap
              items={mapItems}
              onSelectDestination={(ip) => updateUrl({ ip })}
              loading={loading}
            />
          ) : (
            <DataTable
              columns={columns}
              data={items}
              keyExtractor={(row) => row.remote_ip}
              loading={loading}
              onRowClick={(row) => updateUrl({ ip: row.remote_ip })}
              pagination={{
                pageIndex: initialPage - 1,
                pageSize: PAGE_SIZE,
                hasPrevious,
                hasNext,
                onPreviousPage: () => updateUrl({ page: initialPage - 1 }),
                onNextPage: () => updateUrl({ page: initialPage + 1 }),
                totalDisplay: t("destinationsCount", { count: total }),
              }}
              emptyState={
                <EmptyState
                  title={t("emptyTitle")}
                  description={t("emptyDesc")}
                  className="border-0 bg-transparent"
                />
              }
            />
          )}
        </>
      )}

      <SidePanel
        open={Boolean(selected)}
        onClose={() => updateUrl({ ip: undefined })}
        title={selected?.domain || selected?.remote_ip || t("columns.ip")}
        subtitle={selected?.domain ? selected.remote_ip : undefined}
        footerActions={
          selected && (
            <div className="ml-auto">
              <Link
                href={`/flows?ip=${encodeURIComponent(selected.remote_ip)}`}
                className={buttonVariants({ size: "sm" })}
              >
                {t("viewRelatedFlows")}
              </Link>
            </div>
          )
        }
      >
        {selected && (
          <>
            <section>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                {t("properties.identity")}
              </h3>
              <PropertyRow
                label={t("properties.ip")}
                value={selected.remote_ip}
                href={
                  !selected.domain && !isLocalIp(selected.remote_ip)
                    ? ipInfoUrl(selected.remote_ip)
                    : undefined
                }
                external={!selected.domain && !isLocalIp(selected.remote_ip)}
                copyable
                mono
              />
              <PropertyRow
                label={t("properties.domain")}
                value={selected.domain || tStatus("unknown")}
                href={
                  selected.domain
                    ? cloudflareDomainUrl(selected.domain)
                    : undefined
                }
                external
                copyable={Boolean(selected.domain)}
              />
              <PropertyRow
                label={t("properties.country")}
                value={
                  selected.country_name
                    ? `${selected.country_name}${selected.country_code ? ` (${selected.country_code})` : ""}`
                    : selected.country_code || t("notEnabled")
                }
              />
              <PropertyRow
                label={t("properties.region")}
                value={selected.region || tStatus("unknown")}
              />
              <PropertyRow
                label={t("properties.asn")}
                value={selected.asn ? `AS${selected.asn}` : t("notEnabled")}
                href={selected.asn ? cloudflareAsnUrl(selected.asn) : undefined}
                external
              />
              <PropertyRow
                label={t("properties.organization")}
                value={selected.organization || t("notEnabled")}
              />
            </section>
            <section>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                {t("properties.traffic")}
              </h3>
              <PropertyRow
                label={t("properties.download")}
                value={formatBytes(selected.download_bytes)}
                mono
              />
              <PropertyRow
                label={t("properties.upload")}
                value={formatBytes(selected.upload_bytes)}
                mono
              />
              <PropertyRow
                label={t("properties.clients")}
                value={formatPackets(selected.client_count)}
                mono
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
            </section>
          </>
        )}
      </SidePanel>
    </AppLayout>
  );
}
