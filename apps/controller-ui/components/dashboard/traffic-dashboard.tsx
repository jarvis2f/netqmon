"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, ArrowDown, ArrowUp, Layers3 } from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { ApplicationIcon } from "@/components/icons/application-icon";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { MetricCard } from "@/components/data/metric-card";
import {
  TimeRangePicker,
  type CustomDateRange,
  type TimeRangeValue,
} from "@/components/data/time-range-picker";
import {
  TrafficChart,
  type TrafficDataPoint,
} from "@/components/data/traffic-chart";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatBytes, formatPackets, formatTimestamp } from "@/lib/formatters";

type Direction = "both" | "download" | "upload";
type TrafficScope = "internet" | "internal" | "tunnel" | "all";
type GroupBy = "none" | "client" | "application" | "category";

interface TrafficPoint {
  timestamp: number;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  flow_count: number;
}

interface BreakdownRow {
  id: string;
  name: string;
  mac: string | null;
  icon?: import("@/lib/network-types").IconMetadata | null;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  flow_count: number;
  last_seen: number | null;
}

interface TrafficResponse {
  from: number;
  to: number;
  bucket_ms: number;
  group_by: GroupBy;
  points: TrafficPoint[];
  breakdown: BreakdownRow[];
}

interface ApiEnvelope<T> {
  data: T;
  error?: { message?: string };
}

interface TrafficDashboardProps {
  username: string;
  initialRange: TimeRangeValue;
  initialDirection: Direction;
  initialScope: TrafficScope;
  initialGroupBy: GroupBy;
  initialFrom?: string;
  initialTo?: string;
}

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
          : RANGE_MS[range as keyof typeof RANGE_MS]);
  return { from: start, to: end };
}

export function TrafficDashboard({
  username,
  initialRange,
  initialDirection,
  initialScope,
  initialGroupBy,
  initialFrom,
  initialTo,
}: TrafficDashboardProps) {
  const t = useTranslations("traffic");
  const tNav = useTranslations("navigation");
  const tTime = useTranslations("common.timeRange");
  const tStatus = useTranslations("common.status");
  const router = useRouter();

  const [data, setData] = useState<TrafficResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const updateUrl = (changes: Record<string, string | undefined>) => {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(changes)) {
      if (value) params.set(key, value);
      else params.delete(key);
    }
    router.replace(`/traffic?${params.toString()}`, { scroll: false });
  };

  const handleRange = (range: TimeRangeValue, custom?: CustomDateRange) => {
    if (range === "custom" && custom) {
      updateUrl({ range: "custom", from: custom.from, to: custom.to });
      return;
    }
    updateUrl({ range, from: undefined, to: undefined });
  };

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      setError(null);
      const bounds = rangeBounds(initialRange, initialFrom, initialTo);
      const params = new URLSearchParams({
        from: String(bounds.from),
        to: String(bounds.to),
        group_by: initialGroupBy,
        direction: initialDirection,
        scope: initialScope,
      });

      try {
        const response = await fetch(`/api/traffic?${params.toString()}`, {
          signal: controller.signal,
        });
        const payload = (await response.json()) as ApiEnvelope<TrafficResponse>;
        if (!response.ok) {
          setError(payload?.error?.message ?? t("loadError"));
          return;
        }
        setData(payload.data);
      } catch (err) {
        if (!controller.signal.aborted) {
          setError((err as Error).message || t("loadError"));
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [
    initialDirection,
    initialFrom,
    initialGroupBy,
    initialRange,
    initialScope,
    initialTo,
    reloadKey,
    t,
  ]);

  const chartData = useMemo<TrafficDataPoint[]>(
    () =>
      (data?.points ?? []).map((point) => ({
        timestamp: point.timestamp,
        downloadBps:
          point.download_bytes * 8 * (60_000 / (data?.bucket_ms ?? 60_000)),
        uploadBps:
          point.upload_bytes * 8 * (60_000 / (data?.bucket_ms ?? 60_000)),
      })),
    [data],
  );
  const totals = useMemo(
    () =>
      (data?.points ?? []).reduce(
        (sum, point) => ({
          download: sum.download + point.download_bytes,
          upload: sum.upload + point.upload_bytes,
          flows: sum.flows + point.flow_count,
        }),
        { download: 0, upload: 0, flows: 0 },
      ),
    [data],
  );

  const formatRangeLabel = (rangeVal: TimeRangeValue) => {
    if (rangeVal === "custom") return tTime("customRange");
    if (rangeVal === "15m")
      return tTime("lastRange", { range: tTime("range15m") });
    if (rangeVal === "1h")
      return tTime("lastRange", { range: tTime("range1h") });
    if (rangeVal === "24h")
      return tTime("lastRange", { range: tTime("range24h") });
    if (rangeVal === "7d")
      return tTime("lastRange", { range: tTime("range7d") });
    if (rangeVal === "30d")
      return tTime("lastRange", { range: tTime("range30d") });
    return tTime("lastRange", { range: rangeVal });
  };

  const columns: ColumnDef<BreakdownRow>[] = [
    {
      id: "name",
      header:
        initialGroupBy === "none"
          ? t("scope")
          : t(initialGroupBy as "client" | "application" | "category"),
      cell: (row) => (
        <div className="flex min-w-0 items-center gap-2">
          {initialGroupBy === "application" && (
            <ApplicationIcon applicationId={row.id} icon={row.icon} size="md" />
          )}
          {initialGroupBy === "client" && (
            <ClientDeviceIcon
              client={{ name: row.name, mac: row.mac }}
              size="md"
            />
          )}
          <div className="min-w-0">
            <div className="truncate font-medium text-foreground">
              {row.name || row.mac || tStatus("unknown")}
            </div>
            {row.mac && (
              <div className="truncate font-mono text-[10px] text-foreground-muted">
                {row.mac}
              </div>
            )}
          </div>
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
      id: "total",
      header: t("columns.total"),
      align: "right",
      cell: (row) => formatBytes(row.download_bytes + row.upload_bytes),
    },
    {
      id: "packets",
      header: t("columns.packets"),
      align: "right",
      cell: (row) => formatPackets(row.packets, true),
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

  const toolbar = (
    <div className="flex min-w-max items-center justify-between gap-4">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Label className="text-[11px] text-foreground-muted">
            {t("scope")}
          </Label>
          <Select
            value={initialScope}
            onValueChange={(value) => value && updateUrl({ scope: value })}
          >
            <SelectTrigger className="h-8 min-w-[100px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="internet">{t("scopes.internet")}</SelectItem>
              <SelectItem value="internal">{t("scopes.internal")}</SelectItem>
              <SelectItem value="tunnel">{t("scopes.tunnel")}</SelectItem>
              <SelectItem value="all">{t("scopes.all")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Label className="text-[11px] text-foreground-muted">
            {t("direction")}
          </Label>
          <Select
            value={initialDirection}
            onValueChange={(value) => value && updateUrl({ direction: value })}
          >
            <SelectTrigger className="h-8 min-w-[90px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="both">{t("both")}</SelectItem>
              <SelectItem value="download">{t("downloadOption")}</SelectItem>
              <SelectItem value="upload">{t("uploadOption")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Label className="text-[11px] text-foreground-muted">
            {t("groupBy")}
          </Label>
          <Select
            value={initialGroupBy}
            onValueChange={(value) => value && updateUrl({ group: value })}
          >
            <SelectTrigger className="h-8 min-w-[100px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">{t("none")}</SelectItem>
              <SelectItem value="client">{t("client")}</SelectItem>
              <SelectItem value="application">{t("application")}</SelectItem>
              <SelectItem value="category">{t("category")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
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
      title={tNav("traffic")}
      subtitle={t("subtitle")}
      username={username}
      isLive={false}
      toolbar={toolbar}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label={t("columns.download")}
          value={formatBytes(totals.download)}
          icon={ArrowDown}
          loading={loading}
          subtext={formatRangeLabel(initialRange)}
        />
        <MetricCard
          label={t("columns.upload")}
          value={formatBytes(totals.upload)}
          icon={ArrowUp}
          loading={loading}
          subtext={formatRangeLabel(initialRange)}
        />
        <MetricCard
          label={t("flowObservations")}
          value={formatPackets(totals.flows, true)}
          icon={Activity}
          loading={loading}
          subtext={t("aggregatedSamples")}
        />
        <MetricCard
          label={t("breakdownGroups")}
          value={(data?.breakdown.length ?? 0).toLocaleString()}
          icon={Layers3}
          loading={loading}
          subtext={t("groupedBy", {
            group: t(
              initialGroupBy as "none" | "client" | "application" | "category",
            ),
          })}
        />
      </div>

      {error ? (
        <ErrorState
          title={t("historyUnavailable")}
          message={error}
          affectedScope={t("historicalScope")}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : (
        <>
          <TrafficChart
            data={chartData}
            title={`${tNav("traffic")} — ${formatRangeLabel(initialRange)}`}
            height={320}
            loading={loading}
            showDownload={initialDirection !== "upload"}
            showUpload={initialDirection !== "download"}
            maxPoints={200}
          />
          <section
            aria-labelledby="traffic-breakdown-title"
            className="space-y-2"
          >
            <div className="flex items-end justify-between gap-3">
              <div>
                <h2
                  id="traffic-breakdown-title"
                  className="text-xs font-semibold text-foreground"
                >
                  {t("trafficBreakdown")}
                </h2>
                <p className="mt-0.5 text-[11px] text-foreground-muted">
                  {t("breakdownDesc")}
                </p>
              </div>
              {data && (
                <span className="text-[11px] text-foreground-muted">
                  {t("groupsCount", { count: data.breakdown.length })}
                </span>
              )}
            </div>
            <DataTable
              columns={columns}
              data={data?.breakdown ?? []}
              keyExtractor={(row) => row.id}
              loading={loading}
              emptyState={
                <EmptyState
                  title={t("noTrafficRecorded")}
                  description={t("noTelemetryDesc")}
                  className="border-0 bg-transparent"
                />
              }
            />
          </section>
        </>
      )}
    </AppLayout>
  );
}
