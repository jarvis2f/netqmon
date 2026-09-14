"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ChevronRight,
  CircleHelp,
  Laptop,
  Network,
  Radio,
  RefreshCw,
  Router,
  SearchX,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { PropertyRow, SidePanel } from "@/components/overlays/side-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { TableSkeleton } from "@/components/states/loading-state";
import { formatBytes, formatPercent, formatTimestamp } from "@/lib/formatters";
import type {
  ApiEnvelope,
  Insight,
  InsightCategory,
} from "@/lib/network-types";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

type Filter = "all" | "devices" | "traffic" | "security" | "quality" | "system";
type TranslationFn = (
  key: string,
  values?: Record<string, string | number | boolean | Date>,
) => string;
interface TranslationObject {
  has?: (key: string) => boolean;
}

const categoryIcons: Record<string, typeof Activity> = {
  device: Laptop,
  traffic: Upload,
  classification: SearchX,
  dns: ShieldAlert,
  protocol: ShieldCheck,
  destination: Share2,
  capture: Router,
  network_quality: Network,
  connectivity: Radio,
};

const categoryAccents: Record<string, string> = {
  device: "text-accent bg-accent-soft",
  traffic: "text-warning bg-warning-soft",
  classification: "text-warning bg-warning-soft",
  dns: "text-accent bg-accent-soft",
  protocol: "text-accent bg-accent-soft",
  destination: "text-warning bg-warning-soft",
  capture: "text-warning bg-warning-soft",
  network_quality: "text-accent bg-accent-soft",
  connectivity: "text-accent bg-accent-soft",
};

function labelFor(key: string) {
  return key
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function evidenceValue(
  key: string,
  value: unknown,
  translate: TranslationFn,
): string {
  if (value === null) return translate("evidenceValues.notVisible");
  if (typeof value === "boolean")
    return value
      ? translate("evidenceValues.yes")
      : translate("evidenceValues.no");
  if (typeof value === "number") {
    if (key.endsWith("_bytes") || key === "bytes" || key.endsWith("_delta")) {
      return formatBytes(value);
    }
    if (key === "ratio") {
      return value > 1.0 ? `${value.toFixed(1)}x` : formatPercent(value);
    }
    if (key === "threshold") {
      return formatPercent(value);
    }
    if (
      key.endsWith("_time") ||
      key.endsWith("_at") ||
      key.startsWith("window_") ||
      key === "first_seen" ||
      key === "last_seen" ||
      key === "last_observed"
    ) {
      return formatTimestamp(value, "tooltip");
    }
    if (key.endsWith("_ms")) {
      return `${value.toLocaleString()} ms`;
    }
    return value.toLocaleString();
  }
  if (typeof value === "string") return value.replaceAll("_", " ");
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

const COMMON_PARAM_KEYS = [
  "name",
  "client",
  "mac",
  "ip",
  "remote_ip",
  "remote_port",
  "provider",
  "protocol",
  "protocol_name",
  "application",
  "application_name",
  "bytes",
  "upload_bytes",
  "download_bytes",
  "tx_bytes",
  "rx_bytes",
  "total_bytes",
  "unknown_bytes",
  "baseline_bytes",
  "current_bytes",
  "ratio",
  "threshold",
  "threshold_bytes",
  "threshold_ms",
  "multiplier",
  "tracker_flows",
  "peer_flows",
  "count",
  "destination_count",
  "flow_count",
  "interface_delta",
  "flow_delta",
  "lag_ms",
];

function resolveInsightText(
  item: Insight,
  t: ReturnType<typeof useTranslations<"insights">>,
): { title: string; reason: string } {
  const [category, subcode] = item.code.split(".");
  const titleKey = `events.${category}.${subcode}.title`;
  const reasonKey = `events.${category}.${subcode}.reason`;
  const translate = t as unknown as TranslationFn;
  const tObj = t as unknown as TranslationObject;

  const formattedParams: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(item.params ?? {})) {
    if (v === null || v === undefined) {
      formattedParams[k] = "—";
    } else if (typeof v === "number") {
      if (k === "ratio") {
        formattedParams[k] = v > 1.0 ? `${v.toFixed(1)}x` : formatPercent(v);
      } else if (k === "threshold") {
        formattedParams[k] = formatPercent(v);
      } else if (
        k.endsWith("_bytes") ||
        k === "bytes" ||
        k.endsWith("_delta")
      ) {
        formattedParams[k] = formatBytes(v);
      } else if (k.endsWith("_count") || k === "count") {
        formattedParams[k] = v.toLocaleString();
      } else {
        formattedParams[k] = v;
      }
    } else {
      formattedParams[k] = String(v);
    }
  }

  // Populate common aliases
  const clientName = (item.params?.name ??
    item.params?.client ??
    item.affected_client?.name ??
    "Unknown client") as string;
  if (!("name" in formattedParams)) formattedParams.name = clientName;
  if (!("client" in formattedParams)) formattedParams.client = clientName;
  if (!("remote_ip" in formattedParams) && item.params?.remote_ip)
    formattedParams.remote_ip = String(item.params.remote_ip);
  if (!("protocol" in formattedParams) && item.params?.protocol)
    formattedParams.protocol = String(item.params.protocol);
  if (!("provider" in formattedParams) && item.params?.provider)
    formattedParams.provider = String(item.params.provider);
  if (!("protocol_name" in formattedParams))
    formattedParams.protocol_name = (item.params?.protocol_name ??
      item.params?.protocol ??
      "—") as string;
  if (!("application_name" in formattedParams))
    formattedParams.application_name = (item.params?.application_name ??
      item.params?.application ??
      "—") as string;
  if (!("destination_count" in formattedParams))
    formattedParams.destination_count = formattedParams.count ?? "—";
  if (!("upload_bytes" in formattedParams))
    formattedParams.upload_bytes =
      formattedParams.bytes ?? formattedParams.tx_bytes ?? "—";
  if (!("bytes" in formattedParams))
    formattedParams.bytes =
      formattedParams.upload_bytes ?? formattedParams.current_bytes ?? "—";
  if (!("ratio" in formattedParams))
    formattedParams.ratio = formattedParams.multiplier ?? "—";

  // Wrap in Proxy to guarantee that no missing ICU context variable will ever trigger FORMATTING_ERROR
  const safeParams = new Proxy(formattedParams, {
    has: () => true,
    get: (target, prop) =>
      typeof prop === "string" && prop in target ? target[prop] : "—",
    ownKeys: (target) =>
      Array.from(new Set([...Reflect.ownKeys(target), ...COMMON_PARAM_KEYS])),
    getOwnPropertyDescriptor: (target, prop) => ({
      value: typeof prop === "string" && prop in target ? target[prop] : "—",
      writable: true,
      enumerable: true,
      configurable: true,
    }),
  });

  let title = item.code;
  let reason = item.source;

  try {
    if (typeof tObj.has === "function" && tObj.has(titleKey)) {
      title = translate(
        titleKey,
        safeParams as Record<string, string | number>,
      );
    }
  } catch {
    title = item.code;
  }

  try {
    if (typeof tObj.has === "function" && tObj.has(reasonKey)) {
      reason = translate(
        reasonKey,
        safeParams as Record<string, string | number>,
      );
    }
  } catch {
    reason = item.source;
  }

  return { title, reason };
}

export function InsightsDashboard({ username }: { username: string }) {
  const t = useTranslations("insights");
  const tNav = useTranslations("navigation");
  const tStatus = useTranslations("common.status");

  const translate = t as unknown as TranslationFn;
  const tObj = t as unknown as TranslationObject;

  const [items, setItems] = useState<Insight[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<Insight | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const metaFor = (category: InsightCategory) => {
    const Icon = categoryIcons[category] ?? Activity;
    const accent =
      categoryAccents[category] ??
      "text-foreground-secondary bg-surface-subtle";
    const categoryKey = `categories.${category}`;
    const label =
      typeof tObj.has === "function" && tObj.has(categoryKey)
        ? translate(categoryKey)
        : category;
    return { label, icon: Icon, accent };
  };

  const filters: Array<{ id: Filter; label: string }> = [
    { id: "all", label: t("filters.all") },
    { id: "devices", label: t("filters.devices") },
    { id: "traffic", label: t("filters.traffic") },
    { id: "security", label: t("filters.security") },
    { id: "quality", label: t("filters.quality") },
    { id: "system", label: t("filters.system") },
  ];

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const response = await fetch("/api/insights?limit=100", {
          cache: "no-store",
          signal: controller.signal,
        });
        const envelope = (await response.json()) as ApiEnvelope<Insight[]>;
        if (!response.ok)
          throw new Error(
            envelope.error?.message ??
              `Insights request failed (${response.status})`,
          );
        setItems(envelope.data);
        setError(null);
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

  const visible = useMemo(
    () =>
      items.filter((item) => {
        if (filter === "devices") return item.category === "device";
        if (filter === "traffic") return item.category === "traffic";
        if (filter === "security")
          return item.category === "protocol" || item.category === "dns";
        if (filter === "quality") return item.category === "classification";
        if (filter === "system") return item.category === "capture";
        return true;
      }),
    [filter, items],
  );

  const captureWarnings = useMemo(
    () => items.filter((item) => item.category === "capture"),
    [items],
  );
  const unknownInsight = useMemo(
    () =>
      items.find((item) => item.code === "classification.unknown_ratio_high"),
    [items],
  );

  const selectedText = useMemo(
    () => (selected ? resolveInsightText(selected, t) : null),
    [selected, t],
  );

  return (
    <AppLayout
      title={tNav("insights")}
      subtitle={t("subtitle")}
      username={username}
      isLive={false}
      warningBanner={
        captureWarnings.length
          ? t("captureWarningBanner", { count: captureWarnings.length })
          : undefined
      }
      headerActions={
        <button
          type="button"
          onClick={() => setReloadKey((value) => value + 1)}
          className="flex size-8 items-center justify-center rounded-md border border-border bg-surface text-foreground-secondary transition-colors hover:bg-surface-hover hover:text-foreground cursor-pointer"
          aria-label={t("refreshAria")}
          title={t("refreshAria")}
        >
          <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
        </button>
      }
    >
      <section
        className="overflow-hidden rounded-md border border-border bg-surface"
        aria-label="Insight summary"
      >
        <div className="grid grid-cols-1 divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
          <SummaryCell
            label={t("observed24h")}
            value={items.length.toLocaleString()}
            detail={t("findingsDetail")}
          />
          <SummaryCell
            label={t("unknownTraffic")}
            value={
              unknownInsight?.evidence.ratio !== undefined
                ? formatPercent(Number(unknownInsight.evidence.ratio))
                : "0.0%"
            }
            detail={t("coverageDetail")}
            warning={Boolean(unknownInsight)}
          />
          <SummaryCell
            label={t("captureQuality")}
            value={
              captureWarnings.length ? tStatus("review") : tStatus("clear")
            }
            detail={
              captureWarnings.length
                ? t("conditionsDetail", { count: captureWarnings.length })
                : t("noDegradation")
            }
            warning={captureWarnings.length > 0}
          />
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <Tabs
          value={filter}
          onValueChange={(val) => setFilter(val as Filter)}
          variant="pill"
          className="w-auto"
        >
          <TabsList className="h-8 p-0.5 bg-surface-subtle/80 border border-border">
            {filters.map((item) => (
              <TabsTrigger
                key={item.id}
                value={item.id}
                className="h-7 px-3 text-xs font-medium"
              >
                {item.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <span className="px-2 font-mono text-[11px] text-foreground-muted">
          {t("matchesCount", { count: visible.length })}
        </span>
      </div>

      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={t("observationsScope")}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : loading ? (
        <TableSkeleton rows={6} cols={3} />
      ) : visible.length === 0 ? (
        <EmptyState title={t("noMatching")} description={t("noMatchingDesc")} />
      ) : (
        <section
          className="overflow-hidden rounded-md border border-border bg-surface"
          aria-label="Insight evidence ledger"
        >
          <div className="grid grid-cols-[40px_minmax(0,1fr)_auto] border-b border-border bg-surface-subtle/50 px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground-muted">
            <span aria-hidden="true" />
            <span>{t("observationReason")}</span>
            <span className="pr-8">{t("time")}</span>
          </div>
          <div className="divide-y divide-border">
            {visible.map((item) => {
              const meta = metaFor(item.category);
              const Icon = meta.icon;
              const { title, reason } = resolveInsightText(item, t);
              const sourceKey = `sources.${item.source}`;
              const sourceLabel =
                typeof tObj.has === "function" && tObj.has(sourceKey)
                  ? translate(sourceKey)
                  : item.source;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelected(item)}
                  className="group grid w-full grid-cols-[40px_minmax(0,1fr)_auto] items-start gap-0 px-3 py-3 text-left outline-none transition-colors hover:bg-surface-hover focus-visible:bg-surface-hover focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring cursor-pointer"
                  aria-label={t("inspectAria", { title })}
                >
                  <span
                    className={cn(
                      "mt-0.5 flex size-7 items-center justify-center rounded-[5px]",
                      meta.accent,
                    )}
                  >
                    <Icon className="size-3.5" aria-hidden="true" />
                  </span>
                  <span className="min-w-0 pr-5">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-semibold text-foreground">
                        {title}
                      </span>
                      <span className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-foreground-muted">
                        {meta.label}
                      </span>
                    </span>
                    <span className="mt-1 block max-w-4xl text-[11px] leading-5 text-foreground-secondary">
                      {reason}
                    </span>
                    <span className="mt-1 block font-mono text-[9px] uppercase tracking-wider text-foreground-muted">
                      {sourceLabel}
                      {item.affected_client
                        ? ` · ${item.affected_client.name}`
                        : ""}
                    </span>
                  </span>
                  <span
                    className="flex items-center gap-3 whitespace-nowrap pl-3 text-[10px] text-foreground-muted"
                    title={formatTimestamp(item.time, "tooltip")}
                  >
                    {formatTimestamp(item.time, "relative")}
                    <ChevronRight
                      className="size-3.5 transition-transform group-hover:translate-x-0.5"
                      aria-hidden="true"
                    />
                  </span>
                </button>
              );
            })}
          </div>
        </section>
      )}

      <SidePanel
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selectedText?.title ?? tNav("insights")}
        subtitle={
          selected
            ? `${metaFor(selected.category).label} · ${formatTimestamp(selected.time, "date")}`
            : undefined
        }
        width="md"
      >
        {selected && (
          <>
            <section className="rounded-md border border-border bg-surface-subtle/50 p-3">
              <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground-muted">
                <CircleHelp className="size-3.5" />
                {t("whyAppeared")}
              </div>
              <p className="mt-2 text-xs leading-5 text-foreground-secondary">
                {selectedText?.reason}
              </p>
            </section>
            <section>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground-muted">
                {t("provenance")}
              </h3>
              <PropertyRow
                label={t("ruleSource")}
                value={
                  typeof tObj.has === "function" &&
                  tObj.has(`sources.${selected.source}`)
                    ? translate(`sources.${selected.source}`)
                    : selected.source
                }
                mono
              />
              <PropertyRow
                label={t("observedAt")}
                value={formatTimestamp(selected.time, "tooltip")}
                mono
              />
              <PropertyRow
                label={t("severity")}
                value={
                  typeof tObj.has === "function" &&
                  tObj.has(`severities.${selected.severity}`)
                    ? translate(`severities.${selected.severity}`)
                    : selected.severity
                }
              />
              {selected.affected_client && (
                <PropertyRow
                  label={t("affectedClient")}
                  value={selected.affected_client.name}
                />
              )}
              {selected.affected_client?.ip && (
                <PropertyRow
                  label={t("clientIp")}
                  value={selected.affected_client.ip}
                  copyable
                  mono
                />
              )}
              {selected.affected_client?.mac && (
                <PropertyRow
                  label={t("clientMac")}
                  value={selected.affected_client.mac}
                  copyable
                  mono
                />
              )}
            </section>
            <section>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground-muted">
                {t("evidence")}
              </h3>
              {Object.entries(selected.evidence).map(([key, value]) => {
                const labelKey = `evidenceLabels.${key}`;
                const label =
                  typeof tObj.has === "function" && tObj.has(labelKey)
                    ? translate(labelKey)
                    : labelFor(key);
                return (
                  <PropertyRow
                    key={key}
                    label={label}
                    value={evidenceValue(key, value, translate)}
                    mono={
                      typeof value === "number" ||
                      key.includes("ip") ||
                      key.includes("mac")
                    }
                  />
                );
              })}
            </section>
            {selected.category === "dns" && (
              <p className="rounded-md border border-border bg-surface-subtle p-3 text-[11px] leading-5 text-foreground-muted">
                {t("encryptedDnsDisclaimer")}
              </p>
            )}
          </>
        )}
      </SidePanel>
    </AppLayout>
  );
}

function SummaryCell({
  label,
  value,
  detail,
  warning = false,
}: {
  label: string;
  value: string;
  detail: string;
  warning?: boolean;
}) {
  return (
    <div className="px-4 py-3">
      <div className="text-[9px] font-semibold uppercase tracking-[0.14em] text-foreground-muted">
        {label}
      </div>
      <div
        className={cn(
          "mt-1 font-mono text-lg font-semibold tracking-tight",
          warning ? "text-warning" : "text-foreground",
        )}
      >
        {value}
      </div>
      <div className="mt-0.5 text-[10px] text-foreground-muted">{detail}</div>
    </div>
  );
}
