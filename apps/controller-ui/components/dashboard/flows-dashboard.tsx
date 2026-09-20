"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ExternalLink } from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { ApplicationIcon } from "@/components/icons/application-icon";
import { CategoryIcon } from "@/components/icons/category-icon";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import { ProtocolIcon } from "@/components/icons/protocol-icon";
import {
  DataTable,
  type ColumnDef,
  type SortState,
} from "@/components/data/data-table";
import { FilterBar, type FilterChip } from "@/components/data/filter-bar";
import {
  TimeRangePicker,
  type CustomDateRange,
  type TimeRangeValue,
} from "@/components/data/time-range-picker";
import {
  FlowDirection,
  type FlowDirectionType,
} from "@/components/network/flow-direction";
import { FlowPanel } from "@/components/overlays/flow-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { SimpleTooltip } from "@/components/ui/tooltip";
import { useTopologyLabels } from "@/hooks/use-topology-labels";
import {
  formatBytes,
  formatDuration,
  formatIdentifier,
  formatTimestamp,
  ipInfoUrl,
  isLocalIp,
} from "@/lib/formatters";
import type { ApiEnvelope, FlowSummary } from "@/lib/network-types";

const PAGE_SIZE = 50;
const RANGE_MS: Record<string, number> = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 604_800_000,
  "30d": 2_592_000_000,
};

function protocolName(protocol: number) {
  return protocol === 6 ? "TCP" : protocol === 17 ? "UDP" : String(protocol);
}
function directionName(direction: number): FlowDirectionType {
  return direction === 1 ? "upload" : direction === 2 ? "download" : "unknown";
}
function rangeBounds(range: TimeRangeValue, from?: string, to?: string) {
  const end = range === "custom" && to ? Date.parse(to) : Date.now();
  const start =
    range === "custom" && from
      ? Date.parse(from)
      : end - (RANGE_MS[range] ?? RANGE_MS["24h"]);
  return { from: start, to: end };
}
function decodeHistory(value?: string) {
  if (!value) return [] as string[];
  try {
    const parsed = JSON.parse(atob(value));
    return Array.isArray(parsed) &&
      parsed.every((item) => typeof item === "string")
      ? parsed
      : [];
  } catch {
    return [];
  }
}
function encodeHistory(value: string[]) {
  return value.length ? btoa(JSON.stringify(value)) : undefined;
}

interface Props {
  username: string;
  initialRange: TimeRangeValue;
  initialFrom?: string;
  initialTo?: string;
  initialSearch: string;
  initialClient: string;
  initialApplication: string;
  initialDomain: string;
  initialIp: string;
  initialProtocol: string;
  initialPort: string;
  initialDirection: string;
  initialScope: string;
  initialPathType: string;
  initialNat: string;
  initialSort: string;
  initialOrder: "asc" | "desc";
  initialCursor?: string;
  initialHistory?: string;
  initialSelectedFlow?: string;
}

export function FlowsDashboard(props: Props) {
  const t = useTranslations("flows");
  const tNav = useTranslations("navigation");
  const tDir = useTranslations("common.direction");
  const tStatus = useTranslations("common.status");
  const tActions = useTranslations("common.actions");
  const topologyLabels = useTopologyLabels();
  const router = useRouter();

  const [items, setItems] = useState<FlowSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [search, setSearch] = useState(props.initialSearch);
  const [topologyMode, setTopologyMode] = useState("");
  const [draft, setDraft] = useState({
    client: props.initialClient,
    application: props.initialApplication,
    domain: props.initialDomain,
    ip: props.initialIp,
    port: props.initialPort,
  });
  const selected =
    items.find((item) => item.id === props.initialSelectedFlow) ?? null;
  const history = useMemo(
    () => decodeHistory(props.initialHistory),
    [props.initialHistory],
  );

  const filterLabels: Record<string, string> = {
    client: t("filterLabels.client"),
    application: t("filterLabels.application"),
    domain: t("filterLabels.domain"),
    ip: t("filterLabels.ip"),
    protocol: t("filterLabels.protocol"),
    port: t("filterLabels.port"),
    direction: t("filterLabels.direction"),
    scope: t("filterLabels.scope"),
    path_type: t("filterLabels.path"),
    nat: t("filterLabels.nat"),
  };

  const updateUrl = (
    changes: Record<string, string | undefined>,
    resetCursor = false,
  ) => {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(changes)) {
      if (value) params.set(key, value);
      else params.delete(key);
    }
    if (resetCursor) {
      params.delete("cursor");
      params.delete("history");
      params.delete("flow");
    }
    router.replace(`/flows${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (search !== props.initialSearch)
        updateUrl({ search: search || undefined }, true);
    }, 300);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, props.initialSearch]);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const bounds = rangeBounds(
          props.initialRange,
          props.initialFrom,
          props.initialTo,
        );
        const params = new URLSearchParams({
          limit: String(PAGE_SIZE),
          from: String(bounds.from),
          to: String(bounds.to),
          sort: props.initialSort,
          order: props.initialOrder,
        });
        const values: Record<string, string | undefined> = {
          cursor: props.initialCursor,
          search: props.initialSearch,
          client: props.initialClient,
          application: props.initialApplication,
          domain: props.initialDomain,
          ip: props.initialIp,
          protocol: props.initialProtocol,
          port: props.initialPort,
          direction: props.initialDirection,
          scope: props.initialScope,
          path_type: props.initialPathType,
          nat: props.initialNat,
        };
        for (const [key, value] of Object.entries(values))
          if (value) params.set(key, value);
        const response = await fetch(`/api/flows?${params}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        const envelope = (await response.json()) as ApiEnvelope<FlowSummary[]>;
        if (!response.ok)
          throw new Error(
            envelope.error?.message ??
              `Flows request failed (${response.status})`,
          );
        setItems(envelope.data);
        setNextCursor(envelope.pagination?.next_cursor ?? null);
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
    props.initialApplication,
    props.initialClient,
    props.initialCursor,
    props.initialDirection,
    props.initialDomain,
    props.initialFrom,
    props.initialIp,
    props.initialNat,
    props.initialOrder,
    props.initialPathType,
    props.initialPort,
    props.initialProtocol,
    props.initialRange,
    props.initialScope,
    props.initialSearch,
    props.initialSort,
    props.initialTo,
    reloadKey,
    t,
  ]);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/settings/diagnostics", { signal: controller.signal })
      .then((response) => (response.ok ? response.json() : null))
      .then((envelope) =>
        setTopologyMode(envelope?.data?.topology?.topology_mode || ""),
      )
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  const filterValues: Record<string, string> = {
    client: props.initialClient,
    application: props.initialApplication,
    domain: props.initialDomain,
    ip: props.initialIp,
    protocol: props.initialProtocol,
    port: props.initialPort,
    direction: props.initialDirection,
    scope: props.initialScope,
    path_type: props.initialPathType,
    nat: props.initialNat,
  };
  const activeFilters: FilterChip[] = Object.entries(filterValues)
    .filter(([, value]) => value)
    .map(([key, value]) => {
      const group =
        key === "scope"
          ? "scope"
          : key === "path_type"
            ? "path"
            : key === "nat"
              ? "nat"
              : null;
      return {
        key,
        label: filterLabels[key] ?? key,
        value,
        displayValue: group
          ? (topologyLabels.value(group, value) ?? value)
          : value.toUpperCase(),
      };
    });

  const hasDraftValues = Boolean(
    draft.client || draft.application || draft.domain || draft.ip || draft.port,
  );
  const resetDraft = () =>
    setDraft({ client: "", application: "", domain: "", ip: "", port: "" });
  const applyDraft = (event: React.FormEvent) => {
    event.preventDefault();
    updateUrl(
      Object.fromEntries(
        Object.entries(draft).map(([key, value]) => [key, value || undefined]),
      ),
      true,
    );
  };

  const customFilters = (
    <form onSubmit={applyDraft} className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
          {t("exactFilters")}
        </span>
        {hasDraftValues && (
          <button
            type="button"
            onClick={resetDraft}
            className="text-[11px] font-medium text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            {tActions("clearAll")}
          </button>
        )}
      </div>
      <div className="space-y-2.5">
        <div className="grid grid-cols-2 gap-2.5">
          <div className="space-y-1">
            <Label className="text-[11px] font-medium text-foreground-muted">
              {filterLabels.client}
            </Label>
            <Input
              value={draft.client}
              placeholder="IP / MAC / Name"
              className="h-8 text-xs"
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  client: event.target.value,
                }))
              }
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[11px] font-medium text-foreground-muted">
              {filterLabels.application}
            </Label>
            <Input
              value={draft.application}
              placeholder="e.g. YouTube, SSH"
              className="h-8 text-xs"
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  application: event.target.value,
                }))
              }
            />
          </div>
        </div>
        <div className="space-y-1">
          <Label className="text-[11px] font-medium text-foreground-muted">
            {filterLabels.domain}
          </Label>
          <Input
            value={draft.domain}
            placeholder="e.g. *.github.com"
            className="h-8 text-xs"
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                domain: event.target.value,
              }))
            }
          />
        </div>
        <div className="grid grid-cols-5 gap-2.5">
          <div className="col-span-3 space-y-1">
            <Label className="text-[11px] font-medium text-foreground-muted">
              {filterLabels.ip}
            </Label>
            <Input
              value={draft.ip}
              placeholder="e.g. 1.1.1.1"
              className="h-8 text-xs font-mono"
              onChange={(event) =>
                setDraft((current) => ({ ...current, ip: event.target.value }))
              }
            />
          </div>
          <div className="col-span-2 space-y-1">
            <Label className="text-[11px] font-medium text-foreground-muted">
              {filterLabels.port}
            </Label>
            <Input
              value={draft.port}
              placeholder="443"
              className="h-8 text-xs font-mono"
              inputMode="numeric"
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  port: event.target.value,
                }))
              }
            />
          </div>
        </div>
      </div>
      <div className="flex items-center justify-end gap-2 pt-1.5 border-t border-border/40">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={resetDraft}
          disabled={!hasDraftValues}
          className="h-7.5 px-2.5 text-xs"
        >
          {tActions("clearAll")}
        </Button>
        <Button
          type="submit"
          variant="default"
          size="sm"
          className="h-7.5 px-3.5 text-xs font-medium"
        >
          {t("applyFilters")}
        </Button>
      </div>
    </form>
  );

  const handleRange = (range: TimeRangeValue, custom?: CustomDateRange) =>
    updateUrl({ range, from: custom?.from, to: custom?.to }, true);
  const sortState: SortState = {
    columnId: props.initialSort,
    direction: props.initialOrder,
  };
  const handleSort = (sort: SortState) =>
    updateUrl(
      { sort: sort.columnId || "last_seen", order: sort.direction || "desc" },
      true,
    );

  const columns: ColumnDef<FlowSummary>[] = [
    {
      id: "last_seen",
      header: t("columns.time"),
      sortable: true,
      cell: (row) => (
        <SimpleTooltip content={formatTimestamp(row.last_seen, "tooltip")}>
          <span className="cursor-default">
            {formatTimestamp(row.last_seen, "table")}
          </span>
        </SimpleTooltip>
      ),
    },
    {
      id: "client",
      header: t("columns.client"),
      cell: (row) => (
        <div className="flex min-w-0 items-center gap-2">
          <ClientDeviceIcon
            client={{
              name: row.client_name ?? row.client_ip,
              mac: row.client_mac,
              identity: row.client_identity,
            }}
            size="md"
          />
          <div className="min-w-0">
            <div className="truncate font-medium">
              {row.client_name || row.client_ip}
            </div>
            {row.client_name && (
              <div className="truncate font-mono text-[10px] text-foreground-muted">
                {row.client_ip}
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      id: "application",
      header: t("columns.classification"),
      cell: (row) => {
        const applicationId = row.application;
        const name =
          applicationId === "unknown"
            ? !row.protocol_id || row.protocol_id === "unknown"
              ? tStatus("unknown")
              : row.protocol_id
            : row.application_name || formatIdentifier(applicationId);
        return (
          <div className="flex min-w-0 items-center gap-2">
            {applicationId !== "unknown" ? (
              <ApplicationIcon
                applicationId={applicationId}
                category={row.category}
                icon={row.icon}
                size="md"
              />
            ) : row.category && row.category !== "unknown" ? (
              <CategoryIcon category={row.category} size="md" />
            ) : (
              <ProtocolIcon protocol={row.protocol_id ?? "unknown"} size="md" />
            )}
            <div className="min-w-0">
              <div className="truncate font-medium">{name}</div>
              <div className="truncate text-[10px] text-foreground-muted">
                {row.category || tStatus("unknown")} ·{" "}
                {row.traffic_role || row.organization || tStatus("unknown")}
              </div>
            </div>
          </div>
        );
      },
    },
    {
      id: "destination",
      header: t("columns.destination"),
      cell: (row) => (
        <div>
          {row.domain ? (
            <div className="max-w-56 truncate" title={row.domain}>
              {row.domain}
            </div>
          ) : !isLocalIp(row.remote_ip) ? (
            <a
              href={ipInfoUrl(row.remote_ip)}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="group inline-flex max-w-56 items-center gap-1 truncate font-mono text-foreground hover:text-accent hover:underline"
              title={row.remote_ip}
            >
              <span className="truncate">{row.remote_ip}</span>
              <ExternalLink className="size-3 shrink-0 opacity-0 group-hover:opacity-70 transition-opacity" />
            </a>
          ) : (
            <div className="max-w-56 truncate font-mono" title={row.remote_ip}>
              {row.remote_ip}
            </div>
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
      header: t("columns.transport"),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <ProtocolIcon
            protocol={
              row.protocol_id && row.protocol_id !== "unknown"
                ? row.protocol_id
                : protocolName(row.protocol)
            }
          />{" "}
          <span>
            {protocolName(row.protocol)} · {row.remote_port}
          </span>
        </div>
      ),
    },
    {
      id: "direction",
      header: t("columns.direction"),
      cell: (row) => <FlowDirection direction={directionName(row.direction)} />,
    },
    {
      id: "scope",
      header: t("columns.scope"),
      cell: (row) => topologyLabels.value("scope", row.scope),
    },
    {
      id: "path",
      header: t("columns.path"),
      cell: (row) => topologyLabels.value("path", row.path_type),
    },
    {
      id: "download",
      header: t("columns.download"),
      align: "right",
      sortable: true,
      cell: (row) => formatBytes(row.download_bytes),
    },
    {
      id: "upload",
      header: t("columns.upload"),
      align: "right",
      sortable: true,
      cell: (row) => formatBytes(row.upload_bytes),
    },
    {
      id: "duration",
      header: t("columns.duration"),
      align: "right",
      sortable: true,
      cell: (row) =>
        formatDuration(
          Math.max(
            0,
            ((row.ended_at ?? row.last_seen) - row.started_at) / 1_000,
          ),
        ),
    },
  ];

  const toolbar = (
    <FilterBar
      searchValue={search}
      onSearchChange={setSearch}
      searchPlaceholder={t("searchPlaceholder")}
      activeFilters={activeFilters}
      filterOptions={[
        {
          key: "protocol",
          label: t("filterLabels.protocol"),
          options: [
            { value: "tcp", label: "TCP" },
            { value: "udp", label: "UDP" },
          ],
        },
        {
          key: "direction",
          label: t("filterLabels.direction"),
          options: [
            { value: "upload", label: tDir("upload") },
            { value: "download", label: tDir("download") },
            { value: "unknown", label: tDir("unknown") },
          ],
        },
        {
          key: "scope",
          label: t("filterLabels.scope"),
          options: [
            { value: "internet", label: t("values.internet") },
            { value: "internal", label: t("values.internal") },
            { value: "tunnel", label: t("values.tunnel") },
            { value: "unknown", label: tStatus("unknown") },
          ],
        },
        {
          key: "path_type",
          label: t("filterLabels.path"),
          options: [
            { value: "forwarded", label: t("values.forwarded") },
            { value: "internal", label: t("values.internal") },
            { value: "tunnel", label: t("values.tunnel") },
            { value: "unknown", label: tStatus("unknown") },
          ],
        },
        {
          key: "nat",
          label: t("filterLabels.nat"),
          options: [
            { value: "none", label: t("values.none") },
            { value: "snat", label: t("values.snat") },
            { value: "dnat", label: t("values.dnat") },
            { value: "both", label: t("values.both") },
            { value: "unknown", label: tStatus("unknown") },
          ],
        },
      ]}
      onSelectFilter={(key, value) => updateUrl({ [key]: value }, true)}
      onRemoveFilter={(filter) => updateUrl({ [filter.key]: undefined }, true)}
      onClearFilters={() =>
        updateUrl(
          {
            client: undefined,
            application: undefined,
            domain: undefined,
            ip: undefined,
            protocol: undefined,
            port: undefined,
            direction: undefined,
            scope: undefined,
            path_type: undefined,
            nat: undefined,
          },
          true,
        )
      }
      onRefresh={() => setReloadKey((value) => value + 1)}
      customFilterContent={customFilters}
      rightSlot={
        <TimeRangePicker
          value={props.initialRange}
          onChange={handleRange}
          customRange={
            props.initialFrom && props.initialTo
              ? { from: props.initialFrom, to: props.initialTo }
              : undefined
          }
        />
      }
    />
  );

  return (
    <AppLayout
      title={tNav("flows")}
      subtitle={t("subtitle")}
      username={props.username}
      isLive={false}
      toolbar={toolbar}
    >
      {error ? (
        <ErrorState
          title={t("unavailable")}
          message={error}
          affectedScope={t("sessionsScope")}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : (
        <DataTable
          columns={columns}
          data={items}
          keyExtractor={(row) => row.id}
          loading={loading}
          onRowClick={(row) => updateUrl({ flow: row.id })}
          sortState={sortState}
          onSortChange={handleSort}
          pagination={{
            pageIndex: history.length,
            pageSize: PAGE_SIZE,
            hasPrevious: history.length > 0,
            hasNext: Boolean(nextCursor),
            onPreviousPage: () => {
              const previous = [...history];
              const cursor = previous.pop();
              updateUrl({
                cursor: cursor || undefined,
                history: encodeHistory(previous),
                flow: undefined,
              });
            },
            onNextPage: () =>
              nextCursor &&
              updateUrl({
                cursor: nextCursor,
                history: encodeHistory([...history, props.initialCursor ?? ""]),
                flow: undefined,
              }),
            totalDisplay: t("showingCount", { count: items.length }),
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
      <FlowPanel
        flow={selected}
        topologyMode={topologyMode}
        onClose={() => updateUrl({ flow: undefined })}
      />
    </AppLayout>
  );
}
