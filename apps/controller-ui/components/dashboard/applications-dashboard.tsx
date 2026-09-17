"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { DataTable, type ColumnDef } from "@/components/data/data-table";
import { ApplicationIdentity } from "@/components/network/application-identity";
import { PropertyRow, SidePanel } from "@/components/overlays/side-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  formatBytes,
  formatIdentifier,
  formatPackets,
  formatTimestamp,
} from "@/lib/formatters";
import type { ApiEnvelope, ApplicationSummary } from "@/lib/network-types";

export function ApplicationsDashboard({
  username,
  initialSearch,
}: {
  username: string;
  initialSearch: string;
}) {
  const t = useTranslations("applications");
  const tNav = useTranslations("navigation");
  const tStatus = useTranslations("common.status");
  const router = useRouter();
  const searchParams = useSearchParams();
  const searchRef = useRef<HTMLInputElement>(null);

  const [items, setItems] = useState<ApplicationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState(initialSearch);
  const [reloadKey, setReloadKey] = useState(0);
  const selectedQuery = {
    id: searchParams.get("id") ?? undefined,
    category: searchParams.get("category") ?? undefined,
  };

  const selected =
    items.find(
      (item) =>
        item.application_id === selectedQuery.id &&
        (!selectedQuery.category ||
          item.category_id === selectedQuery.category),
    ) ?? null;

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      try {
        const response = await fetch("/api/applications?limit=200", {
          cache: "no-store",
          signal: controller.signal,
        });
        const envelope = (await response.json()) as ApiEnvelope<
          ApplicationSummary[]
        >;
        if (!response.ok)
          throw new Error(
            envelope.error?.message ??
              `Applications request failed (${response.status})`,
          );
        setItems(envelope.data);
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
  }, [reloadKey, t]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if (event.key === "/" && !(event.target instanceof HTMLInputElement)) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, []);

  const replaceQuery = (next: {
    search?: string;
    id?: string;
    category?: string;
  }) => {
    const params = new URLSearchParams(window.location.search);
    if (next.search !== undefined) {
      if (next.search) params.set("search", next.search);
      else params.delete("search");
    }
    if (next.id !== undefined) {
      if (next.id) params.set("id", next.id);
      else params.delete("id");
    }
    if (next.category !== undefined) {
      if (next.category) params.set("category", next.category);
      else params.delete("category");
    }
    router.replace(`/applications${params.size ? `?${params}` : ""}`, {
      scroll: false,
    });
  };

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return items;
    return items.filter(
      (item) =>
        item.application_id.toLowerCase().includes(query) ||
        (item.name ?? "").toLowerCase().includes(query) ||
        item.category_id.toLowerCase().includes(query) ||
        (item.organization_id ?? "").toLowerCase().includes(query) ||
        (item.organization_name ?? "").toLowerCase().includes(query),
    );
  }, [items, search]);

  const columns: ColumnDef<ApplicationSummary>[] = [
    {
      id: "application",
      header: t("columns.application"),
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
      id: "organization",
      header: t("columns.organization"),
      cell: (row) =>
        row.organization_id && row.organization_id !== "unknown"
          ? row.organization_name || formatIdentifier(row.organization_id)
          : tStatus("unknown"),
    },
    {
      id: "category",
      header: t("columns.trafficClass"),
      accessorKey: "category_id",
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
    {
      id: "last_seen",
      header: t("columns.lastSeen"),
      align: "right",
      cell: (row) => formatTimestamp(row.last_seen, "relative"),
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
      <span className="shrink-0 text-[11px] text-foreground-muted">
        {t("applicationsCount", { count: filtered.length })}
      </span>
    </div>
  );

  return (
    <AppLayout
      title={tNav("applications")}
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
        <DataTable
          columns={columns}
          data={filtered}
          keyExtractor={(row) => `${row.application_id}:${row.category_id}`}
          loading={loading}
          onRowClick={(row) => {
            replaceQuery({ id: row.application_id, category: row.category_id });
          }}
          emptyState={
            <EmptyState
              title={t("notFound")}
              description={search ? t("notFoundSearch") : t("notFoundEmpty")}
              className="border-0 bg-transparent"
            />
          }
        />
      )}

      <SidePanel
        open={Boolean(selected)}
        onClose={() => {
          replaceQuery({ id: "", category: "" });
        }}
        title={
          selected?.application_id === "unknown"
            ? tStatus("unknown")
            : selected?.name ||
              (selected?.application_id
                ? formatIdentifier(selected.application_id)
                : t("columns.application"))
        }
        subtitle={
          selected?.category_id
            ? `${t("columns.trafficClass")}: ${selected.category_id}`
            : undefined
        }
        footerActions={
          selected && (
            <div className="ml-auto">
              <Link
                href={`/applications/${encodeURIComponent(selected.application_id)}?category=${encodeURIComponent(selected.category_id)}`}
                className={buttonVariants({ size: "sm" })}
              >
                {t("openFullDetails")}
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
                {t("properties.properties")}
              </h3>
              <PropertyRow
                label={t("properties.organization")}
                value={
                  selected.organization_id &&
                  selected.organization_id !== "unknown"
                    ? selected.organization_name ||
                      formatIdentifier(selected.organization_id)
                    : tStatus("unknown")
                }
              />
              <PropertyRow
                label={t("properties.trafficClass")}
                value={selected.category_id || tStatus("unknown")}
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
                label={t("properties.packets")}
                value={formatPackets(selected.packets)}
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
