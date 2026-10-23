"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  Clock3,
  FileCode2,
  Info,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { SidePanel } from "@/components/overlays/side-panel";
import { EmptyState } from "@/components/states/empty-state";
import { ErrorState } from "@/components/states/error-state";
import { TableSkeleton } from "@/components/states/loading-state";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SimpleTooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  formatPolicyYaml,
  parsePolicyYaml,
  PolicyYamlError,
} from "@/lib/policy-yaml";
import type {
  ApiEnvelope,
  PolicyActionKind,
  PolicyDetail,
  PolicyDeployment,
  PolicyOption,
  PolicyPage,
  PolicyPreviewRequest,
  PolicyPreviewResult,
  PolicyRecord,
  PolicySpecV1,
  PolicyValidation,
  PolicyTrafficMetrics,
  PolicyWeekday,
} from "@/lib/network-types";

const PAGE_SIZE = 10;
const FETCH_PAGE_SIZE = 100;
const WEEKDAYS: PolicyWeekday[] = [
  "mon",
  "tue",
  "wed",
  "thu",
  "fri",
  "sat",
  "sun",
];
const ACTIONS: PolicyActionKind[] = ["block", "allow", "limit"];
const CAPABILITY_KEYS = [
  "client_block",
  "client_limit",
  "application_block",
  "application_limit",
] as const;
type PolicyTranslate = {
  (key: string, values?: Record<string, string | number>): string;
  has: (key: string) => boolean;
};
type DashboardConfirmation =
  { kind: "toggle" | "delete"; record: PolicyRecord } | { kind: "republish" };

class PolicyRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

async function requestData<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { cache: "no-store", ...init });
  if (response.status === 204) return undefined as T;
  let payload: ApiEnvelope<T> & {
    error?: { code?: string; message?: string; details?: unknown };
  };
  try {
    payload = (await response.json()) as typeof payload;
  } catch {
    throw new PolicyRequestError(
      "Unexpected response from Collector",
      response.status,
    );
  }
  if (!response.ok) {
    throw new PolicyRequestError(
      payload.error?.message ?? `Request failed (${response.status})`,
      response.status,
      payload.error?.code,
      payload.error?.details,
    );
  }
  return payload.data;
}

function defaultSpec(gatewayId: string): PolicySpecV1 {
  return {
    schema_version: 1,
    gateway_id: gatewayId,
    name: "",
    description: "",
    enabled: false,
    priority: 500,
    selectors: {
      clients: [],
      applications: [],
      categories: [],
      min_application_confidence: 0.8,
    },
    network: { scope: "internet", direction: "both" },
    action: { type: "block", download_bps: null, upload_bps: null },
    schedule: null,
  };
}

function apiErrorText(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

function policyReasonText(
  code: string | null,
  message: string | null,
  t: PolicyTranslate,
) {
  const key = `reasons.${code}`;
  const description = code && t.has(key) ? t(key) : message;
  if (!description) return code;
  return code ? `${code}: ${description}` : description;
}

function selectorSummary(spec: PolicySpecV1, t: (key: string) => string) {
  const parts = [
    ...spec.selectors.clients,
    ...spec.selectors.applications.map((id) => `app:${id}`),
    ...spec.selectors.categories.map((id) => `category:${id}`),
  ];
  return parts.length ? parts.join(", ") : t("anySelector");
}

function actionSummary(spec: PolicySpecV1, t: (key: string) => string) {
  if (spec.action.type !== "limit") return t(`actions.${spec.action.type}`);
  const rates = [
    spec.action.download_bps !== null
      ? `${t("download")} ${formatMbps(spec.action.download_bps)}`
      : null,
    spec.action.upload_bps !== null
      ? `${t("upload")} ${formatMbps(spec.action.upload_bps)}`
      : null,
  ].filter(Boolean);
  return `${t("actions.limit")} · ${rates.join(" / ")}`;
}

function formatMbps(value: number) {
  return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 3).replace(/\.000$/, "")} Mbps`;
}

function formatBytes(value: number) {
  if (value < 1_000) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value / 1_000;
  let unit = units[0];
  for (let index = 1; scaled >= 1_000 && index < units.length; index += 1) {
    scaled /= 1_000;
    unit = units[index];
  }
  return `${scaled.toFixed(scaled >= 100 ? 0 : 1)} ${unit}`;
}

function formatTimestamp(timestamp: number | null | undefined) {
  return timestamp === null || timestamp === undefined
    ? null
    : new Date(timestamp).toLocaleString();
}

function statusClass(status: string) {
  if (status === "unsupported" || status === "degraded" || status === "failed")
    return "border-warning/30 bg-warning-soft text-warning";
  if (status === "not_deployed")
    return "border-border bg-surface-subtle text-foreground-muted";
  return "border-border bg-surface-subtle text-foreground-muted";
}

function visualUnsupportedPath(value: unknown): string | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return "spec";
  }
  const spec = value as Record<string, unknown>;
  const allowedTop = new Set([
    "schema_version",
    "gateway_id",
    "name",
    "description",
    "enabled",
    "priority",
    "selectors",
    "network",
    "action",
    "schedule",
  ]);
  const extraTop = Object.keys(spec).find((key) => !allowedTop.has(key));
  if (extraTop) return extraTop;
  const selectors = spec.selectors as Record<string, unknown> | undefined;
  if (!selectors || typeof selectors !== "object" || Array.isArray(selectors))
    return "selectors";
  const selectorKey = Object.keys(selectors).find(
    (key) =>
      ![
        "clients",
        "applications",
        "categories",
        "min_application_confidence",
      ].includes(key),
  );
  if (selectorKey) return `selectors.${selectorKey}`;
  const network = spec.network as Record<string, unknown> | undefined;
  if (!network || typeof network !== "object" || Array.isArray(network))
    return "network";
  const networkKey = Object.keys(network).find(
    (key) => !["scope", "direction"].includes(key),
  );
  if (networkKey) return `network.${networkKey}`;
  const action = spec.action as Record<string, unknown> | undefined;
  if (!action || typeof action !== "object" || Array.isArray(action))
    return "action";
  const actionKey = Object.keys(action).find(
    (key) => !["type", "download_bps", "upload_bps"].includes(key),
  );
  if (actionKey) return `action.${actionKey}`;
  if (spec.schedule !== null) {
    const schedule = spec.schedule as Record<string, unknown> | undefined;
    if (!schedule || typeof schedule !== "object" || Array.isArray(schedule))
      return "schedule";
    const scheduleKey = Object.keys(schedule).find(
      (key) => !["timezone", "windows"].includes(key),
    );
    if (scheduleKey) return `schedule.${scheduleKey}`;
    if (Array.isArray(schedule.windows)) {
      if (schedule.windows.length > 1) return "schedule.windows";
      for (const [index, rawWindow] of schedule.windows.entries()) {
        if (
          !rawWindow ||
          typeof rawWindow !== "object" ||
          Array.isArray(rawWindow)
        )
          return `schedule.windows[${index}]`;
        const window = rawWindow as Record<string, unknown>;
        const windowKey = Object.keys(window).find(
          (key) => !["days", "start", "end"].includes(key),
        );
        if (windowKey) return `schedule.windows[${index}].${windowKey}`;
      }
    }
  }
  return null;
}

function isPolicySpec(value: unknown): value is PolicySpecV1 {
  if (visualUnsupportedPath(value)) return false;
  const spec = value as PolicySpecV1;
  return (
    spec.schema_version === 1 &&
    typeof spec.gateway_id === "string" &&
    typeof spec.name === "string" &&
    typeof spec.description === "string" &&
    typeof spec.enabled === "boolean" &&
    Number.isInteger(spec.priority) &&
    Array.isArray(spec.selectors.clients) &&
    Array.isArray(spec.selectors.applications) &&
    Array.isArray(spec.selectors.categories) &&
    typeof spec.selectors.min_application_confidence === "number" &&
    (spec.network?.scope === "internet" ||
      (spec.network?.scope === "agent" && isClientTotalLimit(spec))) &&
    spec.network?.direction === "both" &&
    ACTIONS.includes(spec.action?.type) &&
    (spec.schedule === null ||
      (typeof spec.schedule.timezone === "string" &&
        Array.isArray(spec.schedule.windows) &&
        spec.schedule.windows.every(
          (window) =>
            Array.isArray(window.days) &&
            typeof window.start === "string" &&
            typeof window.end === "string",
        )))
  );
}

function isClientTotalLimit(spec: PolicySpecV1) {
  return (
    spec.action?.type === "limit" &&
    spec.selectors.clients.length > 0 &&
    spec.selectors.applications.length === 0 &&
    spec.selectors.categories.length === 0
  );
}

function withVisualScope(spec: PolicySpecV1): PolicySpecV1 {
  return {
    ...spec,
    network: {
      ...spec.network,
      scope: isClientTotalLimit(spec) ? "agent" : "internet",
    },
  };
}

export function PoliciesDashboard({ username }: { username: string }) {
  const t = useTranslations("policies") as unknown as PolicyTranslate;
  const common = useTranslations("common");
  const [gatewayOptions, setGatewayOptions] = useState<PolicyOption[]>([]);
  const [gatewayId, setGatewayId] = useState("");
  const [pageData, setPageData] = useState<PolicyPage | null>(null);
  const [deployment, setDeployment] = useState<PolicyDeployment | null>(null);
  const [policies, setPolicies] = useState<PolicyRecord[]>([]);
  const [loadingGateways, setLoadingGateways] = useState(true);
  const [loading, setLoading] = useState(false);
  const [pageError, setPageError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [stateFilter, setStateFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [editor, setEditor] = useState<{ record: PolicyRecord | null } | null>(
    null,
  );
  const [detail, setDetail] = useState<PolicyDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] =
    useState<DashboardConfirmation | null>(null);
  const [confirmationPending, setConfirmationPending] = useState(false);
  const [republishing, setRepublishing] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewInput, setPreviewInput] = useState<
    Omit<PolicyPreviewRequest, "gateway_id" | "scope" | "at_ms">
  >({
    client_mac: "",
    application_id: "",
    category_id: "unknown",
    application_confidence: 0.85,
  });
  const [previewResult, setPreviewResult] =
    useState<PolicyPreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const runPolicyPreview = async () => {
    if (!gatewayId) return;
    setPreviewLoading(true);
    setPreviewError(null);
    setPreviewResult(null);
    try {
      const result = await requestData<PolicyPreviewResult>(
        "/api/policies/preview",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ...previewInput,
            gateway_id: gatewayId,
            scope: "internet",
            at_ms: Date.now(),
          } satisfies PolicyPreviewRequest),
        },
      );
      setPreviewResult(result);
    } catch (error) {
      setPreviewError(apiErrorText(error));
    } finally {
      setPreviewLoading(false);
    }
  };

  const loadGateways = useCallback(async () => {
    setLoadingGateways(true);
    try {
      const result = await requestData<{ items: PolicyOption[] }>(
        "/api/policies/options?kind=gateways&page=1&page_size=100",
      );
      setGatewayOptions(result.items);
      setGatewayId((current) => current || result.items[0]?.id || "");
    } catch (error) {
      setPageError(apiErrorText(error));
    } finally {
      setLoadingGateways(false);
    }
  }, []);

  const loadPolicies = useCallback(async () => {
    if (!gatewayId) {
      setPolicies([]);
      setPageData(null);
      setDeployment(null);
      return;
    }
    setLoading(true);
    setPageError(null);
    try {
      const fetchPage = (pageNumber: number) =>
        requestData<PolicyPage>(
          `/api/policies?gateway_id=${encodeURIComponent(gatewayId)}&page=${pageNumber}&page_size=${FETCH_PAGE_SIZE}`,
        );
      const [first, status] = await Promise.all([
        fetchPage(1),
        requestData<PolicyDeployment>(
          `/api/policies/deployment?gateway_id=${encodeURIComponent(gatewayId)}`,
        ),
      ]);
      const pages = Math.ceil(first.total / FETCH_PAGE_SIZE);
      const additional = await Promise.all(
        Array.from({ length: Math.max(0, pages - 1) }, (_, index) =>
          fetchPage(index + 2),
        ),
      );
      const allPages = [first, ...additional];
      if (
        allPages.some(
          (result) => result.desired_revision !== first.desired_revision,
        )
      ) {
        throw new PolicyRequestError(
          t("listChangedRetry"),
          409,
          "revision_conflict",
        );
      }
      setPolicies(allPages.flatMap((result) => result.items));
      setPageData(first);
      setDeployment(status);
      setPage(1);
    } catch (error) {
      setPageError(apiErrorText(error));
    } finally {
      setLoading(false);
    }
  }, [gatewayId, t]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadGateways(), 0);
    return () => window.clearTimeout(timer);
  }, [loadGateways]);

  useEffect(() => {
    if (loadingGateways) return;
    const timer = window.setTimeout(() => void loadPolicies(), 0);
    return () => window.clearTimeout(timer);
  }, [loadingGateways, loadPolicies]);

  useEffect(() => {
    if (!gatewayId) return;
    let active = true;
    const refreshDeployment = async () => {
      if (typeof document !== "undefined" && document.hidden) return;
      try {
        const status = await requestData<PolicyDeployment>(
          `/api/policies/deployment?gateway_id=${encodeURIComponent(gatewayId)}`,
        );
        if (active) setDeployment(status);
      } catch {
        // Keep the last reported state visible during a temporary refresh failure.
      }
    };
    const handleVisibilityChange = () => {
      if (!document.hidden) void refreshDeployment();
    };
    const timer = window.setInterval(() => void refreshDeployment(), 5_000);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [gatewayId]);

  const filteredPolicies = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase();
    return policies.filter((record) => {
      const searchText = [
        record.spec.name,
        record.spec.description,
        ...record.spec.selectors.clients,
        ...record.spec.selectors.applications,
        ...record.spec.selectors.categories,
      ]
        .join(" ")
        .toLocaleLowerCase();
      return (
        (!normalizedQuery || searchText.includes(normalizedQuery)) &&
        (actionFilter === "all" || record.spec.action.type === actionFilter) &&
        (stateFilter === "all" ||
          (stateFilter === "enabled" && record.spec.enabled) ||
          (stateFilter === "disabled" && !record.spec.enabled))
      );
    });
  }, [policies, query, actionFilter, stateFilter]);

  const pageCount = Math.max(1, Math.ceil(filteredPolicies.length / PAGE_SIZE));
  const visiblePolicies = filteredPolicies.slice(
    (page - 1) * PAGE_SIZE,
    page * PAGE_SIZE,
  );

  const openDetail = useCallback(async (record: PolicyRecord) => {
    setDetailLoading(true);
    setDetail(null);
    try {
      setDetail(
        await requestData<PolicyDetail>(
          `/api/policies/${encodeURIComponent(record.id)}`,
        ),
      );
    } catch (error) {
      setNotice(apiErrorText(error));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const mutateEnabled = async (record: PolicyRecord) => {
    const nextEnabled = !record.spec.enabled;
    try {
      await requestData(
        `/api/policies/${encodeURIComponent(record.id)}/enabled`,
        {
          method: "PATCH",
          headers: {
            "content-type": "application/json",
            "if-match": `"rev:${pageData?.desired_revision ?? 0}"`,
            "x-expected-policy-version": String(record.version),
          },
          body: JSON.stringify({ enabled: nextEnabled }),
        },
      );
      setNotice(t(nextEnabled ? "messages.enabled" : "messages.disabled"));
      await loadPolicies();
    } catch (error) {
      setNotice(
        error instanceof PolicyRequestError && error.status === 409
          ? t("messages.conflict")
          : apiErrorText(error),
      );
      if (error instanceof PolicyRequestError && error.status === 409)
        await loadPolicies();
    }
  };

  const removePolicy = async (record: PolicyRecord) => {
    try {
      await requestData(`/api/policies/${encodeURIComponent(record.id)}`, {
        method: "DELETE",
        headers: { "if-match": `"rev:${pageData?.desired_revision ?? 0}"` },
      });
      setNotice(t("messages.deleted"));
      await loadPolicies();
    } catch (error) {
      setNotice(
        error instanceof PolicyRequestError && error.status === 409
          ? t("messages.conflict")
          : apiErrorText(error),
      );
      if (error instanceof PolicyRequestError && error.status === 409)
        await loadPolicies();
    }
  };

  const republishPolicies = async () => {
    if (!gatewayId || republishing) return;
    setRepublishing(true);
    try {
      await requestData(
        `/api/policies/republish?gateway_id=${encodeURIComponent(gatewayId)}`,
        {
          method: "POST",
        },
      );
      setNotice(t("messages.republished"));
      await loadPolicies();
    } catch (error) {
      setNotice(apiErrorText(error));
    } finally {
      setRepublishing(false);
    }
  };

  const confirmAction = async () => {
    if (!confirmation || confirmationPending) return;
    setConfirmationPending(true);
    try {
      if (confirmation.kind === "toggle")
        await mutateEnabled(confirmation.record);
      else if (confirmation.kind === "delete")
        await removePolicy(confirmation.record);
      else await republishPolicies();
    } finally {
      setConfirmationPending(false);
      setConfirmation(null);
    }
  };
  const confirmationAction =
    confirmation?.kind === "toggle"
      ? confirmation.record.spec.enabled
        ? "disable"
        : "enable"
      : confirmation?.kind;

  const deploymentStatus = deployment?.status ?? "not_deployed";

  return (
    <AppLayout
      title={t("title")}
      subtitle={t("subtitle")}
      username={username}
      toolbar={
        <div className="flex min-w-max items-center justify-between gap-2">
          <div className="flex flex-1 items-center gap-2">
            <label className="min-w-[200px] flex-1 sm:max-w-xs">
              <span className="sr-only">{t("search")}</span>
              <Input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
                placeholder={t("searchPlaceholder")}
                leftIcon={<Search className="size-3.5" />}
              />
            </label>
            <Select
              value={actionFilter}
              onValueChange={(value) => {
                setActionFilter(value);
                setPage(1);
              }}
            >
              <SelectTrigger
                className="h-8 w-[132px] sm:w-36"
                aria-label={t("actionFilter")}
              >
                <SelectValue>
                  {actionFilter === "all"
                    ? t("allActions")
                    : t(`actions.${actionFilter}`)}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("allActions")}</SelectItem>
                {ACTIONS.map((action) => (
                  <SelectItem key={action} value={action}>
                    {t(`actions.${action}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={stateFilter}
              onValueChange={(value) => {
                setStateFilter(value);
                setPage(1);
              }}
            >
              <SelectTrigger
                className="h-8 w-[132px] sm:w-36"
                aria-label={t("stateFilter")}
              >
                <SelectValue>
                  {stateFilter === "all"
                    ? t("allStates")
                    : stateFilter === "enabled"
                      ? t("enabled")
                      : t("disabled")}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("allStates")}</SelectItem>
                <SelectItem value="enabled">{t("enabled")}</SelectItem>
                <SelectItem value="disabled">{t("disabled")}</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              onClick={() => void loadPolicies()}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw className={cn("size-4", loading && "animate-spin")} />{" "}
              {common("actions.refresh")}
            </Button>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setPreviewResult(null);
                setPreviewError(null);
                setPreviewOpen(true);
              }}
              disabled={!gatewayId}
              className="gap-2"
            >
              <ShieldCheck className="size-4" /> {t("preview.open")}
            </Button>
            <Button
              onClick={() => setEditor({ record: null })}
              disabled={!gatewayId}
              className="gap-2"
              aria-label={t("create")}
            >
              <Plus className="size-4" /> {t("create")}
            </Button>
          </div>
        </div>
      }
    >
      <div className="w-full min-w-0 space-y-4 pb-6">
        <section
          className="grid auto-rows-fr items-stretch gap-3 sm:grid-cols-2 xl:grid-cols-4"
          aria-label={t("overview")}
        >
          <StatCard
            label={t("totalPolicies")}
            value={pageData?.total ?? policies.length}
            hint={t("totalPoliciesHint")}
            icon={<SlidersHorizontal className="size-4" />}
          />
          <StatCard
            label={t("enabledPolicies")}
            value={policies.filter((record) => record.spec.enabled).length}
            hint={t("desiredOnly")}
            icon={<ShieldCheck className="size-4" />}
          />
          <StatCard
            label={t("notDeployedPolicies")}
            value={
              policies.filter(
                (record) =>
                  record.spec.enabled &&
                  ["unsupported", "failed", "partial", "degraded"].includes(
                    record.execution_status,
                  ),
              ).length
            }
            hint={t("neverShowActive")}
            icon={<Clock3 className="size-4" />}
          />
          <div
            className="h-full min-h-40 min-w-0 rounded-lg border border-border bg-surface p-3"
            role="group"
            aria-label={t("deployment")}
          >
            <div className="flex h-full flex-col justify-between gap-2">
              <div className="flex min-w-0 items-center justify-between gap-2">
                <p className="min-w-0 truncate text-xs font-medium text-foreground-muted">
                  {t("deployment")}
                </p>
                <div className="flex shrink-0 items-center gap-1.5">
                  <SimpleTooltip
                    content={
                      <div className="max-w-xs space-y-1 whitespace-normal text-left text-[11px] font-normal leading-4">
                        <p>{t(`deploymentStatusHint.${deploymentStatus}`)}</p>
                        {deployment?.last_error_code && (
                          <p className="text-warning">
                            {policyReasonText(
                              deployment.last_error_code,
                              deployment.last_error_message,
                              t,
                            )}
                          </p>
                        )}
                        {deployment?.capabilities && (
                          <div className="border-t border-background/20 pt-1">
                            {CAPABILITY_KEYS.map((capability) => (
                              <p key={capability}>
                                {t(`capabilities.${capability}`)}:{" "}
                                {t(
                                  `capabilityStatus.${deployment.capabilities[capability]}`,
                                )}
                              </p>
                            ))}
                          </div>
                        )}
                        <p className="border-t border-background/20 pt-1">
                          {t("lastAck", {
                            time:
                              formatTimestamp(
                                deployment?.last_reported_at_ms,
                              ) ?? t("never"),
                          })}
                          <br />
                          {t("lastHeartbeat", {
                            time:
                              formatTimestamp(
                                deployment?.last_heartbeat_at_ms,
                              ) ?? t("never"),
                          })}
                        </p>
                      </div>
                    }
                  >
                    <span
                      role="status"
                      tabIndex={0}
                      className={cn(
                        "inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
                        deploymentStatusClasses(deploymentStatus),
                      )}
                      aria-label={`${t(`deploymentStatus.${deploymentStatus}`)}: ${t(`deploymentStatusHint.${deploymentStatus}`)}`}
                    >
                      <span
                        className="size-1.5 shrink-0 rounded-full bg-current"
                        aria-hidden="true"
                      />
                      <span className="truncate">
                        {t(`deploymentStatus.${deploymentStatus}`)}
                      </span>
                    </span>
                  </SimpleTooltip>
                  <SimpleTooltip
                    content={republishing ? t("republishing") : t("republish")}
                  >
                    <button
                      type="button"
                      onClick={() => setConfirmation({ kind: "republish" })}
                      disabled={!gatewayId || republishing}
                      className="flex size-7 items-center justify-center rounded-md border border-border text-foreground-muted hover:bg-surface-hover hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                      aria-label={
                        republishing ? t("republishing") : t("republish")
                      }
                    >
                      <RefreshCw
                        className={cn(
                          "size-3.5",
                          republishing && "animate-spin",
                        )}
                      />
                    </button>
                  </SimpleTooltip>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 border-t border-border/70 pt-2">
                {[
                  {
                    key: "desired",
                    label: t("desiredStage"),
                    revision: pageData?.desired_revision ?? 0,
                    tip: t("desiredStageTip"),
                  },
                  {
                    key: "delivered",
                    label: t("deliveredStage"),
                    revision: deployment?.delivered_revision ?? 0,
                    tip: t("deliveredStageTip"),
                  },
                  {
                    key: "acknowledged",
                    label: t("acknowledgedStage"),
                    revision: deployment?.acknowledged_revision ?? 0,
                    tip: t("acknowledgedStageTip"),
                  },
                  {
                    key: "applied",
                    label: t("appliedStage"),
                    revision: deployment?.applied_revision ?? 0,
                    tip: t("appliedStageTip"),
                  },
                ].map((stage) => (
                  <SimpleTooltip key={stage.key} content={stage.tip}>
                    <div
                      role="group"
                      tabIndex={0}
                      aria-label={`${stage.label}: r${stage.revision}. ${stage.tip}`}
                      className="flex min-w-0 items-center justify-between gap-2 rounded-md border border-border bg-surface-subtle px-2 py-1 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <span className="truncate text-[10px] leading-4 text-foreground-muted">
                        {stage.label}
                      </span>
                      <span className="shrink-0 font-mono text-xs leading-4">
                        r{stage.revision}
                      </span>
                    </div>
                  </SimpleTooltip>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section
          className="overflow-hidden rounded-lg border border-border bg-surface"
          aria-labelledby="policy-list-title"
        >
          <div className="border-b border-border p-4">
            <h2
              id="policy-list-title"
              className="text-base font-semibold tracking-tight"
            >
              {t("listTitle")}
            </h2>
          </div>

          {notice && (
            <div
              className="flex items-start justify-between gap-3 border-b border-border bg-surface-subtle px-5 py-3 text-sm"
              role="status"
              aria-live="polite"
            >
              <span>{notice}</span>
              <button
                type="button"
                className="rounded p-1 text-foreground-muted hover:bg-surface-hover"
                onClick={() => setNotice(null)}
                aria-label={common("actions.close")}
              >
                <X className="size-4" />
              </button>
            </div>
          )}

          {pageError ? (
            <div className="p-5">
              <ErrorState
                message={pageError}
                onRetry={() => {
                  void loadGateways();
                  void loadPolicies();
                }}
              />
            </div>
          ) : loading || loadingGateways ? (
            <div className="p-5">
              <TableSkeleton rows={5} cols={6} />
            </div>
          ) : !gatewayOptions.length ? (
            <EmptyState
              icon={SlidersHorizontal}
              title={t("noGatewayTitle")}
              description={t("noGatewayDescription")}
            />
          ) : !policies.length ? (
            <EmptyState
              icon={Check}
              title={t("emptyTitle")}
              description={t("emptyDescription")}
              action={
                <Button onClick={() => setEditor({ record: null })}>
                  <Plus className="mr-2 size-4" />
                  {t("create")}
                </Button>
              }
            />
          ) : !filteredPolicies.length ? (
            <EmptyState
              icon={Search}
              title={t("noResultsTitle")}
              description={t("noResultsDescription")}
            />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[980px] text-left text-sm">
                  <thead className="bg-surface-subtle text-[11px] font-semibold uppercase tracking-[0.12em] text-foreground-muted">
                    <tr>
                      <th className="px-5 py-3">{t("columns.policy")}</th>
                      <th className="px-4 py-3">{t("columns.matches")}</th>
                      <th className="px-4 py-3">{t("columns.action")}</th>
                      <th className="px-4 py-3">{t("columns.schedule")}</th>
                      <th className="px-4 py-3">{t("columns.state")}</th>
                      <th className="px-4 py-3">{t("columns.priority")}</th>
                      <th className="px-4 py-3">{t("columns.updated")}</th>
                      <th className="px-5 py-3 text-right">
                        {t("columns.actions")}
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/70">
                    {visiblePolicies.map((record) => (
                      <tr
                        key={record.id}
                        className="group transition-colors hover:bg-surface-hover/55"
                      >
                        <td className="max-w-[250px] px-5 py-4 align-top">
                          <button
                            type="button"
                            onClick={() => void openDetail(record)}
                            className="text-left focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring rounded-sm"
                          >
                            <span className="block truncate font-semibold text-foreground group-hover:text-accent">
                              {record.spec.name}
                            </span>
                            <span className="mt-1 block line-clamp-2 text-xs leading-5 text-foreground-muted">
                              {record.spec.description || t("noDescription")}
                            </span>
                          </button>
                        </td>
                        <td className="max-w-[260px] px-4 py-4 align-top">
                          <span
                            className="line-clamp-2 text-xs leading-5 text-foreground-muted"
                            title={selectorSummary(record.spec, t)}
                          >
                            {selectorSummary(record.spec, t)}
                          </span>
                        </td>
                        <td className="max-w-[190px] px-4 py-4 align-top">
                          <div className="space-y-1">
                            <span className="inline-flex items-center gap-1.5 text-xs font-medium">
                              <ActionMark action={record.spec.action.type} />
                              {actionSummary(record.spec, t)}
                            </span>
                            {record.spec.action.type === "limit" &&
                            record.execution_details?.clients.length ? (
                              <p className="text-[10px] leading-4 text-foreground-muted">
                                {t("detail.effectiveRates", {
                                  count:
                                    record.execution_details.clients.length,
                                })}
                              </p>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-4 align-top text-xs text-foreground-muted">
                          {record.spec.schedule
                            ? `${record.spec.schedule.timezone} · ${record.spec.schedule.windows.length} ${t("windows")}`
                            : t("permanent")}
                        </td>
                        <td className="px-4 py-4 align-top">
                          <SimpleTooltip
                            content={
                              record.execution_message ||
                              record.execution_reason_code ? (
                                <p className="max-w-xs whitespace-normal text-left leading-4">
                                  {policyReasonText(
                                    record.execution_reason_code,
                                    record.execution_message,
                                    t,
                                  )}
                                </p>
                              ) : null
                            }
                          >
                            <span
                              tabIndex={
                                record.execution_message ||
                                record.execution_reason_code
                                  ? 0
                                  : undefined
                              }
                              className={cn(
                                "inline-flex whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-semibold focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
                                statusClass(record.execution_status),
                              )}
                            >
                              {record.spec.enabled
                                ? t(`execution.${record.execution_status}`)
                                : t("disabled")}
                            </span>
                          </SimpleTooltip>
                        </td>
                        <td className="px-4 py-4 align-top font-mono text-xs tabular-nums text-foreground-muted">
                          {record.spec.priority}
                        </td>
                        <td className="whitespace-nowrap px-4 py-4 align-top text-xs text-foreground-muted">
                          {new Date(record.updated_at_ms).toLocaleDateString()}
                        </td>
                        <td className="px-5 py-4 align-top">
                          <div className="flex justify-end gap-1.5">
                            <button
                              type="button"
                              className="rounded-md px-2 py-1.5 text-xs font-medium text-foreground-muted hover:bg-surface-hover hover:text-foreground"
                              onClick={() => setEditor({ record })}
                            >
                              {t("edit")}
                            </button>
                            <button
                              type="button"
                              className="rounded-md px-2 py-1.5 text-xs font-medium text-foreground-muted hover:bg-surface-hover hover:text-foreground"
                              onClick={() =>
                                setConfirmation({ kind: "toggle", record })
                              }
                            >
                              {record.spec.enabled ? t("disable") : t("enable")}
                            </button>
                            <button
                              type="button"
                              className="rounded-md px-2 py-1.5 text-xs font-medium text-danger hover:bg-danger-soft"
                              onClick={() =>
                                setConfirmation({ kind: "delete", record })
                              }
                            >
                              {t("delete")}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex flex-col gap-3 border-t border-border px-5 py-3 text-xs text-foreground-muted sm:flex-row sm:items-center sm:justify-between">
                <span>
                  {t("pagination", {
                    from: (page - 1) * PAGE_SIZE + 1,
                    to: Math.min(page * PAGE_SIZE, filteredPolicies.length),
                    total: filteredPolicies.length,
                  })}
                </span>
                <div className="flex items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setPage((current) => Math.max(1, current - 1))
                    }
                    disabled={page <= 1}
                    className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2.5 disabled:opacity-40"
                  >
                    <ChevronLeft className="size-3.5" />
                    {common("pagination.previous")}
                  </button>
                  <span className="min-w-16 text-center tabular-nums">
                    {page} / {pageCount}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      setPage((current) => Math.min(pageCount, current + 1))
                    }
                    disabled={page >= pageCount}
                    className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2.5 disabled:opacity-40"
                  >
                    {common("pagination.next")}
                    <ChevronRight className="size-3.5" />
                  </button>
                </div>
              </div>
            </>
          )}
        </section>
      </div>

      {editor && (
        <PolicyEditor
          key={editor.record?.id ?? "create"}
          record={editor.record}
          gatewayId={gatewayId}
          revision={pageData?.desired_revision ?? 0}
          onClose={() => setEditor(null)}
          onSaved={async (message) => {
            setEditor(null);
            setNotice(message);
            await loadPolicies();
          }}
        />
      )}
      <PolicyDetailPanel
        detail={detail}
        loading={detailLoading}
        trafficMetrics={
          deployment?.policies.find(
            (item) => item.policy_id === detail?.policy.id,
          )?.traffic_metrics ?? []
        }
        onClose={() => setDetail(null)}
        onEdit={(record) => {
          setDetail(null);
          setEditor({ record });
        }}
      />
      <PolicyPreviewPanel
        open={previewOpen}
        gatewayId={gatewayId}
        input={previewInput}
        result={previewResult}
        loading={previewLoading}
        error={previewError}
        onInputChange={(field, value) =>
          setPreviewInput((current) => ({ ...current, [field]: value }))
        }
        onRun={() => void runPolicyPreview()}
        onClose={() => setPreviewOpen(false)}
      />
      <PolicyConfirmationDialog
        open={confirmation !== null}
        title={
          confirmationAction ? t(`confirm.${confirmationAction}Title`) : ""
        }
        description={
          confirmation?.kind === "delete"
            ? t("confirm.deleteRisk", { name: confirmation.record.spec.name })
            : confirmationAction === "republish"
              ? t("confirm.republish")
              : confirmationAction
                ? t(`confirm.${confirmationAction}Risk`)
                : ""
        }
        confirmLabel={
          confirmationAction === "republish"
            ? t("confirm.republishAction")
            : confirmationAction
              ? t(confirmationAction)
              : ""
        }
        destructive={confirmationAction === "delete"}
        pending={confirmationPending}
        onCancel={() => setConfirmation(null)}
        onConfirm={() => void confirmAction()}
      />
    </AppLayout>
  );
}

function PolicyConfirmationDialog({
  open,
  title,
  description,
  confirmLabel,
  pending = false,
  destructive = false,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  pending?: boolean;
  destructive?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const t = useTranslations("policies");
  const common = useTranslations("common.actions");
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && !pending) onCancel();
      }}
    >
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={pending}>
            {common("cancel")}
          </Button>
          <Button
            variant={destructive ? "destructive" : "default"}
            onClick={onConfirm}
            disabled={pending}
            aria-busy={pending}
          >
            {pending ? t("editor.working") : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function deploymentStatusClasses(status: string) {
  if (status === "applied") {
    return "border-success/30 bg-success-soft text-success";
  }
  if (status === "failed") {
    return "border-danger/30 bg-danger-soft text-danger";
  }
  if (
    [
      "pending",
      "delivered",
      "offline",
      "partial",
      "degraded",
      "unsupported",
    ].includes(status)
  ) {
    return "border-warning/30 bg-warning-soft text-warning";
  }
  return "border-border bg-surface-subtle text-foreground-muted";
}

function StatCard({
  label,
  value,
  hint,
  icon,
}: {
  label: string;
  value: number;
  hint: string;
  icon: ReactNode;
}) {
  return (
    <div className="h-full min-h-40 rounded-lg border border-border bg-surface p-3">
      <div className="flex h-full flex-col justify-between gap-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium text-foreground-muted">{label}</p>
            <p className="mt-2 font-heading text-2xl font-semibold tracking-tight tabular-nums">
              {value.toLocaleString()}
            </p>
          </div>
          <span className="rounded-lg border border-border bg-surface-subtle p-2 text-foreground-muted">
            {icon}
          </span>
        </div>
        <p className="mt-auto text-xs text-foreground-muted">{hint}</p>
      </div>
    </div>
  );
}

function ActionMark({ action }: { action: PolicyActionKind }) {
  if (action === "block")
    return (
      <span className="size-2 rounded-full bg-danger" aria-hidden="true" />
    );
  if (action === "allow")
    return (
      <span className="size-2 rounded-full bg-accent" aria-hidden="true" />
    );
  return <span className="size-2 rounded-full bg-warning" aria-hidden="true" />;
}

function PolicyEditor({
  record,
  gatewayId,
  revision,
  onClose,
  onSaved,
}: {
  record: PolicyRecord | null;
  gatewayId: string;
  revision: number;
  onClose: () => void;
  onSaved: (message: string) => Promise<void>;
}) {
  const t = useTranslations("policies") as unknown as PolicyTranslate;
  const common = useTranslations("common.actions");
  const [draft, setDraft] = useState<PolicySpecV1>(
    () => record?.spec ?? defaultSpec(gatewayId),
  );
  const [mode, setMode] = useState<"visual" | "yaml">(() =>
    record && visualUnsupportedPath(record.spec) ? "yaml" : "visual",
  );
  const [yaml, setYaml] = useState(() =>
    formatPolicyYaml(record?.spec ?? defaultSpec(gatewayId)),
  );
  const [yamlError, setYamlError] = useState<PolicyYamlError | null>(null);
  const [conversionError, setConversionError] = useState<string | null>(null);
  const [validation, setValidation] = useState<PolicyValidation | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [confirmation, setConfirmation] = useState<"save" | "reload" | null>(
    null,
  );
  const [conflict, setConflict] = useState<{
    current: PolicyRecord | null;
    local: PolicySpecV1;
    revision?: number;
  } | null>(null);
  const [conflictLoading, setConflictLoading] = useState(false);

  const setVisual = (update: (current: PolicySpecV1) => PolicySpecV1) => {
    setDraft((current) => withVisualScope(update(current)));
    setValidation(null);
    setValidationError(null);
  };

  const switchToYaml = () => {
    if (mode === "visual") {
      setYaml(formatPolicyYaml(withVisualScope(draft)));
      setYamlError(null);
      setConversionError(null);
      setMode("yaml");
    }
  };

  const switchToVisual = () => {
    if (mode === "yaml") {
      try {
        const parsed = parsePolicyYaml(yaml);
        const unsupported = visualUnsupportedPath(parsed);
        if (unsupported) {
          setConversionError(
            t("yaml.visualUnsupported", { path: unsupported }),
          );
          return;
        }
        if (!isPolicySpec(parsed)) {
          setConversionError(t("yaml.visualUnsupported", { path: "spec" }));
          return;
        }
        setDraft(withVisualScope(parsed));
        setYamlError(null);
        setValidation(null);
        setConversionError(null);
        setMode("visual");
      } catch (error) {
        setYamlError(
          error instanceof PolicyYamlError
            ? error
            : new PolicyYamlError(apiErrorText(error)),
        );
      }
    }
  };

  const currentSpec = (): PolicySpecV1 | null => {
    if (mode === "visual") return withVisualScope(draft);
    try {
      const parsed = parsePolicyYaml(yaml);
      if (!isPolicySpec(parsed))
        throw new PolicyYamlError(t("yaml.invalidShape"));
      setYamlError(null);
      return parsed;
    } catch (error) {
      setYamlError(
        error instanceof PolicyYamlError
          ? error
          : new PolicyYamlError(apiErrorText(error)),
      );
      return null;
    }
  };

  const validate = async () => {
    const spec = currentSpec();
    if (!spec) return;
    setSaving(true);
    setValidationError(null);
    try {
      const result = await requestData<PolicyValidation>(
        "/api/policies/validate",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ spec }),
        },
      );
      setValidation(result);
      if (result.normalized_spec) setDraft(result.normalized_spec);
      if (mode === "yaml" && result.normalized_spec)
        setYaml(formatPolicyYaml(result.normalized_spec));
      setValidationError(
        result.valid
          ? null
          : result.errors
              .map((issue) => `${issue.path}: ${issue.message}`)
              .join("\n"),
      );
    } catch (error) {
      setValidationError(apiErrorText(error));
    } finally {
      setSaving(false);
    }
  };

  const save = async () => {
    if (saving) return;
    const spec = currentSpec();
    if (!spec || !validation?.valid || !validation.normalized_spec) return;
    setSaving(true);
    setValidationError(null);
    try {
      const updated = await requestData<{
        policy: PolicyRecord;
        desired_revision: number;
      }>(
        record
          ? `/api/policies/${encodeURIComponent(record.id)}`
          : "/api/policies",
        {
          method: record ? "PUT" : "POST",
          headers: {
            "content-type": "application/json",
            "if-match": `"rev:${revision}"`,
            ...(record
              ? { "x-expected-policy-version": String(record.version) }
              : {}),
          },
          body: JSON.stringify(validation.normalized_spec),
        },
      );
      await onSaved(
        record
          ? t("messages.updated")
          : t("messages.created", { name: updated.policy.spec.name }),
      );
    } catch (error) {
      if (error instanceof PolicyRequestError && error.status === 409) {
        const details = error.details as
          | { current_revision?: number; current_policy_version?: number }
          | undefined;
        setConflict({
          current: null,
          local: spec,
          revision: details?.current_revision,
        });
        setConflictLoading(Boolean(record));
        if (record) {
          try {
            const remote = await requestData<PolicyDetail>(
              `/api/policies/${encodeURIComponent(record.id)}`,
            );
            setConflict({
              current: remote.policy,
              local: spec,
              revision: remote.desired_revision,
            });
          } catch {
            setConflict({
              current: null,
              local: spec,
              revision: details?.current_revision,
            });
          }
        }
        setValidationError(t("messages.conflict"));
      } else {
        setValidationError(apiErrorText(error));
      }
    } finally {
      setConflictLoading(false);
      setSaving(false);
    }
  };

  const reloadRemote = () => {
    if (!conflict?.current) return;
    setDraft(conflict.current.spec);
    setYaml(formatPolicyYaml(conflict.current.spec));
    setValidation(null);
    setValidationError(null);
    setConflict(null);
  };

  const updateRate = (
    direction: "download_bps" | "upload_bps",
    value: string,
  ) => {
    const bps = value === "" ? null : Math.round(Number(value) * 1_000_000);
    setVisual((current) => ({
      ...current,
      action: { ...current.action, [direction]: bps },
    }));
  };

  const changeMode = (next: "visual" | "yaml") => {
    setConversionError(null);
    if (next === "yaml") switchToYaml();
    else switchToVisual();
  };

  const warningText = t("editor.notAppliedWarning");
  const editorScope = useMemo(() => {
    if (mode === "visual") return withVisualScope(draft).network.scope;
    try {
      const parsed = parsePolicyYaml(yaml);
      return isPolicySpec(parsed) ? parsed.network.scope : null;
    } catch {
      return null;
    }
  }, [draft, mode, yaml]);

  return (
    <SidePanel
      open
      onClose={onClose}
      title={record ? t("editor.editTitle") : t("editor.createTitle")}
      subtitle={
        record
          ? t("editor.editSubtitle", { version: record.version })
          : t("editor.createSubtitle")
      }
      width="lg"
      footerActions={
        <div className="flex w-full flex-wrap items-center justify-between gap-3">
          <Button variant="outline" onClick={onClose} disabled={saving}>
            {common("cancel")}
          </Button>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => void validate()}
              disabled={saving}
              className="gap-2"
            >
              <Check className="size-4" />
              {t("editor.validate")}
            </Button>
            <Button
              onClick={() => {
                if (record) setConfirmation("save");
                else void save();
              }}
              disabled={saving || !validation?.valid}
              className="gap-2"
            >
              {saving
                ? t("editor.working")
                : record
                  ? common("saveChanges")
                  : common("save")}
            </Button>
          </div>
        </div>
      }
    >
      <div className="space-y-5">
        <div className="flex items-start gap-3 rounded-lg border border-warning/30 bg-warning-soft/60 p-3 text-xs leading-5 text-warning">
          <Info className="mt-0.5 size-4 shrink-0" />
          <p>{warningText}</p>
        </div>
        <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-subtle p-3">
          <div>
            <p className="text-xs font-semibold text-foreground">
              {t("editor.gateway")}
            </p>
            <p className="mt-1 font-mono text-xs text-foreground-muted">
              {gatewayId}
            </p>
          </div>
          {editorScope && (
            <span className="rounded-full border border-border bg-surface px-2.5 py-1 text-[11px] font-semibold text-foreground-muted">
              {t(editorScope === "agent" ? "scopeAgent" : "scopeInternet")}
            </span>
          )}
        </div>
        <div
          className="inline-flex rounded-lg border border-border bg-surface-subtle p-1"
          role="tablist"
          aria-label={t("editor.modeLabel")}
        >
          <button
            type="button"
            role="tab"
            aria-selected={mode === "visual"}
            onClick={() => changeMode("visual")}
            className={cn(
              "rounded-md px-3 py-2 text-xs font-semibold transition-colors",
              mode === "visual"
                ? "bg-surface text-foreground shadow-sm"
                : "text-foreground-muted hover:text-foreground",
            )}
          >
            {t("editor.visualTab")}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "yaml"}
            onClick={() => changeMode("yaml")}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-2 text-xs font-semibold transition-colors",
              mode === "yaml"
                ? "bg-surface text-foreground shadow-sm"
                : "text-foreground-muted hover:text-foreground",
            )}
          >
            <FileCode2 className="size-3.5" />
            {t("editor.yamlTab")}
          </button>
        </div>

        {mode === "visual" ? (
          <div className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("fields.name")} required>
                <Input
                  value={draft.name}
                  maxLength={100}
                  onChange={(event) =>
                    setVisual((current) => ({
                      ...current,
                      name: event.target.value,
                    }))
                  }
                />
              </Field>
              <Field
                label={t("fields.priority")}
                help={t("fields.priorityHelp")}
              >
                <Input
                  type="number"
                  min={0}
                  max={1000}
                  step={1}
                  value={draft.priority}
                  onChange={(event) =>
                    setVisual((current) => ({
                      ...current,
                      priority: Number(event.target.value),
                    }))
                  }
                />
              </Field>
              <Field label={t("fields.description")} className="sm:col-span-2">
                <textarea
                  value={draft.description}
                  maxLength={500}
                  rows={2}
                  onChange={(event) =>
                    setVisual((current) => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                  className="w-full resize-y rounded-md border border-border bg-surface px-3 py-2 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
                />
              </Field>
            </div>

            <div className="space-y-3 rounded-xl border border-border p-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold">
                    {t("fields.matching")}
                  </h3>
                  <p className="mt-1 text-xs text-foreground-muted">
                    {t("fields.matchingHelp")}
                  </p>
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                  {t("fields.logicClientAndApp")}
                </span>
              </div>
              <OptionPicker
                kind="clients"
                gatewayId={gatewayId}
                selected={draft.selectors.clients}
                onChange={(clients) =>
                  setVisual((current) => ({
                    ...current,
                    selectors: { ...current.selectors, clients },
                  }))
                }
              />
              <div className="grid gap-3 md:grid-cols-2">
                <OptionPicker
                  kind="applications"
                  gatewayId={gatewayId}
                  selected={draft.selectors.applications}
                  onChange={(applications) =>
                    setVisual((current) => ({
                      ...current,
                      selectors: { ...current.selectors, applications },
                    }))
                  }
                />
                <OptionPicker
                  kind="categories"
                  gatewayId={gatewayId}
                  selected={draft.selectors.categories}
                  onChange={(categories) =>
                    setVisual((current) => ({
                      ...current,
                      selectors: { ...current.selectors, categories },
                    }))
                  }
                />
              </div>
            </div>

            <div className="grid gap-4 rounded-xl border border-border p-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <p className="text-xs font-semibold text-foreground">
                  {t("fields.action")}
                </p>
                <Select
                  value={draft.action.type}
                  onValueChange={(value) =>
                    setVisual((current) => ({
                      ...current,
                      action: {
                        type: value as PolicyActionKind,
                        download_bps: null,
                        upload_bps: null,
                      },
                    }))
                  }
                >
                  <SelectTrigger
                    className="h-10 w-full text-sm"
                    aria-label={t("fields.action")}
                  >
                    <SelectValue>
                      {t(`actions.${draft.action.type}`)}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {ACTIONS.map((action) => (
                        <SelectItem key={action} value={action}>
                          {t(`actions.${action}`)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
              <Field label={t("fields.direction")}>
                <div className="flex h-10 items-center rounded-md border border-border bg-surface-subtle px-3 text-sm text-foreground-muted">
                  {t("fields.bothDirections")}
                </div>
              </Field>
              {draft.action.type === "limit" && (
                <>
                  {editorScope === "agent" && (
                    <p className="text-xs text-foreground-muted sm:col-span-2">
                      {t("fields.clientTotalHelp")}
                    </p>
                  )}
                  <Field
                    label={t("fields.downloadLimit")}
                    help={t("fields.mbpsHelp")}
                  >
                    <div className="relative">
                      <Input
                        type="number"
                        min={0.064}
                        max={1000}
                        step={0.001}
                        value={
                          draft.action.download_bps === null
                            ? ""
                            : draft.action.download_bps / 1_000_000
                        }
                        onChange={(event) =>
                          updateRate("download_bps", event.target.value)
                        }
                        placeholder="—"
                        className="pr-14"
                      />
                      <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-foreground-muted">
                        Mbps
                      </span>
                    </div>
                  </Field>
                  <Field
                    label={t("fields.uploadLimit")}
                    help={t("fields.mbpsHelp")}
                  >
                    <div className="relative">
                      <Input
                        type="number"
                        min={0.064}
                        max={1000}
                        step={0.001}
                        value={
                          draft.action.upload_bps === null
                            ? ""
                            : draft.action.upload_bps / 1_000_000
                        }
                        onChange={(event) =>
                          updateRate("upload_bps", event.target.value)
                        }
                        placeholder="—"
                        className="pr-14"
                      />
                      <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-foreground-muted">
                        Mbps
                      </span>
                    </div>
                  </Field>
                </>
              )}
              <div className="sm:col-span-2 flex items-center gap-2 rounded-md bg-surface-subtle px-3 py-2 text-xs text-foreground-muted">
                <Info className="size-3.5 shrink-0" />
                <span>{t("fields.allowHelp")}</span>
              </div>
            </div>

            <div className="space-y-4 rounded-xl border border-border p-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold">
                    {t("fields.schedule")}
                  </h3>
                  <p className="mt-1 text-xs text-foreground-muted">
                    {t("fields.scheduleHelp")}
                  </p>
                </div>
                <label className="inline-flex items-center gap-2 text-xs font-medium">
                  <input
                    type="checkbox"
                    checked={draft.schedule !== null}
                    onChange={(event) =>
                      setVisual((current) => ({
                        ...current,
                        schedule: event.target.checked
                          ? {
                              timezone:
                                Intl.DateTimeFormat().resolvedOptions()
                                  .timeZone || "UTC",
                              windows: [
                                {
                                  days: ["mon", "tue", "wed", "thu", "fri"],
                                  start: "18:00",
                                  end: "23:00",
                                },
                              ],
                            }
                          : null,
                      }))
                    }
                    className="size-4 rounded border-border accent-accent"
                  />
                  {t("fields.useSchedule")}
                </label>
              </div>
              {draft.schedule && (
                <>
                  <Field
                    label={t("fields.timezone")}
                    help={t("fields.timezoneHelp")}
                  >
                    <Input
                      value={draft.schedule.timezone}
                      onChange={(event) =>
                        setVisual((current) =>
                          current.schedule
                            ? {
                                ...current,
                                schedule: {
                                  ...current.schedule,
                                  timezone: event.target.value,
                                },
                              }
                            : current,
                        )
                      }
                    />
                  </Field>
                  <div>
                    <p className="mb-2 text-xs font-medium text-foreground">
                      {t("fields.days")}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {WEEKDAYS.map((day) => (
                        <label
                          key={day}
                          className={cn(
                            "inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs",
                            draft.schedule?.windows[0]?.days.includes(day)
                              ? "border-accent/40 bg-accent-soft text-accent"
                              : "border-border bg-surface text-foreground-muted",
                          )}
                        >
                          <input
                            type="checkbox"
                            checked={
                              draft.schedule?.windows[0]?.days.includes(day) ??
                              false
                            }
                            onChange={(event) =>
                              setVisual((current) => {
                                if (!current.schedule) return current;
                                const window = current.schedule.windows[0] ?? {
                                  days: [],
                                  start: "18:00",
                                  end: "23:00",
                                };
                                const days = event.target.checked
                                  ? [...window.days, day]
                                  : window.days.filter(
                                      (value) => value !== day,
                                    );
                                return {
                                  ...current,
                                  schedule: {
                                    ...current.schedule,
                                    windows: [{ ...window, days }],
                                  },
                                };
                              })
                            }
                            className="sr-only"
                          />
                          {t(`weekdays.${day}`)}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Field label={t("fields.start")}>
                      <Input
                        type="time"
                        value={draft.schedule.windows[0]?.start ?? "18:00"}
                        onChange={(event) =>
                          setVisual((current) =>
                            current.schedule
                              ? {
                                  ...current,
                                  schedule: {
                                    ...current.schedule,
                                    windows: [
                                      {
                                        ...(current.schedule.windows[0] ?? {
                                          days: [],
                                          start: "18:00",
                                          end: "23:00",
                                        }),
                                        start: event.target.value,
                                      },
                                    ],
                                  },
                                }
                              : current,
                          )
                        }
                      />
                    </Field>
                    <Field label={t("fields.end")}>
                      <Input
                        type="time"
                        value={draft.schedule.windows[0]?.end ?? "23:00"}
                        onChange={(event) =>
                          setVisual((current) =>
                            current.schedule
                              ? {
                                  ...current,
                                  schedule: {
                                    ...current.schedule,
                                    windows: [
                                      {
                                        ...(current.schedule.windows[0] ?? {
                                          days: [],
                                          start: "18:00",
                                          end: "23:00",
                                        }),
                                        end: event.target.value,
                                      },
                                    ],
                                  },
                                }
                              : current,
                          )
                        }
                      />
                    </Field>
                  </div>
                  <p className="text-xs text-foreground-muted">
                    {t("fields.crossMidnightHelp")}
                  </p>
                </>
              )}
            </div>

            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-surface-subtle p-3">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(event) =>
                  setVisual((current) => ({
                    ...current,
                    enabled: event.target.checked,
                  }))
                }
                className="mt-0.5 size-4 accent-accent"
              />
              <span>
                <span className="block text-sm font-semibold">
                  {t("fields.desiredEnabled")}
                </span>
                <span className="mt-1 block text-xs leading-5 text-foreground-muted">
                  {t("fields.desiredEnabledHelp")}
                </span>
              </span>
            </label>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-foreground">
                  {t("yaml.title")}
                </p>
                <p className="mt-1 text-xs text-foreground-muted">
                  {t("yaml.help")}
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const parsed = currentSpec();
                  if (parsed) setYaml(formatPolicyYaml(parsed));
                }}
                className="gap-1.5"
              >
                <RefreshCw className="size-3.5" />
                {t("yaml.format")}
              </Button>
            </div>
            <textarea
              value={yaml}
              onChange={(event) => {
                setYaml(event.target.value);
                setValidation(null);
                setValidationError(null);
                setConversionError(null);
                try {
                  parsePolicyYaml(event.target.value);
                  setYamlError(null);
                } catch (error) {
                  setYamlError(
                    error instanceof PolicyYamlError
                      ? error
                      : new PolicyYamlError(apiErrorText(error)),
                  );
                }
              }}
              spellCheck={false}
              aria-label={t("yaml.editorLabel")}
              className="min-h-[440px] w-full resize-y rounded-lg border border-border bg-[#101820] px-4 py-4 font-mono text-xs leading-6 text-[#d8e7e7] outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            {yamlError && (
              <p
                className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger"
                role="alert"
              >
                {yamlError.line
                  ? t("yaml.lineError", {
                      line: yamlError.line,
                      column: yamlError.column ?? 1,
                      message: yamlError.message,
                    })
                  : yamlError.message}
              </p>
            )}
            <div className="flex flex-wrap items-start gap-2 rounded-md border border-border bg-surface-subtle p-3 text-xs leading-5 text-foreground-muted">
              <Info className="mt-0.5 size-3.5 shrink-0" />
              <span>{t("yaml.safety")}</span>
            </div>
          </div>
        )}

        {conversionError && (
          <p
            className="rounded-md border border-warning/30 bg-warning-soft px-3 py-2 text-xs text-warning"
            role="alert"
          >
            {conversionError}
          </p>
        )}
        {validationError && (
          <pre
            className="whitespace-pre-wrap rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-xs leading-5 text-danger"
            role="alert"
          >
            {validationError}
          </pre>
        )}
        {validation?.valid && validation.normalized_spec && (
          <div
            className="space-y-3 rounded-xl border border-accent/25 bg-accent-soft/30 p-4"
            aria-live="polite"
          >
            <div className="flex items-center gap-2 text-sm font-semibold text-accent">
              <Check className="size-4" />
              {t("validation.validTitle")}
            </div>
            <div className="grid gap-3 text-xs sm:grid-cols-2">
              <SummaryLine
                label={t("columns.matches")}
                value={selectorSummary(validation.normalized_spec, t)}
              />
              <SummaryLine
                label={t("columns.action")}
                value={actionSummary(validation.normalized_spec, t)}
              />
              <SummaryLine
                label={t("columns.priority")}
                value={String(validation.normalized_spec.priority)}
              />
              <SummaryLine
                label={t("fields.schedule")}
                value={
                  validation.normalized_spec.schedule
                    ? `${validation.normalized_spec.schedule.timezone} · ${validation.normalized_spec.schedule.windows.length} ${t("windows")}`
                    : t("permanent")
                }
              />
            </div>
            {validation.warnings.length > 0 && (
              <ul className="space-y-1 border-t border-accent/15 pt-3 text-xs text-warning">
                {validation.warnings.map((warning) => (
                  <li key={warning} className="flex gap-2">
                    <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                    {warning}
                  </li>
                ))}
              </ul>
            )}
            <p className="border-t border-accent/15 pt-3 text-xs font-semibold text-warning">
              {t("validation.notEffective")}
            </p>
          </div>
        )}
        {conflict && (
          <div
            className="space-y-3 rounded-xl border border-warning/40 bg-warning-soft/35 p-4"
            role="alert"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
              <div>
                <p className="text-sm font-semibold">{t("conflict.title")}</p>
                <p className="mt-1 text-xs leading-5 text-foreground-muted">
                  {t("conflict.description", {
                    revision: conflict.revision ?? "—",
                  })}
                </p>
              </div>
            </div>
            {conflictLoading ? (
              <p className="text-xs text-foreground-muted">
                {t("conflict.loading")}
              </p>
            ) : conflict.current ? (
              <>
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                      {t("conflict.yourDraft")}
                    </p>
                    <pre className="max-h-36 overflow-auto rounded-md bg-surface p-2 text-[10px] leading-4">
                      {JSON.stringify(conflict.local, null, 2)}
                    </pre>
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-foreground-muted">
                      {t("conflict.serverVersion")}
                    </p>
                    <pre className="max-h-36 overflow-auto rounded-md bg-surface p-2 text-[10px] leading-4">
                      {JSON.stringify(conflict.current.spec, null, 2)}
                    </pre>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setConfirmation("reload")}
                >
                  {t("conflict.reload")}
                </Button>
              </>
            ) : (
              <p className="text-xs text-foreground-muted">
                {t("conflict.refreshList")}
              </p>
            )}
          </div>
        )}
      </div>
      <PolicyConfirmationDialog
        open={confirmation !== null}
        title={t(
          confirmation === "reload"
            ? "confirm.reloadTitle"
            : "confirm.saveTitle",
        )}
        description={t(
          confirmation === "reload"
            ? "confirm.reloadConflict"
            : "confirm.saveRisk",
        )}
        confirmLabel={
          confirmation === "reload"
            ? t("conflict.reload")
            : common("saveChanges")
        }
        pending={saving}
        onCancel={() => setConfirmation(null)}
        onConfirm={() => {
          if (saving) return;
          if (confirmation === "reload") {
            reloadRemote();
            setConfirmation(null);
          } else {
            void save().finally(() => setConfirmation(null));
          }
        }}
      />
    </SidePanel>
  );
}

function SummaryLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-foreground-muted">
        {label}
      </p>
      <p className="mt-1 break-words font-medium text-foreground">{value}</p>
    </div>
  );
}

function Field({
  label,
  children,
  help,
  required,
  className,
}: {
  label: string;
  children: ReactNode;
  help?: string;
  required?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <label className="block text-xs font-semibold text-foreground">
        {label}
        {required && <span className="ml-1 text-danger">*</span>}
        {children}
      </label>
      {help && (
        <p className="text-[11px] leading-4 text-foreground-muted">{help}</p>
      )}
    </div>
  );
}

function OptionPicker({
  kind,
  gatewayId,
  selected,
  onChange,
}: {
  kind: "clients" | "applications" | "categories";
  gatewayId: string;
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const t = useTranslations("policies") as unknown as PolicyTranslate;
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<PolicyOption[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const timeout = setTimeout(() => {
      setLoading(true);
      requestData<{ items: PolicyOption[]; total: number }>(
        `/api/policies/options?gateway_id=${encodeURIComponent(gatewayId)}&kind=${kind}&q=${encodeURIComponent(query)}&page=1&page_size=100`,
      )
        .then((result) => {
          if (!active) return;
          setItems(result.items);
          setTotal(result.total);
          setError(null);
        })
        .catch((reason) => {
          if (active) setError(apiErrorText(reason));
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, 180);
    return () => {
      active = false;
      clearTimeout(timeout);
    };
  }, [gatewayId, kind, query]);

  const labels: Record<typeof kind, string> = {
    clients: t("fields.clients"),
    applications: t("fields.applications"),
    categories: t("fields.categories"),
  };
  const help: Record<typeof kind, string> = {
    clients: t("fields.clientsHelp"),
    applications: t("fields.applicationsHelp"),
    categories: t("fields.categoriesHelp"),
  };
  const selectedLabels = selected.map((id) => {
    const item = items.find((option) => option.id === id);
    return {
      id,
      label: item
        ? `${item.name}${item.mac && item.mac !== item.name ? ` · ${item.mac}` : ""}`
        : id,
    };
  });

  const toggle = (id: string) =>
    onChange(
      selected.includes(id)
        ? selected.filter((item) => item !== id)
        : [...selected, id],
    );

  return (
    <div className="space-y-2 rounded-lg border border-border bg-surface-subtle/40 p-3">
      <div>
        <p className="text-xs font-semibold text-foreground">{labels[kind]}</p>
        <p className="mt-1 text-[11px] leading-4 text-foreground-muted">
          {help[kind]}
        </p>
      </div>
      <label className="relative block">
        <span className="sr-only">
          {t("fields.searchOption", { name: labels[kind] })}
        </span>
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-foreground-muted" />
        <Input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t("fields.searchOptionPlaceholder")}
          className="h-9 pl-2 text-xs"
        />
      </label>
      {selectedLabels.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selectedLabels.map(({ id, label }) => (
            <span
              key={id}
              className="inline-flex max-w-full items-center gap-1 rounded-full border border-accent/25 bg-accent-soft px-2 py-1 text-[10px] font-medium text-accent"
            >
              <span className="truncate">{label}</span>
              <button
                type="button"
                aria-label={t("fields.removeOption", { name: label })}
                onClick={() => toggle(id)}
                className="rounded-full hover:bg-accent/10"
              >
                <X className="size-3" />
              </button>
            </span>
          ))}
        </div>
      )}
      <div
        className="max-h-36 space-y-1 overflow-auto rounded-md border border-border bg-surface p-1.5"
        role="group"
        aria-label={labels[kind]}
      >
        {loading ? (
          <p className="px-2 py-3 text-center text-[11px] text-foreground-muted">
            {t("loadingOptions")}
          </p>
        ) : error ? (
          <p className="px-2 py-3 text-center text-[11px] text-danger">
            {error}
          </p>
        ) : items.length ? (
          items.map((item) => (
            <label
              key={item.id}
              className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-surface-hover"
            >
              <input
                type="checkbox"
                checked={selected.includes(item.id)}
                onChange={() => toggle(item.id)}
                className="size-3.5 accent-accent"
              />
              <span className="min-w-0 flex-1 truncate">{item.name}</span>
              {item.mac && (
                <span className="font-mono text-[10px] text-foreground-muted">
                  {item.mac}
                </span>
              )}
            </label>
          ))
        ) : (
          <p className="px-2 py-3 text-center text-[11px] text-foreground-muted">
            {t("fields.noOptions")}
          </p>
        )}
      </div>
      {total > items.length && (
        <p className="text-[10px] text-foreground-muted">
          {t("fields.optionsCapped", { shown: items.length, total })}
        </p>
      )}
    </div>
  );
}

function PolicyDetailPanel({
  detail,
  loading,
  trafficMetrics,
  onClose,
  onEdit,
}: {
  detail: PolicyDetail | null;
  loading: boolean;
  trafficMetrics: PolicyTrafficMetrics[];
  onClose: () => void;
  onEdit: (record: PolicyRecord) => void;
}) {
  const t = useTranslations("policies") as unknown as PolicyTranslate;
  const common = useTranslations("common.actions");
  const blockTrafficMetrics = trafficMetrics.filter(
    (metric) => metric.upload?.interface === "policy-block",
  );
  return (
    <SidePanel
      open={loading || Boolean(detail)}
      onClose={onClose}
      title={detail?.policy.spec.name ?? t("detail.title")}
      subtitle={
        detail
          ? t("detail.version", { version: detail.policy.version })
          : undefined
      }
      statusBadge={
        detail ? (
          <span
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px] font-semibold",
              statusClass(detail.policy.execution_status),
            )}
          >
            {detail.policy.spec.enabled
              ? t(`execution.${detail.policy.execution_status}`)
              : t("disabled")}
          </span>
        ) : undefined
      }
      footerActions={
        detail ? (
          <div className="flex w-full justify-between gap-3">
            <Button variant="outline" onClick={onClose}>
              {common("close")}
            </Button>
            <Button onClick={() => onEdit(detail.policy)}>{t("edit")}</Button>
          </div>
        ) : undefined
      }
    >
      {loading ? (
        <div className="space-y-3">
          <div className="h-5 w-1/2 animate-pulse rounded bg-surface-subtle" />
          <div className="h-24 animate-pulse rounded bg-surface-subtle" />
          <div className="h-32 animate-pulse rounded bg-surface-subtle" />
        </div>
      ) : detail ? (
        <div className="space-y-6">
          <section className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground-muted">
              {t("detail.configuration")}
            </h3>
            <SummaryLine
              label={t("fields.description")}
              value={detail.policy.spec.description || t("noDescription")}
            />
            <SummaryLine
              label={t("columns.matches")}
              value={selectorSummary(detail.policy.spec, t)}
            />
            <SummaryLine
              label={t("columns.action")}
              value={actionSummary(detail.policy.spec, t)}
            />
            <SummaryLine
              label={t("columns.schedule")}
              value={
                detail.policy.spec.schedule
                  ? `${detail.policy.spec.schedule.timezone} · ${detail.policy.spec.schedule.windows.map((window) => `${window.days.map((day) => t(`weekdays.${day}`)).join(",")} ${window.start}–${window.end}`).join("; ")}`
                  : t("permanent")
              }
            />
            <div className="grid grid-cols-2 gap-3">
              <SummaryLine
                label={t("columns.priority")}
                value={String(detail.policy.spec.priority)}
              />
              <SummaryLine
                label={t("detail.gatewayRevision")}
                value={String(detail.desired_revision)}
              />
            </div>
          </section>
          {detail.policy.spec.action.type === "limit" && (
            <section className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground-muted">
                {t("detail.limitRuntime")}
              </h3>
              {detail.policy.execution_details?.clients.length ? (
                <div className="space-y-2">
                  {detail.policy.execution_details.clients.map((client) => (
                    <div
                      key={client.mac}
                      className="rounded-lg border border-border bg-surface-subtle p-3"
                    >
                      <p className="font-mono text-xs font-semibold">
                        {client.mac}
                      </p>
                      <p className="mt-1 text-xs text-foreground-muted">
                        {t("upload")}:{" "}
                        {client.effective_upload_bps === null
                          ? t("unlimited")
                          : formatMbps(client.effective_upload_bps)}
                        {" · "}
                        {t("download")}:{" "}
                        {client.effective_download_bps === null
                          ? t("unlimited")
                          : formatMbps(client.effective_download_bps)}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-foreground-muted">
                  {t("detail.noRuntimeRates")}
                </p>
              )}
              {detail.policy.execution_details?.controlled_interfaces.length ? (
                <SummaryLine
                  label={t("detail.interfaces")}
                  value={detail.policy.execution_details.controlled_interfaces.join(
                    ", ",
                  )}
                />
              ) : null}
              {detail.policy.execution_details?.qdisc && (
                <SummaryLine
                  label={t("detail.qdisc")}
                  value={detail.policy.execution_details.qdisc}
                />
              )}
              {detail.policy.execution_details?.mark_conflict_code && (
                <p className="text-xs text-warning">
                  {t("detail.markConflict")}:{" "}
                  {detail.policy.execution_details.mark_conflict_code}
                </p>
              )}
              {trafficMetrics.length > 0 && (
                <div className="space-y-2 border-t border-border pt-3">
                  <p className="text-xs font-medium">
                    {t("detail.trafficCounters")}
                  </p>
                  <p className="text-[10px] leading-4 text-foreground-muted">
                    {t("detail.trafficCountersHelp")}
                  </p>
                  {trafficMetrics.map((metric) => (
                    <div
                      key={metric.mac}
                      className="rounded-lg border border-border p-3 text-[11px]"
                    >
                      <p className="font-mono font-semibold">{metric.mac}</p>
                      <p className="mt-1 text-foreground-muted">
                        {t("upload")}:{" "}
                        {metric.upload?.bytes === null ||
                        metric.upload?.bytes === undefined
                          ? t("unavailable")
                          : formatBytes(metric.upload.bytes)}
                        {" · "}
                        {t("detail.packets")}:{" "}
                        {metric.upload?.packets ?? t("unavailable")}
                        {" · "}
                        {t("detail.drops")}:{" "}
                        {metric.upload?.drops ?? t("unavailable")}
                        {" · "}
                        {t("detail.overlimits")}:{" "}
                        {metric.upload?.overlimits ?? t("unavailable")}
                      </p>
                      <p className="mt-1 text-foreground-muted">
                        {t("download")}:{" "}
                        {metric.download?.bytes === null ||
                        metric.download?.bytes === undefined
                          ? t("unavailable")
                          : formatBytes(metric.download.bytes)}
                        {" · "}
                        {t("detail.packets")}:{" "}
                        {metric.download?.packets ?? t("unavailable")}
                        {" · "}
                        {t("detail.drops")}:{" "}
                        {metric.download?.drops ?? t("unavailable")}
                        {" · "}
                        {t("detail.overlimits")}:{" "}
                        {metric.download?.overlimits ?? t("unavailable")}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          {detail.policy.spec.action.type === "block" &&
            blockTrafficMetrics.length > 0 && (
              <section className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground-muted">
                  {t("detail.blockTrafficCounters")}
                </h3>
                <p className="text-[10px] leading-4 text-foreground-muted">
                  {t("detail.blockTrafficCountersHelp")}
                </p>
                {blockTrafficMetrics.map((metric) => (
                  <div
                    key={`${metric.policy_id}:${metric.mac}`}
                    data-testid="policy-block-metric-row"
                    className="rounded-lg border border-border p-3 text-[11px]"
                  >
                    <p className="font-mono font-semibold">{metric.mac}</p>
                    <p className="text-foreground-muted">
                      {t("detail.droppedPackets")}:{" "}
                      {metric.upload?.packets ?? t("unavailable")}
                      {" · "}
                      {t("detail.droppedBytes")}:{" "}
                      {metric.upload?.bytes === null ||
                      metric.upload?.bytes === undefined
                        ? t("unavailable")
                        : formatBytes(metric.upload.bytes)}
                    </p>
                  </div>
                ))}
              </section>
            )}
          <div className="rounded-lg border border-warning/30 bg-warning-soft/50 p-3 text-xs leading-5 text-warning">
            <AlertTriangle className="mr-1 inline size-3.5" />
            {t("detail.executionNotice")}
          </div>
          <section className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground-muted">
                {t("detail.auditTitle")}
              </h3>
              <span className="text-[10px] text-foreground-muted">
                {detail.events.length}
              </span>
            </div>
            {detail.events.length ? (
              <ol className="space-y-3 border-l border-border pl-4">
                {detail.events.map((event) => (
                  <li key={event.event_id} className="relative">
                    <span className="absolute -left-[21px] top-1 size-2.5 rounded-full border-2 border-surface bg-accent" />
                    <p className="text-xs font-semibold">
                      {t(`audit.${event.action}` as never, {
                        fallback: event.action,
                      })}
                    </p>
                    <p className="mt-1 text-[11px] text-foreground-muted">
                      {new Date(event.created_at_ms).toLocaleString()} ·{" "}
                      {event.actor_user_id}
                    </p>
                    <p className="mt-1 font-mono text-[10px] text-foreground-muted">
                      {t("detail.revision", { revision: event.revision })}
                    </p>
                    {event.before && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-[11px] text-accent">
                          {t("detail.beforeSnapshot")}
                        </summary>
                        <pre className="mt-2 max-h-36 overflow-auto rounded bg-surface-subtle p-2 text-[10px] leading-4">
                          {JSON.stringify(event.before, null, 2)}
                        </pre>
                      </details>
                    )}
                    {event.after && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-[11px] text-accent">
                          {t("detail.afterSnapshot")}
                        </summary>
                        <pre className="mt-2 max-h-36 overflow-auto rounded bg-surface-subtle p-2 text-[10px] leading-4">
                          {JSON.stringify(event.after, null, 2)}
                        </pre>
                      </details>
                    )}
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-xs text-foreground-muted">
                {t("detail.noAudit")}
              </p>
            )}
          </section>
        </div>
      ) : null}
    </SidePanel>
  );
}

type PolicyPreviewInput = Omit<
  PolicyPreviewRequest,
  "gateway_id" | "scope" | "at_ms"
>;

function PolicyPreviewPanel({
  open,
  gatewayId,
  input,
  result,
  loading,
  error,
  onInputChange,
  onRun,
  onClose,
}: {
  open: boolean;
  gatewayId: string;
  input: PolicyPreviewInput;
  result: PolicyPreviewResult | null;
  loading: boolean;
  error: string | null;
  onInputChange: (
    field: keyof PolicyPreviewInput,
    value: string | number,
  ) => void;
  onRun: () => void;
  onClose: () => void;
}) {
  const t = useTranslations("policies") as unknown as PolicyTranslate;
  const common = useTranslations("common.actions");
  return (
    <SidePanel
      open={open}
      onClose={onClose}
      title={t("preview.title")}
      subtitle={t("preview.subtitle")}
      width="lg"
      footerActions={
        <div className="flex w-full justify-between gap-3">
          <Button variant="outline" onClick={onClose}>
            {common("close")}
          </Button>
          <Button
            onClick={onRun}
            disabled={
              loading ||
              !gatewayId ||
              !input.client_mac.trim() ||
              !input.application_id.trim()
            }
            className="gap-2"
          >
            <ShieldCheck className={cn("size-4", loading && "animate-pulse")} />
            {loading ? t("preview.running") : t("preview.run")}
          </Button>
        </div>
      }
    >
      <div className="space-y-5">
        <div className="rounded-lg border border-accent/20 bg-accent/5 p-3 text-xs leading-5 text-foreground-muted">
          {t("preview.readOnly")}
          <p className="mt-1 font-mono text-[10px]">{gatewayId}</p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="space-y-1.5 text-xs font-medium">
            <span>{t("preview.clientMac")}</span>
            <Input
              value={input.client_mac}
              placeholder="AA:BB:CC:DD:EE:FF"
              onChange={(event) =>
                onInputChange("client_mac", event.target.value)
              }
            />
          </label>
          <label className="space-y-1.5 text-xs font-medium">
            <span>{t("preview.applicationId")}</span>
            <Input
              value={input.application_id}
              placeholder="youtube"
              onChange={(event) =>
                onInputChange("application_id", event.target.value)
              }
            />
          </label>
          <label className="space-y-1.5 text-xs font-medium">
            <span>{t("preview.categoryId")}</span>
            <Input
              value={input.category_id}
              placeholder="streaming"
              onChange={(event) =>
                onInputChange("category_id", event.target.value)
              }
            />
          </label>
          <label className="space-y-1.5 text-xs font-medium">
            <span>{t("preview.confidence")}</span>
            <Input
              type="number"
              min={0}
              max={1}
              step={0.01}
              value={input.application_confidence}
              onChange={(event) =>
                onInputChange(
                  "application_confidence",
                  Number(event.target.value),
                )
              }
            />
          </label>
        </div>
        {error && (
          <div className="rounded-lg border border-danger/30 bg-danger-soft p-3 text-xs text-danger">
            {error}
          </div>
        )}
        {result && (
          <section className="space-y-4 rounded-xl border border-border bg-surface-subtle p-4">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-foreground-muted">
                {t("preview.verdict")}
              </p>
              <p className="mt-1 text-sm font-semibold">
                {t(`preview.verdicts.${result.selected_block_verdict}`)}
              </p>
              <p className="mt-2 text-xs leading-5 text-foreground-muted">
                {result.explanation}
              </p>
            </div>
            <div className="space-y-2">
              <h3 className="text-xs font-semibold">{t("preview.matches")}</h3>
              {result.matched_policies.length ? (
                <ul className="space-y-2">
                  {result.matched_policies.map((policy) => (
                    <li
                      key={policy.policy_id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface p-3 text-xs"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-medium">
                          {policy.name}
                        </span>
                        <span className="text-foreground-muted">
                          {t(`actions.${policy.action}`)} ·{" "}
                          {t("columns.priority")} {policy.priority}
                        </span>
                      </span>
                      {policy.selected && (
                        <span className="shrink-0 rounded-full bg-accent/10 px-2 py-1 text-[10px] font-semibold text-accent">
                          {t("preview.selected")}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-foreground-muted">
                  {t("preview.noMatches")}
                </p>
              )}
            </div>
            {result.active_limits.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold">{t("preview.limits")}</h3>
                {result.active_limits.map((limit) => (
                  <div
                    key={limit.policy_id}
                    className="rounded-lg border border-border bg-surface p-3 text-xs"
                  >
                    <p className="font-medium">{limit.name}</p>
                    <p className="mt-1 text-foreground-muted">
                      {t("download")}:{" "}
                      {limit.download_bps === null
                        ? t("unlimited")
                        : formatMbps(limit.download_bps)}
                      {" · "}
                      {t("upload")}:{" "}
                      {limit.upload_bps === null
                        ? t("unlimited")
                        : formatMbps(limit.upload_bps)}
                    </p>
                    <p className="mt-1 text-[10px] text-warning">
                      {limit.status}
                      {limit.reason_code ? ` · ${limit.reason_code}` : ""}
                    </p>
                  </div>
                ))}
              </div>
            )}
            {result.unsupported_reasons.length > 0 && (
              <div className="space-y-1 border-t border-border pt-3">
                <h3 className="text-xs font-semibold">
                  {t("preview.unsupported")}
                </h3>
                {result.unsupported_reasons.map((reason) => (
                  <p
                    key={reason}
                    className="font-mono text-[10px] text-warning"
                  >
                    {reason}
                  </p>
                ))}
              </div>
            )}
          </section>
        )}
      </div>
    </SidePanel>
  );
}
