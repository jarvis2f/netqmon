"use client";

import { useEffect, useState } from "react";
import {
  Database,
  RefreshCw,
  Save,
  Shield,
  Check,
  Copy,
  AlertTriangle,
  Play,
  Loader2,
  Globe,
  Sun,
  Moon,
  Laptop,
  Server,
  HardDrive,
  Layers,
  Terminal,
  ChevronDown,
  ChevronUp,
  UserCheck,
  Sliders,
  ExternalLink,
  Network,
  KeyRound,
} from "lucide-react";
import { useTranslations, useFormatter } from "next-intl";
import { AppLayout } from "@/components/app-shell/app-layout";
import { LanguageSwitcher } from "@/components/app-shell/language-switcher";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SimpleTooltip } from "@/components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { StatusBadge } from "@/components/network/status-badge";
import { useTheme } from "@/components/theme-provider";
import { formatBytes, formatPercent, formatTimestamp } from "@/lib/formatters";
import type {
  ApiEnvelope,
  RetentionPolicy,
  DiagnosticsInfo,
  RuleReloadResult,
  GeoDatabaseStatus,
  IconCacheStats,
} from "@/lib/network-types";
import { cn } from "@/lib/utils";
import { useTopologyLabels } from "@/hooks/use-topology-labels";
import { Input as MotionInput } from "@/components/motion/input";
import {
  StatefulButton,
  type ButtonState,
} from "@/components/motion/button/stateful";
import {
  AnimatedToastStack,
  useAnimatedToastStack,
} from "@/components/motion/animated-toast-stack";
import type { LicenseStatus } from "@/lib/network-types";

interface MetricRowProps {
  label: string;
  value: React.ReactNode;
  subtext?: string;
  mono?: boolean;
  copyable?: boolean;
}

type SettingsSection =
  | "all"
  | "general"
  | "license"
  | "icon-cache"
  | "retention"
  | "classification"
  | "geo"
  | "network-dataplane"
  | "diagnostics";

const CLASSIFIER_AVAILABILITY_KEYS: Record<string, string> = {
  ready: "classification.availability.ready",
  unavailable: "classification.availability.unavailable",
  connecting: "classification.availability.connecting",
};

const classifierAvailabilityKey = (availability: string) =>
  CLASSIFIER_AVAILABILITY_KEYS[availability] ??
  CLASSIFIER_AVAILABILITY_KEYS.unavailable;

function diagnosticsBackendName(diagnostics: DiagnosticsInfo | null): string {
  return (
    diagnostics?.analytics_backend ?? diagnostics?.db_backend ?? "database"
  );
}

function diagnosticsDatabaseSizeBytes(diagnostics: DiagnosticsInfo): number {
  if (
    diagnostics.metadata_database_size_bytes !== undefined ||
    diagnostics.analytics_database_size_bytes !== undefined
  ) {
    return (
      (diagnostics.metadata_database_size_bytes ?? 0) +
      (diagnostics.analytics_database_size_bytes ?? 0)
    );
  }
  return diagnostics.db_size_bytes ?? 0;
}

function MetricRow({
  label,
  value,
  subtext,
  mono = false,
  copyable = false,
}: MetricRowProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (typeof value === "string" || typeof value === "number") {
      void navigator.clipboard.writeText(String(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="flex items-center justify-between py-2 border-b border-border/50 last:border-0 text-xs gap-3">
      <div className="flex flex-col pr-2 shrink-0">
        <span className="text-foreground-secondary font-medium whitespace-nowrap">
          {label}
        </span>
        {subtext && (
          <span className="text-[11px] text-foreground-muted">{subtext}</span>
        )}
      </div>
      <div className="flex items-center gap-1.5 font-medium text-foreground text-right min-w-0">
        <span className={cn("truncate", mono && "font-mono tabular-nums")}>
          {value ?? "—"}
        </span>
        {copyable && typeof value === "string" && (
          <button
            type="button"
            onClick={handleCopy}
            className="p-1 rounded text-foreground-muted hover:text-foreground hover:bg-surface-hover transition-colors shrink-0 cursor-pointer"
            title={copied ? "Copied" : "Copy"}
            aria-label={`Copy ${label}`}
          >
            {copied ? (
              <Check className="size-3 text-success" />
            ) : (
              <Copy className="size-3" />
            )}
          </button>
        )}
      </div>
    </div>
  );
}

export function SettingsDashboard({ username }: { username: string }) {
  const t = useTranslations("settings");
  const topologyLabels = useTopologyLabels();
  const tNav = useTranslations("navigation");
  const { theme, setTheme } = useTheme();
  const { toasts, showToast, dismissToast } = useAnimatedToastStack();

  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [licenseKey, setLicenseKey] = useState("");
  const [licenseLoading, setLicenseLoading] = useState(true);
  const [activateState, setActivateState] = useState<ButtonState>("idle");
  const [checkState, setCheckState] = useState<ButtonState>("idle");

  // Retention state
  const [retention, setRetention] = useState<RetentionPolicy | null>(null);
  const [retentionLoading, setRetentionLoading] = useState(true);
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionMessage, setRetentionMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [retentionRunning, setRetentionRunning] = useState(false);

  // Diagnostics state
  const [diagnostics, setDiagnostics] = useState<DiagnosticsInfo | null>(null);
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(true);
  const [copiedDiag, setCopiedDiag] = useState(false);
  const [showRawDiag, setShowRawDiag] = useState(false);

  // Rules state
  const [reloadingRules, setReloadingRules] = useState(false);
  const [rulesResult, setRulesResult] = useState<RuleReloadResult | null>(null);
  const [rulesError, setRulesError] = useState<string | null>(null);

  // Geo state
  const [geoStatus, setGeoStatus] = useState<GeoDatabaseStatus | null>(null);
  const [geoLoading, setGeoLoading] = useState(true);
  const [geoUpdating, setGeoUpdating] = useState(false);
  const [geoMessage, setGeoMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [copiedGeoDir, setCopiedGeoDir] = useState(false);

  // Icon cache state
  const [iconCache, setIconCache] = useState<IconCacheStats | null>(null);
  const [iconCacheLoading, setIconCacheLoading] = useState(true);
  const [iconCacheClearing, setIconCacheClearing] = useState(false);
  const [iconCacheMessage, setIconCacheMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  // Active section tab for quick jump
  const [activeTab, setActiveTab] = useState<SettingsSection>("all");

  useEffect(() => {
    let mounted = true;

    async function fetchRetention() {
      try {
        const res = await fetch("/api/settings/retention");
        if (!res.ok) throw new Error("Failed to load retention");
        const data: ApiEnvelope<RetentionPolicy> = await res.json();
        if (mounted) setRetention(data.data);
      } catch {
        if (mounted)
          setRetentionMessage({
            type: "error",
            text: t("retention.loadError"),
          });
      } finally {
        if (mounted) setRetentionLoading(false);
      }
    }

    async function fetchDiagnostics() {
      try {
        const res = await fetch("/api/settings/diagnostics");
        if (!res.ok) throw new Error("Failed to load diagnostics");
        const data: ApiEnvelope<DiagnosticsInfo> = await res.json();
        if (mounted) setDiagnostics(data.data);
      } catch {
        // Silently handle
      } finally {
        if (mounted) setDiagnosticsLoading(false);
      }
    }

    async function fetchGeo() {
      try {
        const res = await fetch("/api/settings/geo");
        if (!res.ok) throw new Error("Failed to load geo");
        const data: ApiEnvelope<GeoDatabaseStatus> = await res.json();
        if (mounted) setGeoStatus(data.data);
      } catch {
        // Silently handle
      } finally {
        if (mounted) setGeoLoading(false);
      }
    }

    async function fetchIconCache() {
      try {
        const res = await fetch("/api/settings/icon-cache");
        if (!res.ok) throw new Error("Failed to load icon cache");
        const data: IconCacheStats = await res.json();
        if (mounted) setIconCache(data);
      } catch {
        if (mounted)
          setIconCacheMessage({
            type: "error",
            text: t("iconCache.loadError"),
          });
      } finally {
        if (mounted) setIconCacheLoading(false);
      }
    }

    async function fetchLicense() {
      try {
        const res = await fetch("/api/settings/license");
        if (!res.ok) throw new Error("Failed to load license");
        const data: ApiEnvelope<LicenseStatus> = await res.json();
        if (mounted) setLicense(data.data);
      } catch {
        if (mounted)
          showToast({ title: t("license.loadError"), status: "error" });
      } finally {
        if (mounted) setLicenseLoading(false);
      }
    }

    void fetchRetention();
    void fetchDiagnostics();
    void fetchGeo();
    void fetchIconCache();
    void fetchLicense();

    return () => {
      mounted = false;
    };
  }, [showToast, t]);

  const runLicenseAction = async (mode: "activate" | "check") => {
    const setState = mode === "activate" ? setActivateState : setCheckState;
    setState("loading");
    try {
      const response = await fetch(`/api/settings/license/${mode}`, {
        method: "POST",
        headers:
          mode === "activate"
            ? { "Content-Type": "application/json" }
            : undefined,
        body:
          mode === "activate"
            ? JSON.stringify({ license_key: licenseKey.trim() })
            : undefined,
      });
      const payload = await response.json();
      if (!response.ok)
        throw new Error(payload?.error?.message ?? t("license.actionError"));
      setLicense((payload as ApiEnvelope<LicenseStatus>).data);
      if (mode === "activate") setLicenseKey("");
      setState("success");
      showToast({
        title: t(
          mode === "activate"
            ? "license.activateSuccess"
            : "license.checkSuccess",
        ),
        status: "success",
      });
      setTimeout(() => setState("idle"), 1400);
    } catch (reason) {
      setState("error");
      showToast({
        title: t("license.actionError"),
        description: reason instanceof Error ? reason.message : undefined,
        status: "error",
      });
      setTimeout(() => setState("idle"), 1800);
    }
  };

  const handleRetentionSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!retention) return;

    setRetentionSaving(true);
    setRetentionMessage(null);

    // Validation
    if (retention.flow_sessions_days < 1 || retention.minute_days < 1) {
      setRetentionMessage({
        type: "error",
        text: t("retention.validationMin1"),
      });
      setRetentionSaving(false);
      return;
    }
    if (
      retention.dns_days < 0 ||
      retention.hour_days < 0 ||
      retention.day_days < 0
    ) {
      setRetentionMessage({
        type: "error",
        text: t("retention.validationNonNegative"),
      });
      setRetentionSaving(false);
      return;
    }

    try {
      const res = await fetch("/api/settings/retention", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(retention),
      });
      if (!res.ok) throw new Error("Failed to save");
      setRetentionMessage({
        type: "success",
        text: t("retention.saveSuccess"),
      });

      // Refresh diagnostics if db size shifted
      try {
        const diagRes = await fetch("/api/settings/diagnostics");
        if (diagRes.ok) {
          const diagData: ApiEnvelope<DiagnosticsInfo> = await diagRes.json();
          setDiagnostics(diagData.data);
        }
      } catch {}
    } catch {
      setRetentionMessage({ type: "error", text: t("retention.saveError") });
    } finally {
      setRetentionSaving(false);
    }
  };

  const handleRetentionRun = async () => {
    setRetentionRunning(true);
    setRetentionMessage(null);
    try {
      const res = await fetch("/api/settings/retention/run", {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to run");
      setRetentionMessage({ type: "success", text: t("retention.runSuccess") });
      try {
        const diagRes = await fetch("/api/settings/diagnostics");
        if (diagRes.ok) {
          const diagData: ApiEnvelope<DiagnosticsInfo> = await diagRes.json();
          setDiagnostics(diagData.data);
        }
      } catch {}
    } catch {
      setRetentionMessage({ type: "error", text: t("retention.runError") });
    } finally {
      setRetentionRunning(false);
    }
  };

  const handleReloadRules = async () => {
    setReloadingRules(true);
    setRulesError(null);
    setRulesResult(null);
    try {
      const res = await fetch("/api/settings/rules/reload", { method: "POST" });
      if (!res.ok) throw new Error("Failed to reload rules");
      const data: ApiEnvelope<RuleReloadResult> = await res.json();
      setRulesResult(data.data);
      try {
        const diagRes = await fetch("/api/settings/diagnostics");
        if (diagRes.ok) {
          const diagData: ApiEnvelope<DiagnosticsInfo> = await diagRes.json();
          setDiagnostics(diagData.data);
        }
      } catch {}
    } catch {
      setRulesError(t("classification.error"));
    } finally {
      setReloadingRules(false);
    }
  };

  const handleGeoUpdate = async () => {
    setGeoUpdating(true);
    setGeoMessage(null);
    try {
      const res = await fetch("/api/settings/geo/update", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(
          data?.error?.message || data?.error || t("geo.updateError"),
        );
      }
      if (data?.data?.status) {
        setGeoStatus(data.data.status);
      }
      setGeoMessage({ type: "success", text: t("geo.updateSuccess") });

      // Refresh diagnostics if geo status shifted
      try {
        const diagRes = await fetch("/api/settings/diagnostics");
        if (diagRes.ok) {
          const diagData: ApiEnvelope<DiagnosticsInfo> = await diagRes.json();
          setDiagnostics(diagData.data);
        }
      } catch {}
    } catch (err: unknown) {
      const errorMsg =
        err instanceof Error ? err.message : t("geo.updateError");
      setGeoMessage({ type: "error", text: errorMsg });
    } finally {
      setGeoUpdating(false);
    }
  };

  const handleClearIconCache = async () => {
    if (!window.confirm(t("iconCache.confirmClear"))) return;
    setIconCacheClearing(true);
    setIconCacheMessage(null);
    try {
      const res = await fetch("/api/settings/icon-cache/clear", {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to clear icon cache");
      const data: IconCacheStats = await res.json();
      setIconCache(data);
      setIconCacheMessage({
        type: "success",
        text: t("iconCache.clearSuccess"),
      });
    } catch {
      setIconCacheMessage({ type: "error", text: t("iconCache.clearError") });
    } finally {
      setIconCacheClearing(false);
    }
  };

  const formatTtl = (seconds?: number) => {
    if (seconds === undefined) return "—";
    if (seconds % 86_400 === 0)
      return t("iconCache.ttlDays", { count: seconds / 86_400 });
    if (seconds % 3_600 === 0)
      return t("iconCache.ttlHours", { count: seconds / 3_600 });
    return t("iconCache.ttlSeconds", { count: seconds });
  };

  const copyDiagnostics = () => {
    if (diagnostics) {
      void navigator.clipboard.writeText(JSON.stringify(diagnostics, null, 2));
      setCopiedDiag(true);
      setTimeout(() => setCopiedDiag(false), 2000);
    }
  };

  const updateRetentionField = (
    field: keyof RetentionPolicy,
    value: string,
  ) => {
    if (!retention) return;
    const num = parseInt(value, 10);
    setRetention({ ...retention, [field]: isNaN(num) ? 0 : num });
  };

  const applyRetentionPreset = (
    preset: "standard" | "compact" | "extended",
  ) => {
    if (!retention) return;
    if (preset === "standard") {
      setRetention({
        ...retention,
        flow_sessions_days: 30,
        dns_days: 7,
        minute_days: 30,
        hour_days: 90,
        day_days: 365,
      });
    } else if (preset === "compact") {
      setRetention({
        ...retention,
        flow_sessions_days: 7,
        dns_days: 3,
        minute_days: 7,
        hour_days: 30,
        day_days: 90,
      });
    } else if (preset === "extended") {
      setRetention({
        ...retention,
        flow_sessions_days: 90,
        dns_days: 30,
        minute_days: 90,
        hour_days: 365,
        day_days: 0,
      });
    }
  };

  const scrollToSection = (sectionId: SettingsSection) => {
    setActiveTab(sectionId);
    if (sectionId === "all") {
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    const element = document.getElementById(`section-${sectionId}`);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  return (
    <AppLayout
      title={tNav("settings")}
      subtitle={t("subtitle")}
      username={username}
      isLive={false}
    >
      <div className="max-w-6xl mx-auto space-y-6 pb-12">
        {/* Navigation pill bar for fast section jumping */}
        <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-3">
          <Tabs
            value={activeTab}
            onValueChange={(val) => scrollToSection(val as SettingsSection)}
            variant="pill"
            className="w-auto overflow-x-auto"
          >
            <TabsList className="h-8 p-0.5 bg-surface-subtle/80">
              <TabsTrigger value="all" className="h-7 px-3 text-xs">
                {tNav("settings")}
              </TabsTrigger>
              <TabsTrigger value="general" className="h-7 px-3 text-xs">
                {t("tabs.general")}
              </TabsTrigger>
              <TabsTrigger value="license" className="h-7 px-3 text-xs">
                {t("tabs.license")}
              </TabsTrigger>
              <TabsTrigger value="icon-cache" className="h-7 px-3 text-xs">
                {t("tabs.iconCache")}
              </TabsTrigger>
              <TabsTrigger value="retention" className="h-7 px-3 text-xs">
                {t("tabs.retention")}
              </TabsTrigger>
              <TabsTrigger value="classification" className="h-7 px-3 text-xs">
                {t("tabs.classification")}
              </TabsTrigger>
              <TabsTrigger value="geo" className="h-7 px-3 text-xs">
                {t("tabs.geo")}
              </TabsTrigger>
              <TabsTrigger
                value="network-dataplane"
                className="h-7 px-3 text-xs"
              >
                {t("tabs.networkDataplane")}
              </TabsTrigger>
              <TabsTrigger value="diagnostics" className="h-7 px-3 text-xs">
                {t("tabs.diagnostics")}
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="hidden sm:flex items-center gap-2 text-xs text-foreground-muted">
            <span className="flex items-center gap-1.5">
              <HardDrive className="size-3.5 text-accent" />
              <span>{diagnosticsBackendName(diagnostics).toUpperCase()}</span>
            </span>
            <span>•</span>
            <span className="font-mono">
              {diagnostics
                ? formatBytes(diagnosticsDatabaseSizeBytes(diagnostics))
                : "—"}
            </span>
          </div>
        </div>

        {/* Section 1: General & Preferences */}
        <section id="section-general" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("interface.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("interface.description")}
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-surface-subtle border border-border text-foreground-secondary">
              General
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Language & Theme Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                    <Globe className="size-4" />
                  </div>
                  <div>
                    <CardTitle>{t("interface.language")}</CardTitle>
                    <CardDescription>
                      {t("interface.languageDescription")}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4 pt-0">
                <div className="flex items-center justify-between py-2 border-b border-border/50">
                  <Label className="text-xs font-medium text-foreground">
                    {t("interface.language")}
                  </Label>
                  <LanguageSwitcher variant="select" />
                </div>

                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs font-medium text-foreground">
                      {t("interface.theme")}
                    </Label>
                    <span className="text-[11px] text-foreground-muted capitalize">
                      {theme}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      onClick={() => setTheme("light")}
                      className={cn(
                        "flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border text-xs font-medium transition-all cursor-pointer",
                        theme === "light"
                          ? "border-accent bg-accent-soft text-accent shadow-xs"
                          : "border-border bg-surface hover:bg-surface-hover text-foreground-secondary",
                      )}
                    >
                      <Sun className="size-3.5" />
                      <span>{t("interface.themeLight")}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setTheme("dark")}
                      className={cn(
                        "flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border text-xs font-medium transition-all cursor-pointer",
                        theme === "dark"
                          ? "border-accent bg-accent-soft text-accent shadow-xs"
                          : "border-border bg-surface hover:bg-surface-hover text-foreground-secondary",
                      )}
                    >
                      <Moon className="size-3.5" />
                      <span>{t("interface.themeDark")}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setTheme("system")}
                      className={cn(
                        "flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border text-xs font-medium transition-all cursor-pointer",
                        theme === "system"
                          ? "border-accent bg-accent-soft text-accent shadow-xs"
                          : "border-border bg-surface hover:bg-surface-hover text-foreground-secondary",
                      )}
                    >
                      <Laptop className="size-3.5" />
                      <span>{t("interface.themeSystem")}</span>
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Session Identity Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-success-soft text-success">
                    <UserCheck className="size-4" />
                  </div>
                  <div>
                    <CardTitle>{t("interface.account")}</CardTitle>
                    <CardDescription>
                      {t("interface.accountDescription")}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 pt-0">
                <MetricRow
                  label={t("interface.account")}
                  value={username}
                  mono
                />
                <MetricRow
                  label={t("interface.role")}
                  value={
                    <StatusBadge
                      status="online"
                      label={t("interface.adminRole")}
                    />
                  }
                />
                <MetricRow
                  label="Session Status"
                  value={
                    <span className="inline-flex items-center gap-1.5 text-xs text-success">
                      <span className="size-2 rounded-full bg-success animate-pulse" />
                      Authenticated
                    </span>
                  }
                />
              </CardContent>
            </Card>
          </div>
        </section>

        <section id="section-license" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("license.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("license.description")}
              </p>
            </div>
            <StatusBadge
              status={license?.edition === "pro" ? "online" : "unknown"}
              label={license?.edition === "pro" ? "Pro" : "Community"}
            />
          </div>
          <Card>
            <CardHeader className="border-b border-border/40">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                  <KeyRound className="size-4" />
                </div>
                <div>
                  <CardTitle>{t("license.cardTitle")}</CardTitle>
                  <CardDescription>
                    {t("license.cardDescription")}
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              {licenseLoading ? (
                <div className="flex h-24 items-center justify-center">
                  <Loader2 className="size-5 animate-spin text-foreground-muted" />
                </div>
              ) : (
                <>
                  <div className="grid grid-cols-1 gap-x-8 md:grid-cols-2">
                    <MetricRow
                      label={t("license.edition")}
                      value={license?.edition === "pro" ? "Pro" : "Community"}
                    />
                    <MetricRow
                      label={t("license.status")}
                      value={license?.license_status ?? "—"}
                      mono
                    />
                    <MetricRow
                      label={t("license.installationId")}
                      value={license?.installation_id ?? "—"}
                      mono
                      copyable
                    />
                    <MetricRow
                      label={t("license.ruleVersion")}
                      value={license?.rule_version ?? "—"}
                      mono
                    />
                    <MetricRow
                      label={t("license.lastCheck")}
                      value={
                        license?.last_success_at
                          ? new Date(
                              license.last_success_at * 1000,
                            ).toLocaleString()
                          : "—"
                      }
                    />
                    <MetricRow
                      label={t("license.leaseUntil")}
                      value={
                        license?.lease_valid_until
                          ? new Date(
                              license.lease_valid_until * 1000,
                            ).toLocaleString()
                          : "—"
                      }
                    />
                  </div>
                  {license?.last_error && (
                    <p
                      role="alert"
                      className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-xs text-danger"
                    >
                      {license.last_error}
                    </p>
                  )}
                  <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_auto_auto] gap-3 items-start">
                    <MotionInput
                      aria-label={t("license.keyLabel")}
                      placeholder={t("license.keyPlaceholder")}
                      value={licenseKey}
                      onChange={setLicenseKey}
                      leftIcon={<KeyRound />}
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <StatefulButton
                      state={activateState}
                      disabled={!licenseKey.trim()}
                      onClick={() => void runLicenseAction("activate")}
                      loadingText={t("license.activating")}
                      successText={t("license.activated")}
                      errorText={t("license.retry")}
                    >
                      {t("license.activate")}
                    </StatefulButton>
                    <StatefulButton
                      variant="outline"
                      state={checkState}
                      disabled={!license?.activated}
                      onClick={() => void runLicenseAction("check")}
                      loadingText={t("license.checking")}
                      successText={t("license.checked")}
                      errorText={t("license.retry")}
                    >
                      {t("license.checkNow")}
                    </StatefulButton>
                  </div>
                  <p className="text-[11px] text-foreground-muted">
                    {t("license.keyNotice")}
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        </section>

        <section id="section-icon-cache" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("iconCache.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("iconCache.description")}
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-surface-subtle border border-border text-foreground-secondary">
              {t("iconCache.badge")}
            </span>
          </div>

          <Card>
            <CardHeader className="border-b border-border/40">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                    <Globe className="size-4" />
                  </div>
                  <div>
                    <CardTitle>{t("iconCache.title")}</CardTitle>
                    <CardDescription>
                      {t("iconCache.cardDescription")}
                    </CardDescription>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleClearIconCache}
                  disabled={iconCacheClearing || iconCacheLoading}
                >
                  {iconCacheClearing ? (
                    <Loader2 className="size-3.5 animate-spin" />
                  ) : (
                    <RefreshCw className="size-3.5" />
                  )}
                  {t("iconCache.clear")}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {iconCacheLoading ? (
                <div className="flex h-24 items-center justify-center">
                  <Loader2 className="size-5 animate-spin text-foreground-muted" />
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-x-8 md:grid-cols-2">
                  <MetricRow
                    label={t("iconCache.cachedRemoteIcons")}
                    value={iconCache?.entry_count ?? 0}
                    mono
                  />
                  <MetricRow
                    label={t("iconCache.cacheSize")}
                    value={formatBytes(iconCache?.weighted_size_bytes ?? 0)}
                    mono
                  />
                  <MetricRow
                    label={t("iconCache.capacity")}
                    value={formatBytes(iconCache?.capacity_bytes ?? 0)}
                    mono
                  />
                  <MetricRow
                    label={t("iconCache.positiveTtl")}
                    value={formatTtl(iconCache?.positive_ttl_seconds)}
                    mono
                  />
                  <MetricRow
                    label={t("iconCache.negativeTtl")}
                    value={formatTtl(iconCache?.negative_ttl_seconds)}
                    mono
                  />
                </div>
              )}
              {iconCacheMessage && (
                <div
                  className={cn(
                    "mt-3 rounded-md border px-3 py-2 text-xs",
                    iconCacheMessage.type === "success"
                      ? "border-success/30 bg-success-soft text-success"
                      : "border-danger/30 bg-danger-soft text-danger",
                  )}
                >
                  {iconCacheMessage.text}
                </div>
              )}
            </CardContent>
          </Card>
        </section>

        {/* Section 2: Data Storage & Retention */}
        <section id="section-retention" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("retention.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("retention.description")}
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-surface-subtle border border-border text-foreground-secondary">
              Storage
            </span>
          </div>

          <Card>
            <CardHeader className="border-b border-border/40">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                    <HardDrive className="size-4" />
                  </div>
                  <div>
                    <CardTitle>{t("retention.title")}</CardTitle>
                    <CardDescription>
                      {t("retention.storageOverview")}
                    </CardDescription>
                  </div>
                </div>

                {/* Quick Presets */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-xs text-foreground-muted mr-1">
                    <Sliders className="size-3.5 inline mr-1" />
                    {t("retention.presets")}:
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => applyRetentionPreset("compact")}
                  >
                    {t("retention.presetCompact")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => applyRetentionPreset("standard")}
                  >
                    {t("retention.presetStandard")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => applyRetentionPreset("extended")}
                  >
                    {t("retention.presetExtended")}
                  </Button>
                </div>
              </div>
            </CardHeader>

            {retentionLoading ? (
              <div className="flex justify-center items-center p-12">
                <Loader2 className="size-6 animate-spin text-foreground-muted" />
              </div>
            ) : retention ? (
              <form onSubmit={handleRetentionSave}>
                <CardContent className="space-y-4 pb-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
                    {/* Flow Sessions */}
                    <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border/50 bg-surface-subtle/50">
                      <Label className="flex flex-col gap-0.5 text-xs font-medium text-foreground">
                        <span>{t("retention.flowSessions")}</span>
                        <span className="text-[11px] font-normal text-foreground-muted">
                          {t("retention.flowSessionsMin")}
                        </span>
                      </Label>
                      <div className="flex items-center gap-1.5 w-32 shrink-0">
                        <Input
                          type="number"
                          min={1}
                          required
                          value={retention.flow_sessions_days}
                          onChange={(e) =>
                            updateRetentionField(
                              "flow_sessions_days",
                              e.target.value,
                            )
                          }
                          className="h-8 text-right font-mono"
                        />
                        <span className="text-xs text-foreground-muted shrink-0 font-medium">
                          {t("retention.daysUnit")}
                        </span>
                      </div>
                    </div>

                    {/* DNS Observations */}
                    <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border/50 bg-surface-subtle/50">
                      <Label className="flex flex-col gap-0.5 text-xs font-medium text-foreground">
                        <span>{t("retention.dnsObservations")}</span>
                        <span className="text-[11px] font-normal text-foreground-muted">
                          {t("retention.dnsObservationsMin")}
                        </span>
                      </Label>
                      <div className="flex items-center gap-1.5 w-32 shrink-0">
                        <Input
                          type="number"
                          min={0}
                          required
                          value={retention.dns_days}
                          onChange={(e) =>
                            updateRetentionField("dns_days", e.target.value)
                          }
                          className="h-8 text-right font-mono"
                        />
                        <span className="text-xs text-foreground-muted shrink-0 font-medium">
                          {t("retention.daysUnit")}
                        </span>
                      </div>
                    </div>

                    {/* Minute Rollups */}
                    <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border/50 bg-surface-subtle/50">
                      <Label className="flex flex-col gap-0.5 text-xs font-medium text-foreground">
                        <span>{t("retention.minuteRollups")}</span>
                        <span className="text-[11px] font-normal text-foreground-muted">
                          {t("retention.minuteRollupsMin")}
                        </span>
                      </Label>
                      <div className="flex items-center gap-1.5 w-32 shrink-0">
                        <Input
                          type="number"
                          min={1}
                          required
                          value={retention.minute_days}
                          onChange={(e) =>
                            updateRetentionField("minute_days", e.target.value)
                          }
                          className="h-8 text-right font-mono"
                        />
                        <span className="text-xs text-foreground-muted shrink-0 font-medium">
                          {t("retention.daysUnit")}
                        </span>
                      </div>
                    </div>

                    {/* Hour Rollups */}
                    <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border/50 bg-surface-subtle/50">
                      <Label className="flex flex-col gap-0.5 text-xs font-medium text-foreground">
                        <span>{t("retention.hourRollups")}</span>
                        <span className="text-[11px] font-normal text-foreground-muted">
                          {t("retention.hourRollupsMin")}
                        </span>
                      </Label>
                      <div className="flex items-center gap-1.5 w-32 shrink-0">
                        <Input
                          type="number"
                          min={0}
                          required
                          value={retention.hour_days}
                          onChange={(e) =>
                            updateRetentionField("hour_days", e.target.value)
                          }
                          className="h-8 text-right font-mono"
                        />
                        <span className="text-xs text-foreground-muted shrink-0 font-medium">
                          {t("retention.daysUnit")}
                        </span>
                      </div>
                    </div>

                    {/* Day Rollups */}
                    <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border/50 bg-surface-subtle/50 md:col-span-2">
                      <Label className="flex flex-col gap-0.5 text-xs font-medium text-foreground">
                        <span>{t("retention.dayRollups")}</span>
                        <span className="text-[11px] font-normal text-foreground-muted">
                          {t("retention.dayRollupsMin")}
                        </span>
                      </Label>
                      <div className="flex items-center gap-1.5 w-32 shrink-0">
                        <Input
                          type="number"
                          min={0}
                          required
                          value={retention.day_days}
                          onChange={(e) =>
                            updateRetentionField("day_days", e.target.value)
                          }
                          className="h-8 text-right font-mono"
                        />
                        <span className="text-xs text-foreground-muted shrink-0 font-medium">
                          {t("retention.daysUnit")}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Feedback Message */}
                  {retentionMessage && (
                    <div
                      className={cn(
                        "p-3 rounded-md text-xs flex items-center gap-2 border transition-all",
                        retentionMessage.type === "success"
                          ? "bg-success-soft text-success border-success/30"
                          : "bg-danger-soft text-danger border-danger/30",
                      )}
                    >
                      {retentionMessage.type === "success" ? (
                        <Check className="size-4 shrink-0" />
                      ) : (
                        <AlertTriangle className="size-4 shrink-0" />
                      )}
                      <span>{retentionMessage.text}</span>
                    </div>
                  )}
                </CardContent>

                <CardFooter className="flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-2.5 pt-4 border-t border-border/40 bg-surface-subtle/30">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleRetentionRun}
                    disabled={retentionRunning}
                    className="gap-1.5"
                  >
                    {retentionRunning ? (
                      <Loader2 className="size-3.5 animate-spin" />
                    ) : (
                      <Play className="size-3.5 text-accent" />
                    )}
                    <span>
                      {retentionRunning
                        ? t("retention.running")
                        : t("retention.runNow")}
                    </span>
                  </Button>
                  <Button
                    type="submit"
                    variant="default"
                    size="sm"
                    disabled={retentionSaving}
                    className="gap-1.5 shadow-xs"
                  >
                    {retentionSaving ? (
                      <Loader2 className="size-3.5 animate-spin" />
                    ) : (
                      <Save className="size-3.5" />
                    )}
                    <span>
                      {retentionSaving
                        ? t("retention.saving")
                        : t("retention.save")}
                    </span>
                  </Button>
                </CardFooter>
              </form>
            ) : (
              <CardContent className="py-6 text-sm text-foreground-muted">
                {t("retention.loadError")}
              </CardContent>
            )}
          </Card>
        </section>

        {/* Section 3: Classification Rules */}
        <section id="section-classification" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("classification.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("classification.description")}
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-surface-subtle border border-border text-foreground-secondary">
              Rules
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Reload and Status Action Card */}
            <Card className="lg:col-span-1 flex flex-col justify-between">
              <div>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                      <Shield className="size-4" />
                    </div>
                    <div>
                      <CardTitle>{t("classification.title")}</CardTitle>
                      <CardDescription>
                        {t("classification.reloadHint")}
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3 pt-0 text-xs">
                  <p className="text-foreground-secondary leading-relaxed">
                    {t("classification.description")}
                  </p>

                  {rulesError && (
                    <div className="p-2.5 rounded-md bg-danger-soft border border-danger/30 text-danger flex items-center gap-2">
                      <AlertTriangle className="size-4 shrink-0" />
                      <span>{rulesError}</span>
                    </div>
                  )}

                  {rulesResult && (
                    <div className="p-3 rounded-md bg-surface-subtle border border-border space-y-2">
                      <div className="flex items-center gap-1.5 text-success font-medium">
                        <Check className="size-3.5" />
                        <span>{t("classification.success")}</span>
                      </div>
                      <div className="text-foreground-muted space-y-0.5">
                        <div>
                          {t("classification.loadedApps", {
                            count: rulesResult.application_count,
                          })}
                        </div>
                        <div>
                          {t("classification.loadedSelfhostApps", {
                            count: rulesResult.selfhost_application_count,
                          })}
                        </div>
                        <div>
                          {t("classification.reloadedAt", {
                            time: formatTimestamp(
                              rulesResult.reloaded_at,
                              "tooltip",
                            ),
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </div>

              <CardFooter className="pt-3 border-t border-border/40">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleReloadRules}
                  disabled={reloadingRules}
                  className="w-full gap-2"
                >
                  {reloadingRules ? (
                    <Loader2 className="size-3.5 animate-spin" />
                  ) : (
                    <RefreshCw className="size-3.5" />
                  )}
                  <span>
                    {reloadingRules
                      ? t("classification.reloading")
                      : t("classification.reloadButton")}
                  </span>
                </Button>
              </CardFooter>
            </Card>

            {/* Classifier Rule Statistics */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                      <Layers className="size-4" />
                    </div>
                    <div>
                      <CardTitle>
                        {t("classification.rulesBreakdown")}
                      </CardTitle>
                      <CardDescription>
                        {t("classification.rulesBreakdownDesc")}
                      </CardDescription>
                    </div>
                  </div>
                  {diagnostics?.classification && (
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded text-[10px] font-mono font-medium border",
                        diagnostics.classification.availability === "ready"
                          ? "bg-success-soft text-success border-success/30"
                          : "bg-danger-soft text-danger border-danger/30",
                      )}
                    >
                      {t(
                        classifierAvailabilityKey(
                          diagnostics.classification.availability,
                        ),
                      )}
                    </span>
                  )}
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                {diagnostics?.classification ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                    <MetricRow
                      label={t("classification.classifierdStatus")}
                      value={t(
                        classifierAvailabilityKey(
                          diagnostics.classification.availability,
                        ),
                      )}
                      subtext={
                        diagnostics.classification.last_error ?? undefined
                      }
                    />
                    <MetricRow
                      label={t("classification.classifierdVersion")}
                      value={
                        diagnostics.classification.classifier_version ?? "—"
                      }
                      mono
                    />
                    <MetricRow
                      label={t("classification.applications")}
                      value={(
                        diagnostics.classification.stats?.application_count ?? 0
                      ).toLocaleString()}
                      mono
                    />
                    <MetricRow
                      label={t("classification.selfhostApplications")}
                      value={(
                        diagnostics.classification.stats
                          ?.selfhost_application_count ?? 0
                      ).toLocaleString()}
                      mono
                    />
                    <MetricRow
                      label={t("classification.clients")}
                      value={(
                        diagnostics.classification.stats?.client_count ?? 0
                      ).toLocaleString()}
                      mono
                    />
                    <MetricRow
                      label={t("classification.protocols")}
                      value={(
                        diagnostics.classification.stats?.protocol_count ?? 0
                      ).toLocaleString()}
                      mono
                    />
                    <MetricRow
                      label={t("classification.statsRuleVersion")}
                      value={
                        diagnostics.classification.stats?.rule_version ?? "—"
                      }
                      mono
                    />
                    <MetricRow
                      label={t("classification.updatedAt")}
                      value={
                        diagnostics.classification.stats?.updated_at_unix_ms
                          ? formatTimestamp(
                              diagnostics.classification.stats
                                .updated_at_unix_ms,
                              "tooltip",
                            )
                          : "—"
                      }
                    />
                  </div>
                ) : (
                  <div className="py-6 text-center text-xs text-foreground-muted">
                    {diagnosticsLoading ? (
                      <Loader2 className="size-5 animate-spin mx-auto" />
                    ) : (
                      t("diagnostics.failed")
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </section>

        {/* Section 4: Geo Databases */}
        <section id="section-geo" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("geo.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("geo.description")}
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-surface-subtle border border-border text-foreground-secondary">
              GeoIP & ASN
            </span>
          </div>

          {/* Feedback Message */}
          {geoMessage && (
            <div
              className={cn(
                "p-3 rounded-md text-xs flex items-center gap-2 border transition-all",
                geoMessage.type === "success"
                  ? "bg-success-soft text-success border-success/30"
                  : "bg-danger-soft text-danger border-danger/30",
              )}
            >
              {geoMessage.type === "success" ? (
                <Check className="size-4 shrink-0" />
              ) : (
                <AlertTriangle className="size-4 shrink-0" />
              )}
              <span>{geoMessage.text}</span>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Overview & Action Card */}
            <Card className="lg:col-span-1 flex flex-col justify-between">
              <div>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                        <Globe className="size-4" />
                      </div>
                      <div>
                        <CardTitle>{t("geo.title")}</CardTitle>
                        <CardDescription>
                          {t("geo.autoSourceNotice")}
                        </CardDescription>
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 pt-0 text-xs">
                  <MetricRow
                    label={t("geo.status")}
                    value={
                      <StatusBadge
                        status={geoStatus?.enabled ? "online" : "offline"}
                        label={
                          geoStatus?.enabled
                            ? t("geo.enabled")
                            : t("geo.disabled")
                        }
                      />
                    }
                  />

                  <div className="space-y-1.5 pt-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-foreground-secondary font-medium">
                        {t("geo.directory")}
                      </span>
                      {geoStatus?.directory && (
                        <button
                          type="button"
                          onClick={() => {
                            void navigator.clipboard.writeText(
                              geoStatus.directory,
                            );
                            setCopiedGeoDir(true);
                            setTimeout(() => setCopiedGeoDir(false), 1500);
                          }}
                          className="inline-flex items-center gap-1 text-[11px] text-foreground-muted hover:text-foreground transition-colors px-1.5 py-0.5 rounded hover:bg-surface-hover cursor-pointer"
                        >
                          {copiedGeoDir ? (
                            <>
                              <Check className="size-3 text-success" />
                              <span className="text-success">
                                {t("diagnostics.copied")}
                              </span>
                            </>
                          ) : (
                            <>
                              <Copy className="size-3" />
                              <span>{t("diagnostics.copy")}</span>
                            </>
                          )}
                        </button>
                      )}
                    </div>
                    <div
                      className="px-2.5 py-2 rounded-md bg-surface-subtle border border-border/70 font-mono text-[11px] text-foreground break-all select-all leading-relaxed"
                      title={geoStatus?.directory}
                    >
                      {geoStatus?.directory ?? "—"}
                    </div>
                  </div>
                </CardContent>
              </div>

              <CardFooter className="pt-3 border-t border-border/40 flex flex-col gap-2">
                <Button
                  type="button"
                  variant="default"
                  size="sm"
                  onClick={handleGeoUpdate}
                  disabled={geoUpdating}
                  className="w-full gap-2 shadow-xs"
                >
                  {geoUpdating ? (
                    <Loader2 className="size-3.5 animate-spin" />
                  ) : (
                    <RefreshCw className="size-3.5" />
                  )}
                  <span>
                    {geoUpdating ? t("geo.updating") : t("geo.updateNow")}
                  </span>
                </Button>
              </CardFooter>
            </Card>

            {/* Databases Cards */}
            <div className="lg:col-span-2 space-y-4">
              {geoLoading ? (
                <Card className="flex items-center justify-center p-8">
                  <Loader2 className="size-6 animate-spin text-accent" />
                </Card>
              ) : geoStatus && geoStatus.databases.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {geoStatus.databases.map((db) => (
                    <Card
                      key={db.filename}
                      className="flex flex-col justify-between"
                    >
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-1 min-w-0">
                            <CardTitle
                              className="text-sm font-mono truncate"
                              title={db.filename}
                            >
                              {db.filename}
                            </CardTitle>
                            <CardDescription className="text-xs">
                              {db.database_type ||
                                (db.filename.includes("Country")
                                  ? "IP to Country Lite"
                                  : "IP to ASN Lite")}
                            </CardDescription>
                          </div>
                          <StatusBadge
                            status={db.installed ? "online" : "offline"}
                            label={
                              db.installed
                                ? t("geo.installed")
                                : t("geo.notInstalled")
                            }
                          />
                        </div>
                      </CardHeader>
                      <CardContent className="pt-0 space-y-1 text-xs">
                        <MetricRow
                          label={t("geo.buildDate")}
                          value={
                            db.build_date ||
                            (db.build_epoch
                              ? new Date(
                                  db.build_epoch * 1000,
                                ).toLocaleDateString()
                              : "—")
                          }
                          mono
                        />
                        <MetricRow
                          label={t("geo.fileSize")}
                          value={
                            db.installed ? formatBytes(db.file_size_bytes) : "—"
                          }
                          mono
                        />
                        <MetricRow
                          label={t("geo.lastModified")}
                          value={
                            db.last_modified_unix_s
                              ? new Date(
                                  db.last_modified_unix_s * 1000,
                                ).toLocaleString()
                              : "—"
                          }
                        />
                        {db.record_count != null && (
                          <MetricRow
                            label="Nodes / Records"
                            value={db.record_count.toLocaleString()}
                            mono
                          />
                        )}
                      </CardContent>
                      <CardFooter className="pt-2 pb-3 border-t border-border/40 text-[11px] flex justify-between items-center text-foreground-muted">
                        <span className="truncate">Source</span>
                        <a
                          href={
                            db.source_url.startsWith("http")
                              ? db.source_url
                              : undefined
                          }
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-accent hover:underline font-mono"
                        >
                          <span className="truncate max-w-[160px]">
                            {db.source_url.replace(
                              "https://db-ip.com/db/download/",
                              "",
                            )}
                          </span>
                          <ExternalLink className="size-3 shrink-0" />
                        </a>
                      </CardFooter>
                    </Card>
                  ))}
                </div>
              ) : (
                <Card className="p-6 text-center text-sm text-foreground-muted">
                  {t("geo.loadError")}
                </Card>
              )}
            </div>
          </div>
        </section>

        <section id="section-network-dataplane" className="space-y-4">
          <div>
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              {t("networkDataplane.title")}
            </h2>
            <p className="mt-0.5 text-xs text-foreground-muted">
              {t("networkDataplane.description")}
            </p>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <span className="rounded-md bg-accent-soft p-1.5 text-accent">
                    <Network className="size-4" />
                  </span>
                  <CardTitle>{t("networkDataplane.logicalTopology")}</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-1 pt-0">
                <MetricRow
                  label={t("networkDataplane.topologyMode")}
                  value={topologyLabels.value(
                    "mode",
                    diagnostics?.topology?.topology_mode,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.agentAddress")}
                  value={diagnostics?.topology?.agent_addresses.join(", ")}
                  mono
                  copyable
                />
                <MetricRow
                  label={t("networkDataplane.captureInterface")}
                  value={diagnostics?.topology?.capture_interface}
                  mono
                />
                <MetricRow
                  label={t("networkDataplane.upstreamGateway")}
                  value={diagnostics?.topology?.upstream_gateway}
                  mono
                  copyable
                />
                <MetricRow
                  label={t("networkDataplane.nat")}
                  value={topologyLabels.value(
                    "nat",
                    diagnostics?.topology?.nat_status,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.confidence")}
                  value={
                    diagnostics?.topology
                      ? `${diagnostics.topology.confidence}%`
                      : undefined
                  }
                  mono
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>{t("networkDataplane.dataplaneHealth")}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 pt-0">
                <MetricRow
                  label={t("networkDataplane.attachBackend")}
                  value={topologyLabels.value(
                    "backend",
                    diagnostics?.topology?.attach_backend,
                  )}
                  mono
                />
                <MetricRow
                  label={t("networkDataplane.attachOrder")}
                  value={topologyLabels.value(
                    "order",
                    diagnostics?.topology?.attach_order,
                  )}
                  mono
                />
                <MetricRow
                  label={t("networkDataplane.ipv4Coverage")}
                  value={topologyLabels.value(
                    "coverage",
                    diagnostics?.topology?.ipv4_coverage,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.ipv6Coverage")}
                  value={topologyLabels.value(
                    "coverage",
                    diagnostics?.topology?.ipv6_coverage,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.icmpRedirect")}
                  value={topologyLabels.value(
                    "status",
                    diagnostics?.topology?.icmp_redirect,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.softwareOffload")}
                  value={topologyLabels.value(
                    "status",
                    diagnostics?.topology?.software_flow_offload,
                  )}
                />
                <MetricRow
                  label={t("networkDataplane.hardwareOffload")}
                  value={topologyLabels.value(
                    "status",
                    diagnostics?.topology?.hardware_flow_offload,
                  )}
                />
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>{t("networkDataplane.networks")}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2 pt-0 sm:grid-cols-2 lg:grid-cols-3">
              {diagnostics?.topology?.segments.length ? (
                diagnostics.topology.segments.map((segment) => (
                  <div
                    key={`${segment.interface}-${segment.subnet}`}
                    className="rounded-lg border border-border bg-surface-subtle px-3 py-2"
                  >
                    <div className="font-mono text-xs font-semibold">
                      {segment.subnet}
                    </div>
                    <div className="mt-0.5 text-[10px] uppercase tracking-wide text-foreground-muted">
                      {topologyLabels.value("role", segment.role)} ·{" "}
                      {segment.interface || "—"}
                    </div>
                  </div>
                ))
              ) : (
                <span className="text-xs text-foreground-muted">
                  {t("networkDataplane.unavailable")}
                </span>
              )}
            </CardContent>
          </Card>
          {diagnostics?.topology?.topology_warnings.length ? (
            <div className="rounded-xl border border-warning/30 bg-warning/10 p-4 text-xs text-warning-foreground">
              <div className="mb-2 flex items-center gap-2 font-semibold">
                <AlertTriangle className="size-4" />
                {t("networkDataplane.warnings")}
              </div>
              <ul className="space-y-1 pl-5 list-disc">
                {diagnostics.topology.topology_warnings.map((warning) => (
                  <li key={warning}>{topologyLabels.warning(warning)}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>

        {/* System & Gateway Diagnostics */}
        <section id="section-diagnostics" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-foreground tracking-tight">
                {t("diagnostics.title")}
              </h2>
              <p className="text-xs text-foreground-muted mt-0.5">
                {t("diagnostics.description")}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <SimpleTooltip content={t("diagnostics.copy")}>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  onClick={copyDiagnostics}
                  disabled={!diagnostics || diagnosticsLoading}
                  className="gap-1.5 text-xs"
                >
                  {copiedDiag ? (
                    <Check className="size-3 text-success" />
                  ) : (
                    <Copy className="size-3" />
                  )}
                  <span>
                    {copiedDiag
                      ? t("diagnostics.copied")
                      : t("diagnostics.copy")}
                  </span>
                </Button>
              </SimpleTooltip>
            </div>
          </div>

          <SamplingPanel sampling={diagnostics?.sampling} />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Gateway Hardware Details */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                      <Server className="size-4" />
                    </div>
                    <div>
                      <CardTitle>{t("diagnostics.gatewayInfo")}</CardTitle>
                      <CardDescription>
                        Edge OpenWrt Probe & Linux Kernel
                      </CardDescription>
                    </div>
                  </div>
                  {diagnostics?.gateway ? (
                    <StatusBadge status="online" label="Online" />
                  ) : (
                    <StatusBadge
                      status="offline"
                      label={t("diagnostics.notConnected")}
                    />
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-1 pt-0">
                {diagnostics?.gateway ? (
                  <>
                    <MetricRow
                      label={t("diagnostics.gatewayName")}
                      value={diagnostics.gateway.name}
                    />
                    <MetricRow
                      label={t("diagnostics.gatewayId")}
                      value={diagnostics.gateway.id}
                      mono
                      copyable
                    />
                    <MetricRow
                      label={t("diagnostics.agentVersion")}
                      value={diagnostics.gateway.agent_version}
                      mono
                    />
                    <MetricRow
                      label={t("diagnostics.kernel")}
                      value={diagnostics.gateway.kernel_version}
                      mono
                    />
                  </>
                ) : (
                  <div className="py-6 text-center text-xs text-foreground-muted">
                    {diagnosticsLoading ? (
                      <Loader2 className="size-5 animate-spin mx-auto" />
                    ) : (
                      t("diagnostics.notConnected")
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Observatory Collector Core */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-accent-soft text-accent">
                    <Database className="size-4" />
                  </div>
                  <div>
                    <CardTitle>{t("diagnostics.title")}</CardTitle>
                    <CardDescription>
                      Backend Storage & Telemetry Metrics
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-1 pt-0">
                {diagnostics ? (
                  <>
                    <MetricRow
                      label={t("diagnostics.collectorVersion")}
                      value={diagnostics.collector_version}
                      mono
                    />
                    <MetricRow
                      label={t("diagnostics.dbBackend")}
                      value={diagnosticsBackendName(diagnostics).toUpperCase()}
                    />
                    <MetricRow
                      label={t("diagnostics.dbSize")}
                      value={formatBytes(
                        diagnosticsDatabaseSizeBytes(diagnostics),
                      )}
                      mono
                    />
                    <MetricRow
                      label={t("diagnostics.activeFlows")}
                      value={(
                        diagnostics.active_flow_count ??
                        diagnostics.active_flows ??
                        0
                      ).toLocaleString()}
                      mono
                    />
                    <MetricRow
                      label={t("diagnostics.unknownRatio")}
                      value={formatPercent(diagnostics.unknown_ratio)}
                      mono
                    />
                    <MetricRow
                      label={t("diagnostics.geoDb")}
                      value={
                        diagnostics.geo_enabled ? (
                          <span className="text-xs text-success font-medium flex items-center gap-1">
                            <span className="size-1.5 rounded-full bg-success" />
                            {t("diagnostics.enabled")}
                          </span>
                        ) : (
                          <span className="text-xs text-foreground-muted">
                            {t("diagnostics.disabled")}
                          </span>
                        )
                      }
                    />
                  </>
                ) : (
                  <div className="py-6 text-center text-xs text-foreground-muted">
                    {diagnosticsLoading ? (
                      <Loader2 className="size-5 animate-spin mx-auto" />
                    ) : (
                      t("diagnostics.failed")
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Collapsible Raw JSON Diagnostics */}
          {diagnostics && (
            <Card className="border-dashed">
              <button
                type="button"
                onClick={() => setShowRawDiag(!showRawDiag)}
                className="w-full px-4 py-3 flex items-center justify-between text-xs font-medium text-foreground-secondary hover:text-foreground hover:bg-surface-hover/50 transition-colors cursor-pointer"
              >
                <span className="flex items-center gap-2">
                  <Terminal className="size-3.5 text-foreground-muted" />
                  <span>Raw Diagnostic Telemetry Payload</span>
                </span>
                {showRawDiag ? (
                  <ChevronUp className="size-4" />
                ) : (
                  <ChevronDown className="size-4" />
                )}
              </button>
              {showRawDiag && (
                <CardContent className="pt-0 pb-4 border-t border-border/40">
                  <pre className="p-3 mt-3 rounded-md bg-surface-subtle font-mono text-[11px] text-foreground-secondary overflow-x-auto max-h-72 border border-border/50">
                    {JSON.stringify(diagnostics, null, 2)}
                  </pre>
                </CardContent>
              )}
            </Card>
          )}
        </section>
      </div>
      <AnimatedToastStack toasts={toasts} onDismiss={dismissToast} fixed />
    </AppLayout>
  );
}

function SamplingPanel({
  sampling,
}: {
  sampling: DiagnosticsInfo["sampling"];
}) {
  const t = useTranslations("settings.sampling");
  const formatter = useFormatter();
  const number = (value: number) =>
    formatter.number(value, { maximumFractionDigits: 2 });
  const state = (enabled: boolean) => (enabled ? t("enabled") : t("disabled"));
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("title")}</CardTitle>
        <CardDescription>
          {sampling
            ? t("window", {
                minutes: Math.max(1, Math.round(sampling.window_seconds / 60)),
              })
            : t("unavailable")}
        </CardDescription>
      </CardHeader>
      {sampling && (
        <CardContent className="grid gap-6 lg:grid-cols-3">
          <div className="min-w-0">
            <h3 className="mb-2 text-sm font-medium">{t("configuration")}</h3>
            <MetricRow label={t("engine")} value={sampling.engine} mono />
            <MetricRow
              label={t("dpiEnabled")}
              value={state(sampling.enabled)}
            />
            <MetricRow
              label={t("engineAvailable")}
              value={sampling.available ? t("available") : t("unavailable")}
            />
            {sampling.configs.length === 0 && (
              <p className="py-2 text-xs text-muted-foreground">
                {t("waiting")}
              </p>
            )}
            {sampling.configs.map((config) => (
              <div key={config.gateway_id} className="flex flex-col gap-1 pt-2">
                {sampling.configs.length > 1 && (
                  <p className="break-all font-mono text-xs">
                    {config.gateway_id}
                  </p>
                )}
                <MetricRow
                  label={t("sampleEnabled")}
                  value={state(config.enabled)}
                />
                <MetricRow
                  label={t("bytesFlow")}
                  value={formatBytes(config.max_bytes_per_flow)}
                  mono
                />
                <MetricRow
                  label={t("packetsDirection")}
                  value={number(config.max_packets_per_direction)}
                  mono
                />
                <MetricRow
                  label={t("bytesPacket")}
                  value={formatBytes(config.max_bytes_per_packet)}
                  mono
                />
              </div>
            ))}
          </div>
          <div className="min-w-0">
            <h3 className="mb-2 text-sm font-medium">{t("observations")}</h3>
            <MetricRow
              label={t("sampleCount")}
              value={number(sampling.sample_count)}
              mono
            />
            <MetricRow
              label={t("sampledFlows")}
              value={number(sampling.sampled_flows)}
              mono
            />
            <MetricRow
              label={t("bytes")}
              value={formatBytes(sampling.sample_bytes)}
              mono
            />
            <MetricRow
              label={t("average")}
              value={formatBytes(sampling.average_sample_bytes)}
              mono
            />
            <MetricRow
              label={t("p95")}
              value={formatBytes(sampling.p95_sample_bytes)}
              mono
            />
            <MetricRow
              label={t("maximum")}
              value={formatBytes(sampling.max_sample_bytes)}
              mono
            />
            <MetricRow
              label={t("success")}
              value={
                sampling.sampled_flows
                  ? formatPercent(sampling.dpi_success_rate)
                  : "—"
              }
              mono
            />
            <MetricRow
              label={t("drops")}
              value={number(sampling.sample_drops)}
              mono
            />
          </div>
          <div className="min-w-0">
            <h3 className="mb-2 text-sm font-medium">{t("impactTitle")}</h3>
            <MetricRow
              label={t("impact")}
              value={sampling.impact ? t(sampling.impact) : "—"}
            />
            <MetricRow
              label={t("bandwidth")}
              value={`${number(sampling.bandwidth_kbps)} Kbps`}
              mono
            />
            <MetricRow
              label={t("ratio")}
              value={
                sampling.traffic_ratio === null
                  ? "—"
                  : formatter.number(sampling.traffic_ratio, {
                      style: "percent",
                      maximumFractionDigits: 2,
                    })
              }
              mono
            />
            <MetricRow
              label={t("newFlows")}
              value={number(sampling.new_flows)}
              mono
            />
            <MetricRow
              label={t("flowRate")}
              value={`${number(sampling.new_flows_per_second)} / s`}
              mono
            />
            <MetricRow
              label={t("dropRate")}
              value={formatter.number(sampling.sample_drop_rate, {
                style: "percent",
                maximumFractionDigits: 2,
              })}
              mono
            />
            <MetricRow
              label={t("theoretical")}
              value={`${number(sampling.theoretical_max_kbps)} Kbps`}
              mono
            />
            <p className="pt-3 text-xs leading-relaxed text-muted-foreground">
              {t("basis")}
            </p>
          </div>
        </CardContent>
      )}
      <CardFooter>
        <p className="text-xs leading-relaxed text-muted-foreground">
          {t("privacy")}
        </p>
      </CardFooter>
    </Card>
  );
}
