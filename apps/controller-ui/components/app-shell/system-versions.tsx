"use client";

import { ArrowUpRight, Check } from "lucide-react";
import { useTranslations } from "next-intl";
import { useGatewayStatus } from "@/components/app-shell/gateway-status-provider";
import { compareVersions, latestRelease } from "@/lib/releases";

export function SystemVersions() {
  const t = useTranslations("navigation.versions");
  const {
    controllerVersion,
    agentVersion,
    gatewayStatus,
    releases,
    releaseCheckStatus,
  } = useGatewayStatus();

  return (
    <dl className="flex flex-col gap-3 border-t border-border/60 bg-surface/60 px-3 py-3">
      {[
        { name: "Controller", version: controllerVersion, disconnected: false },
        {
          name: "Agent",
          version: agentVersion,
          disconnected: gatewayStatus === "offline",
        },
      ].map(({ name, version, disconnected }) => {
        const release =
          version && releases ? latestRelease(version, releases) : null;
        const comparison =
          version && release ? compareVersions(version, release.version) : null;
        const hasUpdate = comparison !== null && comparison < 0;
        const isCurrent = comparison !== null && comparison >= 0;
        const status = !version
          ? disconnected
            ? t("notConnected")
            : gatewayStatus === "loading"
              ? t("loading")
              : t("unknown")
          : releaseCheckStatus === "loading"
            ? t("checking")
            : releaseCheckStatus === "error"
              ? t("checkFailed")
              : !release || comparison === null
                ? t("unavailable")
                : hasUpdate
                  ? t("updateAvailable")
                  : t("upToDate");

        return (
          <div key={name} className="flex min-w-0 flex-col gap-1">
            <dt className="flex min-h-5 items-center justify-between gap-1">
              <span className="text-[11px] font-medium leading-none text-foreground">
                {name}
              </span>
              {hasUpdate && release ? (
                <a
                  href={release.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={t("viewRelease", {
                    name,
                    version: release.version,
                  })}
                  title={`${status} · v${release.version}`}
                  className="inline-flex shrink-0 items-center gap-0.5 rounded-md bg-warning-soft/70 px-1.5 py-1 text-[10px] font-medium leading-none text-warning transition-colors hover:bg-warning-soft focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  {t("updateAction")}
                  <ArrowUpRight className="size-2.5" aria-hidden="true" />
                </a>
              ) : (
                <span className="inline-flex shrink-0 items-center gap-0.5 text-[10px] leading-none text-foreground-muted">
                  {isCurrent && (
                    <Check
                      className="size-2.5 text-success"
                      aria-hidden="true"
                    />
                  )}
                  {status}
                </span>
              )}
            </dt>
            <dd className="m-0 flex flex-col gap-1">
              <span
                className="break-all font-mono text-[11px] leading-snug text-foreground-secondary"
                title={version ?? undefined}
              >
                {version ? `v${version.replace(/^v/, "")}` : "—"}
              </span>
              {disconnected && version && (
                <span className="text-[10px] leading-snug text-foreground-muted">
                  {t("lastConnected")}
                </span>
              )}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
