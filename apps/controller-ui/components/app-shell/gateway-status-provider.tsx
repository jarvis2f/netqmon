"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { subscribeVisibleEventSource } from "@/lib/visible-event-source";
import type { Release } from "@/lib/releases";

type GatewayStatus = "online" | "offline" | "degraded" | "loading";
interface GatewayState {
  gatewayName: string | null;
  gatewayStatus: GatewayStatus;
  streamStatus: "live" | "delayed" | "loading";
  controllerVersion: string | null;
  agentVersion: string | null;
  releases: Release[] | null;
  releaseCheckStatus: "loading" | "ready" | "error";
}

const INITIAL_STATE: GatewayState = {
  gatewayName: null,
  gatewayStatus: "loading",
  streamStatus: "loading",
  controllerVersion: null,
  agentVersion: null,
  releases: null,
  releaseCheckStatus: "loading",
};
const GatewayStatusContext = createContext(INITIAL_STATE);

function observedStatus(value: unknown): GatewayStatus {
  return value === "online" || value === "offline" || value === "degraded"
    ? value
    : "degraded";
}

function GatewayStatusConnection({ children }: { children: ReactNode }) {
  const [state, setState] = useState(INITIAL_STATE);

  useEffect(() => {
    let controller: AbortController | null = null;
    let active = true;
    let checkedAt = 0;
    let retryAfter = 0;
    const check = async () => {
      if (document.hidden || controller || Date.now() - checkedAt < retryAfter)
        return;
      const request = new AbortController();
      controller = request;
      try {
        const response = await fetch("/api/system/releases", {
          signal: request.signal,
        });
        if (!response.ok) throw new Error("Release check unavailable");
        const { data } = (await response.json()) as {
          data: { releases: Release[] };
        };
        if (!Array.isArray(data.releases)) throw new Error("Invalid releases");
        if (active && !request.signal.aborted) {
          checkedAt = Date.now();
          retryAfter = 3_600_000;
          setState((current) => ({
            ...current,
            releases: data.releases,
            releaseCheckStatus: "ready",
          }));
        }
      } catch {
        if (active && !request.signal.aborted) {
          checkedAt = Date.now();
          retryAfter = 300_000;
          setState((current) => ({
            ...current,
            releases: null,
            releaseCheckStatus: "error",
          }));
        }
      } finally {
        if (controller === request) controller = null;
      }
    };
    const onVisibilityChange = () => {
      if (document.hidden) {
        controller?.abort();
        controller = null;
      } else void check();
    };
    void check();
    const timer = window.setInterval(() => void check(), 300_000);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      active = false;
      controller?.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  useEffect(() => {
    let refreshController: AbortController | null = null;
    let timeout: number | undefined;
    let active = true;
    let gatewayId: string | null = null;
    let lastSeen = 0;
    let offlineAfterMs = 30_000;
    const update = (patch: Partial<GatewayState>) => {
      if (!active || document.hidden) return;
      setState((current) => {
        const next = { ...current, ...patch };
        return current.gatewayName === next.gatewayName &&
          current.gatewayStatus === next.gatewayStatus &&
          current.streamStatus === next.streamStatus &&
          current.controllerVersion === next.controllerVersion &&
          current.agentVersion === next.agentVersion
          ? current
          : next;
      });
    };
    const refresh = async () => {
      if (!active || document.hidden || refreshController) return;
      const controller = new AbortController();
      refreshController = controller;
      try {
        const response = await fetch("/api/overview/status", {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("Gateway status unavailable");
        const { data } = (await response.json()) as {
          data: {
            gateway_status: string;
            controller_version?: string;
            gateway: {
              id: string;
              name: string;
              last_seen: number;
              offline_after_ms: number;
              agent_version?: string;
            } | null;
          };
        };
        if (!active || controller.signal.aborted || document.hidden) return;
        const gateway = data.gateway;
        gatewayId = gateway?.id ?? null;
        if (gateway?.offline_after_ms && gateway.offline_after_ms > 0)
          offlineAfterMs = gateway.offline_after_ms;
        update({
          gatewayName: gateway?.name || gateway?.id || null,
          controllerVersion: data.controller_version || null,
          agentVersion: gateway?.agent_version || null,
        });
        // A slow overview request must not overwrite a newer SSE observation.
        if (!gateway || gateway.last_seen >= lastSeen) {
          lastSeen = gateway?.last_seen ?? 0;
          update({
            gatewayStatus: gateway
              ? observedStatus(data.gateway_status)
              : "offline",
          });
        }
      } catch {
        if (!controller.signal.aborted && !lastSeen)
          update({ gatewayStatus: "degraded" });
      } finally {
        if (refreshController === controller) refreshController = null;
      }
    };

    void refresh();
    const stopRealtime = subscribeVisibleEventSource(
      "/api/realtime?status_only=true",
      (events) => {
        update({ streamStatus: "loading" });
        timeout = window.setTimeout(
          () => update({ streamStatus: "delayed" }),
          8_000,
        );
        events.onopen = () => {
          window.clearTimeout(timeout);
          update({ streamStatus: "live" });
        };
        events.onerror = () => update({ streamStatus: "delayed" });
        events.addEventListener("gateway_status", (event) => {
          try {
            const data = JSON.parse(event.data) as {
              gateway_id?: string;
              status?: string;
              observed_at?: number;
            };
            if (gatewayId && data.gateway_id !== gatewayId) return;
            if (!data.status || data.status === "enrolled") return;
            if (data.status === "online" && data.observed_at)
              lastSeen = Math.max(lastSeen, data.observed_at);
            update({ gatewayStatus: observedStatus(data.status) });
          } catch {
            update({ streamStatus: "delayed" });
          }
        });
        events.addEventListener("snapshot", (event) => {
          try {
            const data = JSON.parse(event.data) as {
              gateway_health?: { observed_at?: number } | null;
            };
            const observed = data.gateway_health?.observed_at;
            if (observed && observed > lastSeen) {
              lastSeen = observed;
              update({
                gatewayStatus:
                  Date.now() - observed > offlineAfterMs ? "offline" : "online",
              });
            }
          } catch {
            update({ streamStatus: "delayed" });
          }
        });
      },
    );
    const onVisibilityChange = () => {
      if (document.hidden) {
        refreshController?.abort();
        refreshController = null;
        window.clearTimeout(timeout);
      } else {
        void refresh();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    const refreshTimer = window.setInterval(() => void refresh(), 15_000);
    const staleTimer = window.setInterval(() => {
      if (lastSeen && Date.now() - lastSeen > offlineAfterMs)
        update({ gatewayStatus: "offline" });
    }, 1_000);
    return () => {
      active = false;
      refreshController?.abort();
      stopRealtime();
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.clearTimeout(timeout);
      window.clearInterval(refreshTimer);
      window.clearInterval(staleTimer);
    };
  }, []);

  return (
    <GatewayStatusContext.Provider value={state}>
      {children}
    </GatewayStatusContext.Provider>
  );
}

export function GatewayStatusProvider({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  if (pathname === "/login" || pathname === "/setup") return children;
  return <GatewayStatusConnection>{children}</GatewayStatusConnection>;
}

export function useGatewayStatus() {
  const state = useContext(GatewayStatusContext);
  return {
    gatewayName: state.gatewayName,
    gatewayStatus: state.gatewayStatus,
    controllerVersion: state.controllerVersion,
    agentVersion: state.agentVersion,
    releases: state.releases,
    releaseCheckStatus: state.releaseCheckStatus,
    isLive:
      state.streamStatus === "loading"
        ? ("loading" as const)
        : state.streamStatus === "live" && state.gatewayStatus === "online",
  };
}
