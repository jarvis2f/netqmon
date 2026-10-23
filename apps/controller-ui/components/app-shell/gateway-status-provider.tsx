"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { subscribeVisibleEventSource } from "@/lib/visible-event-source";

type GatewayStatus = "online" | "offline" | "degraded" | "loading";
interface GatewayState {
  gatewayName: string | null;
  gatewayStatus: GatewayStatus;
  streamStatus: "live" | "delayed" | "loading";
}

const INITIAL_STATE: GatewayState = {
  gatewayName: null,
  gatewayStatus: "loading",
  streamStatus: "loading",
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
          current.streamStatus === next.streamStatus
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
            gateway: {
              id: string;
              name: string;
              last_seen: number;
              offline_after_ms: number;
            } | null;
          };
        };
        if (!active || controller.signal.aborted || document.hidden) return;
        const gateway = data.gateway;
        gatewayId = gateway?.id ?? null;
        if (gateway?.offline_after_ms && gateway.offline_after_ms > 0)
          offlineAfterMs = gateway.offline_after_ms;
        update({ gatewayName: gateway?.name || gateway?.id || null });
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
    isLive:
      state.streamStatus === "loading"
        ? ("loading" as const)
        : state.streamStatus === "live" && state.gatewayStatus === "online",
  };
}
