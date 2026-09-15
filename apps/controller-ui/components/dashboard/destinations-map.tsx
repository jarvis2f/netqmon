"use client";

import React, { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { useTranslations } from "next-intl";
import { formatBytes, formatIdentifier, formatPackets } from "@/lib/formatters";
import type { DestinationSummary } from "@/lib/network-types";
import { CountryFlag } from "@/components/icons/country-flag";
import { Loader2 } from "lucide-react";
import { useTheme } from "@/components/theme-provider";

const SVG_NS = "http://www.w3.org/2000/svg";

interface Point {
  x: number;
  y: number;
}

interface BezierCurve {
  p0: Point;
  p1: Point;
  p2: Point;
}

interface Particle {
  el: SVGElement;
  curve: BezierCurve;
  dir: "down" | "up";
  t: number;
  speed: number;
  throughput: number;
}

interface DestinationsMapProps {
  items: DestinationSummary[];
  onSelectDestination?: (ip: string) => void;
  loading?: boolean;
  className?: string;
  sourceGatewayName?: string;
  sourceCoordinates?: { lat: number; lng: number };
}

function bezierPoint(c: BezierCurve, t: number): Point {
  const u = 1 - t;
  return {
    x: u * u * c.p0.x + 2 * u * t * c.p1.x + t * t * c.p2.x,
    y: u * u * c.p0.y + 2 * u * t * c.p1.y + t * t * c.p2.y,
  };
}

function curvePath(c: BezierCurve): string {
  return `M ${c.p0.x} ${c.p0.y} Q ${c.p1.x} ${c.p1.y} ${c.p2.x} ${c.p2.y}`;
}

function getCurve(a: Point, b: Point): BezierCurve {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const dist = Math.hypot(dx, dy);
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;

  const nx = -dy / (dist || 1);
  const ny = dx / (dist || 1);
  const bend = Math.min(120, Math.max(28, dist * 0.16));

  return {
    p0: a,
    p1: { x: mx + nx * bend, y: my + ny * bend },
    p2: b,
  };
}

export function DestinationsMap({
  items,
  onSelectDestination,
  loading = false,
  className = "",
  sourceGatewayName = "Gateway",
  sourceCoordinates = { lat: 30.2741, lng: 120.1551 },
}: DestinationsMapProps) {
  const t = useTranslations("destinations");
  const tStatus = useTranslations("common.status");
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const animFrameRef = useRef<number | null>(null);
  const particlesRef = useRef<Particle[]>([]);
  const lastTimeRef = useRef<number | null>(null);

  const [tooltipData, setTooltipData] = useState<{
    item: DestinationSummary;
    x: number;
    y: number;
  } | null>(null);

  // Filter valid geographic items
  const validItems = React.useMemo(() => {
    return items.filter(
      (item) =>
        item.latitude !== null &&
        item.longitude !== null &&
        Number.isFinite(item.latitude) &&
        Number.isFinite(item.longitude) &&
        (item.latitude !== 0 || item.longitude !== 0),
    );
  }, [items]);

  const maxTraffic = React.useMemo(() => {
    if (!validItems.length) return 1;
    return Math.max(
      ...validItems.map((f) => f.download_bytes + f.upload_bytes),
      1,
    );
  }, [validItems]);

  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        zoomControl: true,
        attributionControl: true,
        worldCopyJump: true,
        minZoom: 2,
        maxZoom: 16,
      }).setView([25, 20], 2.2);

      mapInstanceRef.current = map;
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
        tileLayerRef.current = null;
      }
    };
  }, []);

  // Sync Leaflet Tile Layer with light/dark theme using clean unwatermarked Esri Canvas tiles
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    const tileUrl = isDark
      ? "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
      : "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}";

    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
    }

    const layer = L.tileLayer(tileUrl, {
      maxZoom: 16,
      attribution:
        '&copy; <a href="https://www.esri.com/">Esri</a>, DeLorme, NAVTEQ',
    }).addTo(map);

    tileLayerRef.current = layer;
  }, [isDark]);

  // Redraw SVG and particles when map moves, zooms, theme or items update
  useEffect(() => {
    const map = mapInstanceRef.current;
    const svg = svgRef.current;
    if (!map || !svg) return;

    const redraw = () => {
      if (!svg || !map) return;
      svg.innerHTML = "";
      particlesRef.current = [];

      const rect = map.getContainer().getBoundingClientRect();
      svg.setAttribute("viewBox", `0 0 ${rect.width} ${rect.height}`);

      const homePoint = map.latLngToContainerPoint([
        sourceCoordinates.lat,
        sourceCoordinates.lng,
      ]);

      // High contrast colors: Download = Electric Cyan (cool), Upload = Radiant Orange (warm)
      const colors = {
        glow: isDark ? "rgba(0, 229, 255, 0.08)" : "rgba(2, 132, 199, 0.08)",
        base: isDark ? "rgba(78, 116, 151, 0.35)" : "rgba(148, 163, 184, 0.45)",
        download: isDark ? "#00e5ff" : "#0284c7",
        upload: isDark ? "#ff7a00" : "#ea580c",
        homeHaloFill: isDark
          ? "rgba(0, 229, 255, 0.15)"
          : "rgba(2, 132, 199, 0.15)",
        homeHaloStroke: isDark
          ? "rgba(0, 229, 255, 0.5)"
          : "rgba(2, 132, 199, 0.55)",
        homeDot: isDark ? "#00e5ff" : "#0284c7",
        destHaloFill: isDark
          ? "rgba(0, 229, 255, 0.1)"
          : "rgba(2, 132, 199, 0.1)",
        destHaloStroke: isDark
          ? "rgba(0, 229, 255, 0.3)"
          : "rgba(2, 132, 199, 0.35)",
        destDot: isDark ? "#67e8f9" : "#0284c7",
        labelFill: isDark ? "#e2e8f0" : "#0f172a",
        labelStroke: isDark ? "#07131f" : "#ffffff",
      };

      // Home Gateway Halo & Center Dot
      const homeHalo = document.createElementNS(SVG_NS, "circle");
      homeHalo.setAttribute("cx", String(homePoint.x));
      homeHalo.setAttribute("cy", String(homePoint.y));
      homeHalo.setAttribute("r", "16");
      homeHalo.setAttribute("fill", colors.homeHaloFill);
      homeHalo.setAttribute("stroke", colors.homeHaloStroke);
      homeHalo.setAttribute("stroke-width", "1.5");
      svg.appendChild(homeHalo);

      const homeDot = document.createElementNS(SVG_NS, "circle");
      homeDot.setAttribute("cx", String(homePoint.x));
      homeDot.setAttribute("cy", String(homePoint.y));
      homeDot.setAttribute("r", "5");
      homeDot.setAttribute("fill", colors.homeDot);
      svg.appendChild(homeDot);

      validItems.forEach((flow) => {
        if (flow.latitude === null || flow.longitude === null) return;
        const dest = map.latLngToContainerPoint([
          flow.latitude,
          flow.longitude,
        ]);
        const curve = getCurve(homePoint, dest);

        const down = flow.download_bytes;
        const up = flow.upload_bytes;
        const total = down + up;
        const ratio = Math.max(0, Math.min(1, total / maxTraffic));
        const width = 1.4 + Math.min(12, Math.pow(ratio, 0.6) * 9);

        // Glow Layer
        const glow = document.createElementNS(SVG_NS, "path");
        glow.setAttribute("d", curvePath(curve));
        glow.setAttribute("fill", "none");
        glow.setAttribute("stroke", colors.glow);
        glow.setAttribute("stroke-width", String(width + 7));
        glow.setAttribute("stroke-linecap", "round");
        svg.appendChild(glow);

        // Base Layer
        const base = document.createElementNS(SVG_NS, "path");
        base.setAttribute("d", curvePath(curve));
        base.setAttribute("fill", "none");
        base.setAttribute("stroke", colors.base);
        base.setAttribute("stroke-width", String(width + 1.2));
        base.setAttribute("stroke-linecap", "round");
        svg.appendChild(base);

        // Download Layer (Cyan / Blue)
        const dShare = total > 0 ? down / total : 0.5;
        const downPath = document.createElementNS(SVG_NS, "path");
        downPath.setAttribute("d", curvePath(curve));
        downPath.setAttribute("fill", "none");
        downPath.setAttribute("stroke", colors.download);
        downPath.setAttribute(
          "stroke-opacity",
          String(Math.min(0.75, 0.3 + dShare * 0.45)),
        );
        downPath.setAttribute(
          "stroke-width",
          String(Math.max(1.2, width * dShare)),
        );
        downPath.setAttribute("stroke-linecap", "round");
        svg.appendChild(downPath);

        // Upload Layer (Orange / Coral)
        const uShare = total > 0 ? up / total : 0.5;
        const upPath = document.createElementNS(SVG_NS, "path");
        upPath.setAttribute("d", curvePath(curve));
        upPath.setAttribute("fill", "none");
        upPath.setAttribute("stroke", colors.upload);
        upPath.setAttribute(
          "stroke-opacity",
          String(Math.min(0.75, 0.3 + uShare * 0.45)),
        );
        upPath.setAttribute(
          "stroke-width",
          String(Math.max(1.0, width * uShare)),
        );
        upPath.setAttribute("stroke-linecap", "round");
        svg.appendChild(upPath);

        // Destination Halo
        const destHalo = document.createElementNS(SVG_NS, "circle");
        destHalo.setAttribute("cx", String(dest.x));
        destHalo.setAttribute("cy", String(dest.y));
        destHalo.setAttribute("r", "11");
        destHalo.setAttribute("fill", colors.destHaloFill);
        destHalo.setAttribute("stroke", colors.destHaloStroke);
        svg.appendChild(destHalo);

        // Destination Interactive Dot
        const destDot = document.createElementNS(SVG_NS, "circle");
        destDot.setAttribute("cx", String(dest.x));
        destDot.setAttribute("cy", String(dest.y));
        destDot.setAttribute("r", "4.5");
        destDot.setAttribute("fill", colors.destDot);
        destDot.setAttribute("style", "pointer-events:auto; cursor:pointer;");
        destDot.setAttribute("data-ip", flow.remote_ip);

        destDot.addEventListener("mousemove", (e) => {
          const wrapRect = map.getContainer().getBoundingClientRect();
          setTooltipData({
            item: flow,
            x: Math.min(e.clientX - wrapRect.left + 12, wrapRect.width - 220),
            y: Math.min(e.clientY - wrapRect.top + 12, wrapRect.height - 140),
          });
        });

        destDot.addEventListener("mouseleave", () => {
          setTooltipData(null);
        });

        destDot.addEventListener("click", () => {
          onSelectDestination?.(flow.remote_ip);
        });

        svg.appendChild(destDot);

        // Destination Label: Priority is Application Name -> Domain -> City/Country -> IP
        const labelText =
          flow.application_name ||
          (flow.application ? formatIdentifier(flow.application) : null) ||
          flow.domain ||
          flow.city ||
          flow.country_name ||
          flow.remote_ip;
        const label = document.createElementNS(SVG_NS, "text");
        label.setAttribute("x", String(dest.x + 8));
        label.setAttribute("y", String(dest.y - 8));
        label.setAttribute("fill", colors.labelFill);
        label.setAttribute("font-size", "10");
        label.setAttribute("font-weight", "600");
        label.setAttribute("paint-order", "stroke");
        label.setAttribute("stroke", colors.labelStroke);
        label.setAttribute("stroke-width", "3");
        label.setAttribute("stroke-linejoin", "round");
        label.setAttribute("style", "pointer-events:none; user-select:none;");
        label.textContent = labelText;
        svg.appendChild(label);

        // Particles
        const particleCount = Math.max(
          2,
          Math.min(14, Math.round(ratio * 12) + 2),
        );
        const dCount = Math.max(1, Math.round(particleCount * dShare));
        const uCount = Math.max(1, particleCount - dCount);

        for (let i = 0; i < dCount; i++) {
          const pEl = document.createElementNS(SVG_NS, "circle");
          pEl.setAttribute("r", "2.2");
          pEl.setAttribute("fill", colors.download);
          svg.appendChild(pEl);
          particlesRef.current.push({
            el: pEl,
            curve,
            dir: "down",
            t: Math.random(),
            speed: 0.00008 + Math.random() * 0.0001,
            throughput: down,
          });
        }

        for (let i = 0; i < uCount; i++) {
          const pEl = document.createElementNS(SVG_NS, "circle");
          pEl.setAttribute("r", "2.0");
          pEl.setAttribute("fill", colors.upload);
          svg.appendChild(pEl);
          particlesRef.current.push({
            el: pEl,
            curve,
            dir: "up",
            t: Math.random(),
            speed: 0.00008 + Math.random() * 0.0001,
            throughput: up,
          });
        }
      });
    };

    redraw();

    map.on("zoom move resize", redraw);
    return () => {
      map.off("zoom move resize", redraw);
    };
  }, [isDark, maxTraffic, onSelectDestination, sourceCoordinates, validItems]);

  // Particle Animation Loop
  useEffect(() => {
    let active = true;

    const animate = (now: number) => {
      const lastTime = lastTimeRef.current ?? now;
      const dt = now - lastTime;
      lastTimeRef.current = now;

      particlesRef.current.forEach((p) => {
        const boost = 0.8 + Math.min(2.0, p.throughput / 50_000_000);
        p.t += dt * p.speed * boost;
        if (p.t > 1) p.t -= 1;

        // Direction: down = remote -> gateway, up = gateway -> remote
        const tVal = p.dir === "up" ? p.t : 1 - p.t;
        const pos = bezierPoint(p.curve, tVal);

        p.el.setAttribute("cx", String(pos.x));
        p.el.setAttribute("cy", String(pos.y));

        const alpha = 0.3 + 0.7 * Math.sin(Math.PI * p.t);
        p.el.setAttribute("fill-opacity", String(Math.max(0.25, alpha)));
      });

      if (active) {
        animFrameRef.current = requestAnimationFrame(animate);
      }
    };

    animFrameRef.current = requestAnimationFrame(animate);

    return () => {
      active = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, []);

  return (
    <div
      className={`relative w-full overflow-hidden rounded-xl border border-border bg-slate-100 dark:bg-[#07131f] ${className}`}
      style={{ height: "560px", minHeight: "480px" }}
    >
      {/* Map Leaflet Container */}
      <div ref={mapContainerRef} className="h-full w-full" />

      {/* SVG Flow Overlay */}
      <div className="pointer-events-none absolute inset-0 z-[450]">
        <svg ref={svgRef} className="h-full w-full overflow-visible" />
      </div>

      {/* Top Header & Legend Overlay */}
      <div className="pointer-events-none absolute left-4 right-4 top-4 z-[500] flex items-start justify-between gap-3">
        <div className="pointer-events-auto rounded-lg border border-border bg-surface/90 px-3.5 py-2.5 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-[#050e19]/80">
          <h2 className="text-xs font-semibold text-foreground dark:text-white">
            {t("mapTitle")}
          </h2>
          <p className="mt-0.5 text-[10px] text-foreground-muted">
            {t("mapSubtitle")}
          </p>
        </div>
        <div className="pointer-events-auto flex items-center gap-3.5 rounded-lg border border-border bg-surface/90 px-3 py-2 text-[11px] text-foreground shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-[#050e19]/80 dark:text-foreground-secondary">
          <span className="flex items-center gap-1.5">
            <i className="inline-block size-2 rounded-full bg-[#00e5ff] shadow-[0_0_8px_#00e5ff]" />
            {t("download")}
          </span>
          <span className="flex items-center gap-1.5">
            <i className="inline-block size-2 rounded-full bg-[#ff7a00] shadow-[0_0_8px_#ff7a00]" />
            {t("upload")}
          </span>
        </div>
      </div>

      {/* Bottom Source Node Badge */}
      <div className="pointer-events-none absolute bottom-4 left-4 z-[500]">
        <div className="rounded-lg border border-border bg-surface/90 px-3 py-2 text-[11px] text-foreground shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-[#050e19]/80 dark:text-foreground-secondary">
          <span>{t("sourceGateway", { name: sourceGatewayName })}</span>
        </div>
      </div>

      {/* Loading Overlay */}
      {loading && (
        <div className="absolute inset-0 z-[600] flex items-center justify-center bg-surface/50 backdrop-blur-sm dark:bg-[#07131f]/60">
          <Loader2 className="size-6 animate-spin text-primary" />
        </div>
      )}

      {/* Empty geolocation state */}
      {!loading && validItems.length === 0 && (
        <div className="pointer-events-none absolute inset-0 z-[500] flex items-center justify-center">
          <div className="rounded-xl border border-border bg-surface/95 px-6 py-4 text-center shadow-lg backdrop-blur-md dark:border-white/10 dark:bg-[#050e19]/90">
            <div className="text-xs font-semibold text-foreground dark:text-white">
              {t("noGeoPoints")}
            </div>
            <div className="mt-1 text-[11px] text-foreground-muted">
              {t("noGeoPointsDesc")}
            </div>
          </div>
        </div>
      )}

      {/* Interactive Tooltip */}
      {tooltipData && (
        <div
          className="pointer-events-none absolute z-[700] min-w-48 rounded-lg border border-border bg-surface/95 p-3 shadow-xl backdrop-blur-md dark:border-white/15 dark:bg-[#050d17]/95"
          style={{ left: `${tooltipData.x}px`, top: `${tooltipData.y}px` }}
        >
          <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground dark:text-white">
            <CountryFlag code={tooltipData.item.country_code} />
            <span className="truncate">
              {tooltipData.item.application ||
                tooltipData.item.domain ||
                tooltipData.item.remote_ip}
            </span>
          </div>
          {(tooltipData.item.application || tooltipData.item.domain) && (
            <div className="mt-0.5 truncate font-mono text-[10px] text-foreground-muted">
              {tooltipData.item.application && tooltipData.item.domain
                ? `${tooltipData.item.domain} (${tooltipData.item.remote_ip})`
                : tooltipData.item.remote_ip}
            </div>
          )}
          <div className="mt-2 space-y-1 text-[11px]">
            <div className="flex justify-between gap-4 text-foreground-muted">
              <span>{t("country")}</span>
              <b className="font-medium text-foreground dark:text-white">
                {tooltipData.item.country_name ||
                  tooltipData.item.country_code ||
                  tStatus("unknown")}
              </b>
            </div>
            <div className="flex justify-between gap-4 text-foreground-muted">
              <span>{t("download")}</span>
              <b className="font-mono text-cyan-500 dark:text-[#00e5ff]">
                {formatBytes(tooltipData.item.download_bytes)}
              </b>
            </div>
            <div className="flex justify-between gap-4 text-foreground-muted">
              <span>{t("upload")}</span>
              <b className="font-mono text-orange-500 dark:text-[#ff7a00]">
                {formatBytes(tooltipData.item.upload_bytes)}
              </b>
            </div>
            <div className="flex justify-between gap-4 border-t border-border pt-1 text-foreground-muted dark:border-white/10">
              <span>{t("total")}</span>
              <b className="font-mono text-foreground dark:text-white">
                {formatBytes(
                  tooltipData.item.download_bytes +
                    tooltipData.item.upload_bytes,
                )}
              </b>
            </div>
            <div className="flex justify-between gap-4 text-[10px] text-foreground-muted">
              <span>
                {t("columns.flows")} / {t("columns.clients")}
              </span>
              <span className="font-mono text-foreground-secondary">
                {formatPackets(tooltipData.item.flow_count)} /{" "}
                {formatPackets(tooltipData.item.client_count)}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
