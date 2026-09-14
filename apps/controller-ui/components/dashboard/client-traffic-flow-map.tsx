"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  Cloud,
  Cpu,
  HardDrive,
  Laptop,
  Layers,
  Network,
  Pause,
  Play,
  Router,
  Server,
  Smartphone,
  Tv,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { ClientDeviceIcon } from "@/components/icons/client-device-icon";
import { useTheme } from "@/components/theme-provider";
import { formatBitrate } from "@/lib/formatters";
import { useTopologyLabels } from "@/hooks/use-topology-labels";
import {
  resolveDeviceIconType,
  type DeviceIconType,
} from "@/lib/device-icon-resolver";
import type {
  ClientSummary,
  TopologySegment,
  TopologySummary,
} from "@/lib/network-types";

export interface ThroughputRate {
  upload_bytes_per_second: number;
  download_bytes_per_second: number;
}

interface Props {
  topology: TopologySummary | null;
  agentName: string;
  clients: ClientSummary[];
  realtimeRates: Record<string, ThroughputRate>;
  internet: ThroughputRate;
  activeInternetFlows: number;
  onlineClientCount: number;
  selectedClientId?: number | null;
  onSelectClient: (id: number) => void;
  isLive?: boolean;
}

type Category = "computer" | "mobile" | "tv" | "server" | "iot" | "other";
type NodeType = "internet" | "upstream" | "agent" | "category" | "client";
type EdgeKind = "wan" | "route" | "tunnel" | "client";

interface Segment extends TopologySegment {
  id: string;
  clients: ClientSummary[];
  unresolved?: boolean;
}

interface Node {
  id: string;
  type: NodeType;
  name: string;
  meta: string;
  down: number;
  up: number;
  x: number;
  y: number;
  category?: Category;
  client?: ClientSummary;
}

interface Edge {
  from: Node;
  to: Node;
  kind: EdgeKind;
  down: number;
  up: number;
}

const COLORS = {
  dark: {
    down: "#38bdf8",
    up: "#34d399",
    wan: "#a78bfa",
    route: "#64748b",
    tunnel: "#22d3ee",
  },
  light: {
    down: "#0284c7",
    up: "#059669",
    wan: "#7c3aed",
    route: "#64748b",
    tunnel: "#0891b2",
  },
};

function categoryOf(type: DeviceIconType): Category {
  if (type === "laptop" || type === "desktop") return "computer";
  if (type === "smartphone" || type === "tablet") return "mobile";
  if (type === "tv") return "tv";
  if (type === "nas" || type === "server") return "server";
  if (
    ["iot", "camera", "printer", "speaker", "game-console", "router"].includes(
      type,
    )
  )
    return "iot";
  return "other";
}

function categoryIcon(category?: Category) {
  if (category === "computer") return <Laptop className="size-4" />;
  if (category === "mobile") return <Smartphone className="size-4" />;
  if (category === "tv") return <Tv className="size-4" />;
  if (category === "server") return <HardDrive className="size-4" />;
  if (category === "iot") return <Cpu className="size-4" />;
  return <Layers className="size-4" />;
}

function ipv4(value: string) {
  const parts = value.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  )
    return null;
  return parts.reduce((result, part) => result * 256 + part, 0) >>> 0;
}

function ipv6(value: string) {
  const clean = value.split("%")[0].toLowerCase();
  if (!clean.includes(":")) return null;
  const halves = clean.split("::");
  if (halves.length > 2) return null;
  const parseHalf = (half: string) =>
    half ? half.split(":").filter(Boolean) : [];
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? "");
  const expandIpv4 = (parts: string[]) =>
    parts.flatMap((part) => {
      const mapped = ipv4(part);
      return mapped === null
        ? [part]
        : [
            ((mapped >>> 16) & 0xffff).toString(16),
            (mapped & 0xffff).toString(16),
          ];
    });
  const expandedLeft = expandIpv4(left);
  const expandedRight = expandIpv4(right);
  const missing = 8 - expandedLeft.length - expandedRight.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const parts = [
    ...expandedLeft,
    ...Array.from({ length: missing }, () => "0"),
    ...expandedRight,
  ];
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part)))
    return null;
  return parts.reduce(
    (result, part) =>
      (result << BigInt(16)) + BigInt(Number.parseInt(part, 16)),
    BigInt(0),
  );
}

function isInSubnet(address: string | null | undefined, cidr: string) {
  if (!address) return false;
  const [network, rawPrefix] = cidr.split("/");
  const addressNumber = ipv4(address);
  const networkNumber = ipv4(network);
  const prefix = Number(rawPrefix);
  if (
    addressNumber !== null &&
    networkNumber !== null &&
    Number.isInteger(prefix) &&
    prefix >= 0 &&
    prefix <= 32
  ) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (addressNumber & mask) === (networkNumber & mask);
  }
  const addressV6 = ipv6(address);
  const networkV6 = ipv6(network);
  if (
    addressV6 !== null &&
    networkV6 !== null &&
    Number.isInteger(prefix) &&
    prefix >= 0 &&
    prefix <= 128
  ) {
    const hostBits = BigInt(128 - prefix);
    return addressV6 >> hostBits === networkV6 >> hostBits;
  }
  return address === network;
}

function arrangeSegments(
  topology: TopologySummary | null,
  clients: ClientSummary[],
) {
  const segments: Segment[] = (topology?.segments ?? []).map(
    (segment, index) => ({
      ...segment,
      id: `segment-${index}-${segment.interface}-${segment.subnet}`,
      clients: [],
    }),
  );
  const unresolved: ClientSummary[] = [];
  clients.forEach((client) => {
    const match = segments
      .filter((segment) => isInSubnet(client.ip, segment.subnet))
      .sort(
        (a, b) =>
          Number(b.subnet.split("/")[1] ?? 0) -
          Number(a.subnet.split("/")[1] ?? 0),
      )[0];
    if (match) match.clients.push(client);
    else unresolved.push(client);
  });
  if (unresolved.length)
    segments.push({
      id: "segment-unresolved",
      subnet: "—",
      interface: "—",
      role: "unresolved",
      confidence: 0,
      clients: unresolved,
      unresolved: true,
    });
  return segments;
}

function ratesFor(
  clients: ClientSummary[],
  rates: Record<string, ThroughputRate>,
) {
  return clients.reduce(
    (result, client) => {
      const rate =
        rates[client.mac] ?? (client.ip ? rates[client.ip] : undefined);
      result.down += (rate?.download_bytes_per_second ?? 0) * 8;
      result.up += (rate?.upload_bytes_per_second ?? 0) * 8;
      return result;
    },
    { down: 0, up: 0 },
  );
}

function spread(index: number, count: number, min = 0.1, max = 0.9) {
  return count <= 1 ? 0.5 : min + (index / (count - 1)) * (max - min);
}

function rgba(hex: string, alpha: number) {
  const value = Number.parseInt(hex.slice(1), 16);
  return `rgba(${(value >> 16) & 255},${(value >> 8) & 255},${value & 255},${alpha})`;
}

class Particle {
  t = Math.random();
  seed = Math.random();
  constructor(
    public edge: Edge,
    public direction: "down" | "up",
  ) {}
  update(dt: number) {
    const traffic = this.direction === "down" ? this.edge.down : this.edge.up;
    this.t =
      (this.t +
        dt *
          (0.00028 + Math.min(traffic / 100_000_000, 1) * 0.0008) *
          (0.8 + this.seed * 0.4)) %
      1;
  }
}

export function ClientTrafficFlowMap({
  topology,
  agentName,
  clients,
  realtimeRates,
  internet,
  activeInternetFlows,
  onlineClientCount,
  selectedClientId,
  onSelectClient,
  isLive = true,
}: Props) {
  const t = useTranslations("clients.topology");
  const lt = useTranslations("clients.logicalTopology");
  const topologyLabels = useTopologyLabels();
  const { resolvedTheme } = useTheme();
  const dark = resolvedTheme === "dark";
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLElement>(null);
  const particlePool = useRef<Map<string, Particle[]>>(new Map());
  const [size, setSize] = useState({ width: 900, height: 620 });
  const [hovered, setHovered] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [category, setCategory] = useState<Category | null>(null);
  const segments = useMemo(
    () => arrangeSegments(topology, clients),
    [topology, clients],
  );
  const totals = useMemo(
    () => ({
      down: internet.download_bytes_per_second * 8,
      up: internet.upload_bytes_per_second * 8,
    }),
    [internet],
  );
  const height = useMemo(() => {
    if (!category) return 620;
    const count = clients.filter(
      (client) => categoryOf(resolveDeviceIconType(client)) === category,
    ).length;
    return Math.max(620, 540 + Math.ceil(count / 6) * 95);
  }, [category, clients]);

  const nodes = useMemo<Node[]>(() => {
    const expanded = Boolean(category);
    const result: Node[] = [
      {
        id: "internet",
        type: "internet",
        name: t("internet"),
        meta: lt("publicNetwork"),
        ...totals,
        x: 0.5,
        y: expanded ? 75 / height : 0.12,
      },
    ];
    const hasUpstream = Boolean(topology?.upstream_gateway);
    if (hasUpstream)
      result.push({
        id: "upstream",
        type: "upstream",
        name: topology!.upstream_gateway,
        meta: lt("nextHop"),
        ...totals,
        x: 0.5,
        y: expanded ? 175 / height : 0.29,
      });
    const addresses = topology?.agent_addresses ?? [];
    const addressSummary =
      addresses.length > 1
        ? `${addresses[0]} · +${addresses.length - 1}`
        : addresses[0];
    const mode = topologyLabels.value(
      "mode",
      topology?.topology_mode || "Unknown",
    );
    result.push({
      id: "agent",
      type: "agent",
      name: agentName || lt("agentFallback"),
      meta:
        [addressSummary, mode].filter(Boolean).join(" · ") ||
        lt("unknownAddress"),
      ...totals,
      x: 0.5,
      y: expanded
        ? (hasUpstream ? 275 : 210) / height
        : hasUpstream
          ? 0.46
          : 0.34,
    });
    if (!category) {
      const groups = new Map<Category, ClientSummary[]>();
      clients.forEach((client) => {
        const key = categoryOf(resolveDeviceIconType(client));
        groups.set(key, [...(groups.get(key) ?? []), client]);
      });
      [...groups.entries()].forEach(([key, group], index, entries) => {
        const routeCount = segments.filter(
          (segment) =>
            !segment.unresolved &&
            segment.clients.some((client) =>
              group.some((item) => item.id === client.id),
            ),
        ).length;
        result.push({
          id: `category-${key}`,
          type: "category",
          name: t(`categories.${key}`),
          meta: `${t("devicesCount", { count: group.length })} · ${lt("networksCount", { count: routeCount })}`,
          ...ratesFor(group, realtimeRates),
          category: key,
          x: spread(index, entries.length, 0.12, 0.88),
          y: 0.74,
        });
      });
      return result;
    }
    const visible = clients.filter(
      (client) => categoryOf(resolveDeviceIconType(client)) === category,
    );
    result.push({
      id: `category-${category}`,
      type: "category",
      name: t(`categories.${category}`),
      meta: t("devicesCount", { count: visible.length }),
      ...ratesFor(visible, realtimeRates),
      category,
      x: 0.5,
      y: 375 / height,
    });
    const columns = Math.min(6, Math.max(1, visible.length));
    visible.forEach((client, index) => {
      const row = Math.floor(index / columns);
      const rowCount = Math.min(columns, visible.length - row * columns);
      const route = segments.find((segment) =>
        segment.clients.some((item) => item.id === client.id),
      );
      const routeLabel = route?.unresolved
        ? lt("unresolvedClients")
        : route?.subnet;
      result.push({
        id: `client-${client.id}`,
        type: "client",
        name: client.name || client.mac,
        meta: [client.ip || client.mac, routeLabel].filter(Boolean).join(" · "),
        ...ratesFor([client], realtimeRates),
        client,
        category,
        x: spread(index % columns, rowCount, 0.09, 0.91),
        y: (485 + row * 95) / height,
      });
    });
    return result;
  }, [
    agentName,
    category,
    clients,
    height,
    lt,
    realtimeRates,
    segments,
    t,
    topology,
    topologyLabels,
    totals,
  ]);

  const edges = useMemo<Edge[]>(() => {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const result: Edge[] = [];
    const connect = (fromId: string, toId: string, kind: EdgeKind) => {
      const from = byId.get(fromId);
      const to = byId.get(toId);
      if (from && to) result.push({ from, to, kind, down: to.down, up: to.up });
    };
    if (byId.has("upstream")) {
      connect("internet", "upstream", "wan");
      connect("upstream", "agent", "route");
    } else connect("internet", "agent", "wan");
    nodes
      .filter((node) => node.type === "category")
      .forEach((node) => connect("agent", node.id, "route"));
    nodes
      .filter((node) => node.type === "client")
      .forEach((node) =>
        connect(`category-${node.category}`, node.id, "client"),
      );
    return result;
  }, [nodes]);

  useEffect(() => {
    const next = new Map<string, Particle[]>();
    edges.forEach((edge) => {
      const key = `${edge.from.id}->${edge.to.id}`;
      const old = particlePool.current.get(key) ?? [];
      old.forEach((particle) => {
        particle.edge = edge;
      });
      const downCount = edge.down
        ? Math.min(12, Math.max(3, Math.round(Math.sqrt(edge.down / 150_000))))
        : 2;
      const upCount = edge.up
        ? Math.min(9, Math.max(2, Math.round(Math.sqrt(edge.up / 180_000))))
        : 1;
      const down = old
        .filter((particle) => particle.direction === "down")
        .slice(0, downCount);
      const up = old
        .filter((particle) => particle.direction === "up")
        .slice(0, upCount);
      while (down.length < downCount) down.push(new Particle(edge, "down"));
      while (up.length < upCount) up.push(new Particle(edge, "up"));
      next.set(key, [...down, ...up]);
    });
    particlePool.current = next;
  }, [edges]);

  useEffect(() => {
    const resize = () => {
      if (!containerRef.current || !canvasRef.current) return;
      const width = Math.max(
        320,
        Math.round(containerRef.current.getBoundingClientRect().width),
      );
      const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
      canvasRef.current.width = width * dpr;
      canvasRef.current.height = height * dpr;
      canvasRef.current.style.width = `${width}px`;
      canvasRef.current.style.height = `${height}px`;
      setSize({ width, height });
    };
    resize();
    const observer = new ResizeObserver(resize);
    const container = containerRef.current;
    if (container) observer.observe(container);
    return () => observer.disconnect();
  }, [height]);

  useEffect(() => {
    let alive = true;
    let previous = performance.now();
    let frame = 0;
    const render = (now: number) => {
      if (!alive) return;
      const dt = Math.min(34, Math.max(1, now - previous));
      previous = now;
      const context = canvasRef.current?.getContext("2d");
      if (context) {
        const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
        context.setTransform(dpr, 0, 0, dpr, 0, 0);
        context.clearRect(0, 0, size.width, size.height);
        const palette = dark ? COLORS.dark : COLORS.light;
        const geometry = (edge: Edge) => {
          const x0 = edge.from.x * size.width,
            y0 = edge.from.y * size.height,
            x1 = edge.to.x * size.width,
            y1 = edge.to.y * size.height;
          const dx = x1 - x0,
            dy = y1 - y0,
            length = Math.hypot(dx, dy) || 1,
            bend = length * (edge.kind === "wan" ? 0.025 : 0.06);
          return {
            x0,
            y0,
            x1,
            y1,
            cx: (x0 + x1) / 2 - (dy / length) * bend,
            cy: (y0 + y1) / 2 + (dx / length) * bend,
          };
        };
        const laneWidth = (edge: Edge) =>
          3 + Math.min(1, Math.sqrt((edge.down + edge.up) / 100_000_000)) * 23;
        edges.forEach((edge) => {
          const g = geometry(edge),
            related =
              !hovered || edge.from.id === hovered || edge.to.id === hovered;
          const color =
            edge.kind === "wan"
              ? palette.wan
              : edge.kind === "tunnel"
                ? palette.tunnel
                : edge.kind === "route"
                  ? palette.route
                  : edge.down >= edge.up
                    ? palette.down
                    : palette.up;
          context.beginPath();
          context.moveTo(g.x0, g.y0);
          context.quadraticCurveTo(g.cx, g.cy, g.x1, g.y1);
          context.lineCap = "round";
          context.strokeStyle = rgba(color, related ? 0.16 : 0.04);
          context.lineWidth = laneWidth(edge) * 2;
          context.shadowBlur = related ? 18 : 0;
          context.shadowColor = rgba(color, 0.28);
          context.stroke();
          context.shadowBlur = 0;
          context.strokeStyle = rgba(color, related ? 0.5 : 0.12);
          context.lineWidth = 1.3;
          context.stroke();
        });
        particlePool.current.forEach((particles) =>
          particles.forEach((particle) => {
            if (!paused) particle.update(dt);
            const edge = particle.edge,
              g = geometry(edge),
              s = particle.direction === "down" ? particle.t : 1 - particle.t,
              u = 1 - s;
            const x = u * u * g.x0 + 2 * u * s * g.cx + s * s * g.x1,
              y = u * u * g.y0 + 2 * u * s * g.cy + s * s * g.y1;
            const color =
              edge.kind === "wan"
                ? palette.wan
                : particle.direction === "down"
                  ? palette.down
                  : palette.up;
            const related =
              !hovered || edge.from.id === hovered || edge.to.id === hovered;
            context.beginPath();
            context.arc(x, y, 1.1 + particle.seed, 0, Math.PI * 2);
            context.fillStyle = rgba(color, related ? 0.9 : 0.14);
            context.fill();
          }),
        );
      }
      frame = requestAnimationFrame(render);
    };
    frame = requestAnimationFrame(render);
    return () => {
      alive = false;
      cancelAnimationFrame(frame);
    };
  }, [dark, edges, hovered, paused, size]);

  const back = () => setCategory(null);
  return (
    <section
      ref={containerRef}
      style={{ height }}
      className="relative w-full overflow-hidden rounded-xl border border-border bg-surface-subtle/80 text-foreground shadow-sm dark:bg-[#07101d]"
    >
      <div
        className="pointer-events-none absolute inset-0 dark:hidden"
        style={{
          background:
            "radial-gradient(circle at 50% 40%,rgba(2,132,199,.08),rgba(241,245,249,.5) 46%,transparent 76%),linear-gradient(180deg,#fff,#f8fafc)",
        }}
      />
      <div
        className="pointer-events-none absolute inset-0 hidden dark:block"
        style={{
          background:
            "radial-gradient(circle at 50% 40%,rgba(56,189,248,.12),rgba(15,23,42,.45) 52%,transparent 82%),linear-gradient(180deg,#090e17,#060a12)",
        }}
      />
      <canvas
        ref={canvasRef}
        className="pointer-events-none absolute inset-0"
      />
      <header className="absolute left-4 right-4 top-3.5 z-20 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span
            className={`size-2.5 rounded-full ${isLive && !paused ? "bg-emerald-500 shadow-[0_0_12px_#10b981]" : "bg-slate-400"}`}
          />
          <div>
            <div className="flex items-center gap-2 text-sm font-bold">
              {lt("title")}
              <span className="rounded-full border border-border bg-surface/80 px-2 py-0.5 font-mono text-[10px] font-normal text-foreground-secondary">
                {topologyLabels.value(
                  "mode",
                  topology?.topology_mode || "Unknown",
                )}{" "}
                · {topology?.confidence ?? 0}%
              </span>
              {paused && (
                <span className="text-[10px] text-amber-600">
                  {t("paused")}
                </span>
              )}
            </div>
            <p className="text-[11px] text-foreground-muted">
              {lt("description")}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {category && (
            <button
              type="button"
              onClick={back}
              className="flex items-center gap-1.5 rounded-md border border-border bg-surface/90 px-2.5 py-1.5 text-xs shadow-sm hover:bg-surface-hover cursor-pointer"
            >
              <ArrowLeft className="size-3.5" />
              {lt("backToTopology")}
            </button>
          )}
          <div className="hidden items-center gap-3 rounded-md border border-border bg-surface/85 px-3 py-1.5 text-[11px] sm:flex">
            <span className="flex items-center gap-1">
              <i className="size-2 rounded-full bg-sky-500" />
              {t("legend.download")}
            </span>
            <span className="flex items-center gap-1">
              <i className="size-2 rounded-full bg-emerald-500" />
              {t("legend.upload")}
            </span>
            <span className="flex items-center gap-1">
              <i className="size-2 rounded-full bg-violet-500" />
              {t("legend.wan")}
            </span>
          </div>
          <button
            type="button"
            onClick={() => setPaused((value) => !value)}
            className="rounded-md border border-border bg-surface/90 p-1.5 cursor-pointer"
            aria-label={paused ? t("resumeAnimation") : t("pauseAnimation")}
          >
            {paused ? (
              <Play className="size-3.5" />
            ) : (
              <Pause className="size-3.5" />
            )}
          </button>
        </div>
      </header>
      {nodes.map((node) => {
        const interactive = node.type === "category" || node.type === "client",
          wan = node.type === "internet" || node.type === "upstream",
          agent = node.type === "agent",
          selected = node.client?.id === selectedClientId;
        const icon =
          node.type === "internet" ? (
            <Cloud className="size-4" />
          ) : node.type === "upstream" ? (
            <Router className="size-4" />
          ) : agent ? (
            <Server className="size-4" />
          ) : node.type === "client" && node.client ? (
            <ClientDeviceIcon client={node.client} size="sm" />
          ) : node.type === "category" ? (
            categoryIcon(node.category)
          ) : (
            <Network className="size-4" />
          );
        return (
          <button
            key={node.id}
            type="button"
            disabled={!interactive}
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}
            onClick={() => {
              if (node.type === "category") setCategory(node.category!);
              else if (node.client) onSelectClient(node.client.id);
            }}
            style={{ left: `${node.x * 100}%`, top: `${node.y * 100}%` }}
            className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 rounded-xl bg-surface/95 px-3 py-2 text-left shadow-sm backdrop-blur transition hover:shadow-md ${interactive ? "cursor-pointer" : "cursor-default"} disabled:cursor-default dark:bg-slate-900/90 ${agent ? "w-[190px] max-w-[190px] border-2 border-sky-500/40" : wan ? "min-w-[155px] border border-purple-500/40" : selected ? "min-w-[135px] scale-105 border-2 border-sky-500" : "min-w-[130px] max-w-[190px] border border-border/80 hover:border-sky-500/60"}`}
          >
            <div className="flex items-center gap-2.5">
              <span
                className={`flex size-8 shrink-0 items-center justify-center rounded-lg border ${wan ? "border-purple-200 bg-purple-100 text-purple-700 dark:bg-purple-950/80 dark:text-purple-300" : agent ? "border-sky-200 bg-sky-100 text-sky-700 dark:bg-sky-950/80 dark:text-sky-300" : "border-cyan-200 bg-cyan-100 text-cyan-700 dark:bg-cyan-950/80 dark:text-cyan-300"}`}
              >
                {icon}
              </span>
              <span className="min-w-0 flex-1">
                <b className="block truncate text-xs">{node.name}</b>
                <span
                  className="block truncate text-[10px] text-foreground-muted"
                  title={node.meta}
                >
                  {node.meta}
                </span>
              </span>
            </div>
            <div className="mt-2 flex justify-between border-t border-border/70 pt-1.5 font-mono text-[10px]">
              <span className="flex items-center gap-1 text-sky-600">
                <ArrowDown className="size-3" />
                <b>{formatBitrate(node.down)}</b>
              </span>
              <span className="flex items-center gap-1 text-emerald-600">
                <ArrowUp className="size-3" />
                <b>{formatBitrate(node.up)}</b>
              </span>
            </div>
          </button>
        );
      })}
      {topology?.topology_warnings.length ? (
        <div className="absolute bottom-14 left-4 right-4 z-20 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-[10px] text-amber-700 backdrop-blur dark:text-amber-300">
          {topology.topology_warnings.map(topologyLabels.warning).join(" · ")}
        </div>
      ) : null}
      <footer className="absolute bottom-3.5 left-4 right-4 z-20 flex flex-wrap gap-2 text-xs">
        {[
          [t("totalDown"), formatBitrate(totals.down), "text-sky-600"],
          [t("totalUp"), formatBitrate(totals.up), "text-emerald-600"],
          [t("activeFlows"), activeInternetFlows.toLocaleString(), ""],
          [t("onlineDevices"), onlineClientCount.toLocaleString(), ""],
        ].map(([label, value, color]) => (
          <span
            key={label}
            className="rounded-lg border border-border/80 bg-surface/90 px-3 py-1.5 shadow-sm"
          >
            <span className="text-foreground-muted">{label} </span>
            <b className={`font-mono ${color}`}>{value}</b>
          </span>
        ))}
      </footer>
    </section>
  );
}
