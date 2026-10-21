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
    route: "#38bdf8",
    tunnel: "#22d3ee",
    track: "rgba(148, 163, 184, 0.14)",
    trackCenter: "rgba(148, 163, 184, 0.22)",
  },
  light: {
    down: "#0284c7",
    up: "#059669",
    wan: "#7c3aed",
    route: "#0284c7",
    tunnel: "#0891b2",
    track: "rgba(100, 116, 139, 0.16)",
    trackCenter: "rgba(100, 116, 139, 0.24)",
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

class FlowParticle {
  t: number;
  seed: number;
  lateralOffset: number;
  size: number;
  direction: "down" | "up";
  edge: Edge;

  constructor(edge: Edge, direction: "down" | "up", initialT?: number) {
    this.edge = edge;
    this.direction = direction;
    this.seed = Math.random();
    this.t = initialT ?? Math.random();
    this.lateralOffset = (Math.random() - 0.5) * 0.8;
    this.size = 2.2 + Math.random() * 0.9;
  }

  update(dt: number) {
    const traffic = this.direction === "down" ? this.edge.down : this.edge.up;
    const trafficFactor = Math.min(
      1,
      Math.log10(Math.max(1, traffic / 1000)) / 6,
    );
    const speed =
      (0.00016 + trafficFactor * 0.00036) * (0.85 + this.seed * 0.3);
    this.t = (this.t + dt * speed) % 1;
  }
}

function computeParticleCount(trafficBps: number, isWan: boolean): number {
  if (trafficBps <= 0) {
    return 1;
  }
  const factor = Math.log10(Math.max(10, trafficBps / 5000));
  const count = Math.round(2 + Math.max(0, factor) * 3.5);
  return Math.min(isWan ? 20 : 16, Math.max(2, count));
}

interface EdgeGeometry {
  p0x: number;
  p0y: number;
  p1x: number;
  p1y: number;
  p2x: number;
  p2y: number;
  p3x: number;
  p3y: number;
  spanY: number;
  dx: number;
}

function getEdgeGeometry(
  edge: Edge,
  width: number,
  height: number,
): EdgeGeometry {
  const deltaY = Math.max(10, (edge.to.y - edge.from.y) * height);
  const cardHalfHeight = Math.min(36, deltaY * 0.35);

  const p0x = edge.from.x * width;
  const p0y = edge.from.y * height + cardHalfHeight;
  const p3x = edge.to.x * width;
  const p3y = edge.to.y * height - cardHalfHeight;

  const spanY = Math.max(1, p3y - p0y);
  const p1x = p0x;
  const p1y = p0y + spanY * 0.5;
  const p2x = p3x;
  const p2y = p3y - spanY * 0.5;

  return {
    p0x,
    p0y,
    p1x,
    p1y,
    p2x,
    p2y,
    p3x,
    p3y,
    spanY,
    dx: p3x - p0x,
  };
}

function evalCurve(g: EdgeGeometry, s: number) {
  const t = Math.max(0, Math.min(1, s));
  const x = g.p0x + g.dx * (3 * t * t - 2 * t * t * t);
  const y = g.p0y + g.spanY * t;

  const dxdt = g.dx * 6 * t * (1 - t);
  const dydt = g.spanY;
  const len = Math.hypot(dxdt, dydt) || 1;

  const tx = dxdt / len;
  const ty = dydt / len;
  const nx = -ty;
  const ny = tx;

  return { x, y, tx, ty, nx, ny };
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
  const particlePool = useRef<Map<string, FlowParticle[]>>(new Map());
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
    const next = new Map<string, FlowParticle[]>();
    edges.forEach((edge) => {
      const key = `${edge.from.id}->${edge.to.id}`;
      const old = particlePool.current.get(key) ?? [];
      old.forEach((particle) => {
        particle.edge = edge;
      });
      const isWan = edge.kind === "wan";
      const downCount = computeParticleCount(edge.down, isWan);
      const upCount = computeParticleCount(edge.up, isWan);
      const down = old
        .filter((particle) => particle.direction === "down")
        .slice(0, downCount);
      const up = old
        .filter((particle) => particle.direction === "up")
        .slice(0, upCount);

      while (down.length < downCount) {
        const idx = down.length;
        const initialT = (idx / downCount + Math.random() * 0.1) % 1;
        down.push(new FlowParticle(edge, "down", initialT));
      }
      while (up.length < upCount) {
        const idx = up.length;
        const initialT = (idx / upCount + Math.random() * 0.1) % 1;
        up.push(new FlowParticle(edge, "up", initialT));
      }
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

        const geometries = new Map<Edge, EdgeGeometry>();
        edges.forEach((edge) => {
          geometries.set(edge, getEdgeGeometry(edge, size.width, size.height));
        });

        // 1. Base Conduit Tracks (Clean subtle highway lines)
        edges.forEach((edge) => {
          const g = geometries.get(edge)!;
          const related =
            !hovered || edge.from.id === hovered || edge.to.id === hovered;

          context.beginPath();
          context.moveTo(g.p0x, g.p0y);
          context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
          context.lineCap = "round";
          context.strokeStyle = palette.track;
          context.lineWidth = related ? 3.5 : 2.5;
          context.stroke();

          // Core centerline
          context.beginPath();
          context.moveTo(g.p0x, g.p0y);
          context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
          context.strokeStyle = palette.trackCenter;
          context.lineWidth = 1;
          context.stroke();
        });

        // 2. Active Glowing Conduits (Luminous translucent aura for active bandwidth)
        edges.forEach((edge) => {
          const totalTraffic = edge.down + edge.up;
          if (totalTraffic <= 0) return;
          const g = geometries.get(edge)!;
          const related =
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

          const glowWidth =
            5 +
            Math.min(12, Math.log10(Math.max(10, totalTraffic / 30_000)) * 2.8);

          context.save();
          context.beginPath();
          context.moveTo(g.p0x, g.p0y);
          context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
          context.lineCap = "round";
          context.strokeStyle = rgba(color, related ? 0.16 : 0.04);
          context.lineWidth = glowWidth;
          context.shadowBlur = related ? 14 : 0;
          context.shadowColor = rgba(color, 0.35);
          context.stroke();
          context.restore();
        });

        // 3. Hardware Cable Ports (Glowing Connection Pins at top & bottom anchors)
        edges.forEach((edge) => {
          const g = geometries.get(edge)!;
          const related =
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

          const portAlpha = related ? 0.75 : 0.25;

          context.beginPath();
          context.arc(g.p0x, g.p0y, 2.5, 0, Math.PI * 2);
          context.fillStyle = rgba(color, portAlpha);
          context.fill();

          context.beginPath();
          context.arc(g.p3x, g.p3y, 2.5, 0, Math.PI * 2);
          context.fillStyle = rgba(color, portAlpha);
          context.fill();
        });

        // 4. UniFi Particle Pulses with Comet Trails & Glowing Laser Cores
        particlePool.current.forEach((particles) => {
          particles.forEach((particle) => {
            if (!paused) particle.update(dt);
            const edge = particle.edge;
            const g = geometries.get(edge);
            if (!g) return;

            const related =
              !hovered || edge.from.id === hovered || edge.to.id === hovered;
            const traffic = particle.direction === "down" ? edge.down : edge.up;
            const isIdle = traffic === 0;

            const color =
              edge.kind === "wan"
                ? palette.wan
                : particle.direction === "down"
                  ? palette.down
                  : palette.up;

            const headS =
              particle.direction === "down" ? particle.t : 1 - particle.t;
            const tailStepSign = particle.direction === "down" ? -1 : 1;

            const trailSpan = isIdle
              ? 0.038
              : 0.042 +
                Math.min(
                  0.045,
                  Math.log10(Math.max(1, traffic / 10_000)) * 0.012,
                );

            const edgeFade = Math.min(
              1,
              Math.min(headS / 0.07, (1 - headS) / 0.07),
            );
            const idleAlpha = isIdle ? 0.38 : 1.0;
            const relatedAlpha = related ? 1.0 : 0.15;
            const totalAlpha = Math.min(
              1,
              Math.max(0, edgeFade * idleAlpha * relatedAlpha),
            );

            if (totalAlpha <= 0.02) return;

            // Separate bidirectional lanes cleanly:
            // Downlink travels on offset -3.5px, Uplink travels on offset +3.5px
            const isWan = edge.kind === "wan";
            const baseLaneOffset = isWan
              ? 0
              : particle.direction === "down"
                ? -3.5
                : 3.5;
            const totalLaneOffset =
              baseLaneOffset + particle.lateralOffset * 1.2;

            const s0 = headS;
            const s1 = headS + tailStepSign * trailSpan * 0.33;
            const s2 = headS + tailStepSign * trailSpan * 0.66;
            const s3 = headS + tailStepSign * trailSpan;

            const p0 = evalCurve(g, s0);
            const p1 = evalCurve(g, s1);
            const p2 = evalCurve(g, s2);
            const p3 = evalCurve(g, s3);

            const hX = p0.x + totalLaneOffset * p0.nx;
            const hY = p0.y + totalLaneOffset * p0.ny;
            const t1X = p1.x + totalLaneOffset * p1.nx;
            const t1Y = p1.y + totalLaneOffset * p1.ny;
            const t2X = p2.x + totalLaneOffset * p2.nx;
            const t2Y = p2.y + totalLaneOffset * p2.ny;
            const t3X = p3.x + totalLaneOffset * p3.nx;
            const t3Y = p3.y + totalLaneOffset * p3.ny;

            // 4a. Draw Comet Tail
            const gradient = context.createLinearGradient(t3X, t3Y, hX, hY);
            gradient.addColorStop(0, rgba(color, 0));
            gradient.addColorStop(0.4, rgba(color, totalAlpha * 0.35));
            gradient.addColorStop(1, rgba(color, totalAlpha * 0.9));

            context.beginPath();
            context.moveTo(t3X, t3Y);
            context.lineTo(t2X, t2Y);
            context.lineTo(t1X, t1Y);
            context.lineTo(hX, hY);
            context.strokeStyle = gradient;
            context.lineWidth = particle.size * 1.35;
            context.lineCap = "round";
            context.stroke();

            // 4b. Draw Glowing Pulse Head
            context.save();
            context.shadowColor = color;
            context.shadowBlur = related ? (isIdle ? 6 : 14) : 4;
            context.beginPath();
            context.arc(hX, hY, particle.size + 1.2, 0, Math.PI * 2);
            context.fillStyle = rgba(color, totalAlpha * 0.75);
            context.fill();

            // 4c. Draw Bright Laser Core (White Center)
            context.shadowBlur = 0;
            context.beginPath();
            context.arc(hX, hY, particle.size * 0.65, 0, Math.PI * 2);
            context.fillStyle = rgba("#ffffff", totalAlpha * 0.95);
            context.fill();
            context.restore();
          });
        });
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
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35] dark:opacity-[0.2]"
        style={{
          backgroundImage: "radial-gradient(currentColor 1px, transparent 1px)",
          backgroundSize: "22px 22px",
          color: dark ? "#38bdf8" : "#64748b",
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
        const isHovered = node.id === hovered;
        const isConnectedToHovered =
          hovered !== null &&
          edges.some(
            (e) =>
              (e.from.id === hovered && e.to.id === node.id) ||
              (e.to.id === hovered && e.from.id === node.id),
          );
        const isDimmed =
          hovered !== null && !isHovered && !isConnectedToHovered;
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
            className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 rounded-xl bg-surface/95 px-3 py-2 text-left shadow-sm backdrop-blur transition-all duration-200 hover:shadow-md ${isDimmed ? "opacity-40 scale-[0.98]" : "opacity-100"} ${isHovered ? "ring-2 ring-sky-500 shadow-md shadow-sky-500/25 scale-[1.02]" : ""} ${interactive ? "cursor-pointer" : "cursor-default"} disabled:cursor-default dark:bg-slate-900/90 ${agent ? "w-[190px] max-w-[190px] border-2 border-sky-500/40" : wan ? "min-w-[155px] border border-purple-500/40" : selected ? "min-w-[135px] scale-105 border-2 border-sky-500" : "min-w-[130px] max-w-[190px] border border-border/80 hover:border-sky-500/60"}`}
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
