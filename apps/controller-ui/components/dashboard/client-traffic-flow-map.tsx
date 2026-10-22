"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

class SwarmParticle {
  t: number;
  lateralRatio: number;
  radius: number;
  colorType: "aqua" | "purple" | "white";
  alpha: number;
  speedMult: number;
  direction: "down" | "up";
  edge: Edge;

  constructor(edge: Edge, direction: "down" | "up", initialT?: number) {
    this.edge = edge;
    this.direction = direction;
    this.t = initialT ?? Math.random();
    // Triangular distribution centered around 0 to naturally cluster near the middle of the river
    this.lateralRatio = (Math.random() + Math.random() - 1) * 0.95;
    this.radius = 0.75 + Math.random() * 0.55; // 0.75px to 1.3px
    this.speedMult = 0.85 + Math.random() * 0.3; // natural speed variation
    this.alpha = 0.5 + Math.random() * 0.45; // twinkling opacity

    const rand = Math.random();
    if (direction === "down") {
      this.colorType = rand < 0.62 ? "aqua" : rand < 0.92 ? "purple" : "white";
    } else {
      this.colorType = rand < 0.62 ? "purple" : rand < 0.92 ? "aqua" : "white";
    }
  }

  update(dt: number, baseSpeed: number) {
    this.t = (this.t + dt * baseSpeed * this.speedMult) % 1;
  }
}

function computeStreamWidth(trafficBps: number, isWan: boolean): number {
  if (trafficBps <= 50) return 0;
  if (trafficBps < 5_000) return 9; // like 864 bps in UniFi console
  if (trafficBps < 50_000) return 12;
  if (trafficBps < 500_000) return 15;
  if (trafficBps < 10_000_000) return 18;
  return isWan ? 24 : 21;
}

function computeSwarmCount(trafficBps: number, isWan: boolean): number {
  if (trafficBps <= 50) return 0;
  if (trafficBps < 5_000) return 22;
  if (trafficBps < 50_000) return 34;
  if (trafficBps < 500_000) return 46;
  if (trafficBps < 10_000_000) return 64;
  return isWan ? 90 : 76;
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
  portOffsetX = 0,
): EdgeGeometry {
  const deltaY = Math.max(10, (edge.to.y - edge.from.y) * height);
  const cardHalfHeight = Math.min(38, deltaY * 0.35);

  const p0x = edge.from.x * width + portOffsetX;
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
  const particlePool = useRef<Map<string, SwarmParticle[]>>(new Map());
  const [smoothRates, setSmoothRates] = useState<
    Record<string, { down: number; up: number }>
  >({});
  const smoothRatesRef = useRef<Record<string, { down: number; up: number }>>(
    {},
  );
  const lastUiUpdateRef = useRef<number>(0);
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

  const outgoingMap = useMemo(() => {
    const map = new Map<string, Edge[]>();
    edges.forEach((edge) => {
      const list = map.get(edge.from.id) ?? [];
      list.push(edge);
      map.set(edge.from.id, list);
    });
    map.forEach((list) => {
      list.sort((a, b) => a.to.x - b.to.x);
    });
    return map;
  }, [edges]);

  const getPortOffset = useCallback(
    (edge: Edge) => {
      const siblings = outgoingMap.get(edge.from.id);
      if (!siblings || siblings.length <= 1) return 0;
      const idx = siblings.indexOf(edge);
      if (idx === -1) return 0;
      const count = siblings.length;
      const maxSpan = Math.min(110, (count - 1) * 22);
      return -maxSpan / 2 + (idx / (count - 1)) * maxSpan;
    },
    [outgoingMap],
  );

  useEffect(() => {
    const next = new Map<string, SwarmParticle[]>();
    edges.forEach((edge) => {
      const key = `${edge.from.id}->${edge.to.id}`;
      const old = particlePool.current.get(key) ?? [];
      old.forEach((p) => {
        p.edge = edge;
      });
      const isWan = edge.kind === "wan";
      const downCount = computeSwarmCount(edge.down, isWan);
      const upCount = computeSwarmCount(edge.up, isWan);
      const down = old
        .filter((p) => p.direction === "down")
        .slice(0, downCount);
      const up = old.filter((p) => p.direction === "up").slice(0, upCount);

      while (down.length < downCount) {
        down.push(new SwarmParticle(edge, "down"));
      }
      while (up.length < upCount) {
        up.push(new SwarmParticle(edge, "up"));
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

        // Smoothly interpolate rates for nodes
        nodes.forEach((node) => {
          const targetDown = node.down;
          const targetUp = node.up;
          const current = smoothRatesRef.current[node.id] ?? {
            down: targetDown,
            up: targetUp,
          };
          const factor = 1 - Math.exp(-dt * 0.007);
          const newDown =
            Math.abs(targetDown - current.down) < 50
              ? targetDown
              : current.down + (targetDown - current.down) * factor;
          const newUp =
            Math.abs(targetUp - current.up) < 50
              ? targetUp
              : current.up + (targetUp - current.up) * factor;
          smoothRatesRef.current[node.id] = { down: newDown, up: newUp };
        });

        if (now - lastUiUpdateRef.current > 50) {
          lastUiUpdateRef.current = now;
          setSmoothRates({ ...smoothRatesRef.current });
        }

        const geometries = new Map<Edge, EdgeGeometry>();
        edges.forEach((edge) => {
          geometries.set(
            edge,
            getEdgeGeometry(edge, size.width, size.height, getPortOffset(edge)),
          );
        });

        // 1. Sleek Cable Tracks & UniFi Translucent River Conduits
        edges.forEach((edge) => {
          const g = geometries.get(edge)!;
          const related =
            !hovered || edge.from.id === hovered || edge.to.id === hovered;
          const smoothedNodeRates = smoothRatesRef.current[edge.to.id];
          const totalTraffic =
            (smoothedNodeRates?.down ?? edge.down) +
            (smoothedNodeRates?.up ?? edge.up);
          const isWan = edge.kind === "wan";
          const streamWidth = computeStreamWidth(totalTraffic, isWan);
          const hasTraffic = streamWidth > 0;

          // 1a. Base center guide wire (crisp 1.5px, subtle slate)
          context.beginPath();
          context.moveTo(g.p0x, g.p0y);
          context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
          context.lineCap = "round";
          context.strokeStyle = dark
            ? related
              ? hasTraffic
                ? "rgba(148, 163, 184, 0.22)"
                : "rgba(148, 163, 184, 0.12)"
              : "rgba(148, 163, 184, 0.05)"
            : related
              ? hasTraffic
                ? "rgba(100, 116, 139, 0.24)"
                : "rgba(100, 116, 139, 0.15)"
              : "rgba(100, 116, 139, 0.06)";
          context.lineWidth = 1.5;
          context.stroke();

          // 1b. Translucent river corridor (UniFi fluid bed) when active
          if (hasTraffic && related) {
            // Outer soft river conduit
            context.beginPath();
            context.moveTo(g.p0x, g.p0y);
            context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
            context.lineCap = "round";
            context.strokeStyle = dark
              ? "rgba(56, 189, 248, 0.11)"
              : "rgba(2, 132, 199, 0.08)";
            context.lineWidth = streamWidth + 4;
            context.stroke();

            // Inner river corridor
            context.beginPath();
            context.moveTo(g.p0x, g.p0y);
            context.bezierCurveTo(g.p1x, g.p1y, g.p2x, g.p2y, g.p3x, g.p3y);
            context.lineCap = "round";
            context.strokeStyle = dark
              ? "rgba(56, 189, 248, 0.08)"
              : "rgba(2, 132, 199, 0.05)";
            context.lineWidth = streamWidth * 0.6;
            context.stroke();
          }
        });

        // 2. Hardware Connection Ports (Crisp terminal pins)
        edges.forEach((edge) => {
          const g = geometries.get(edge)!;
          const related =
            !hovered || edge.from.id === hovered || edge.to.id === hovered;
          const smoothedNodeRates = smoothRatesRef.current[edge.to.id];
          const totalTraffic =
            (smoothedNodeRates?.down ?? edge.down) +
            (smoothedNodeRates?.up ?? edge.up);
          const hasTraffic = totalTraffic > 50;
          const isWan = edge.kind === "wan";
          const activeColor = isWan ? palette.wan : palette.route;

          const pinAlpha = related ? (hasTraffic ? 0.9 : 0.35) : 0.12;
          const pinColor = hasTraffic
            ? activeColor
            : dark
              ? "#64748b"
              : "#94a3b8";

          // Top pin
          context.beginPath();
          context.arc(g.p0x, g.p0y, 2.5, 0, Math.PI * 2);
          context.fillStyle = rgba(pinColor, pinAlpha);
          context.fill();

          // Bottom pin
          context.beginPath();
          context.arc(g.p3x, g.p3y, 2.5, 0, Math.PI * 2);
          context.fillStyle = rgba(pinColor, pinAlpha);
          context.fill();

          if (hasTraffic && related) {
            context.beginPath();
            context.arc(g.p0x, g.p0y, 5, 0, Math.PI * 2);
            context.fillStyle = rgba(pinColor, 0.18);
            context.fill();

            context.beginPath();
            context.arc(g.p3x, g.p3y, 5, 0, Math.PI * 2);
            context.fillStyle = rgba(pinColor, 0.18);
            context.fill();
          }
        });

        // 3. UniFi Stardust Particle Swarm (Dense Micro-Particles)
        const aquaDots: { x: number; y: number; r: number; a: number }[] = [];
        const purpleDots: { x: number; y: number; r: number; a: number }[] = [];
        const whiteDots: { x: number; y: number; r: number; a: number }[] = [];

        particlePool.current.forEach((particles) => {
          particles.forEach((p) => {
            const edge = p.edge;
            const g = geometries.get(edge);
            if (!g) return;

            const related =
              !hovered || edge.from.id === hovered || edge.to.id === hovered;
            const smoothedNodeRates = smoothRatesRef.current[edge.to.id];
            const traffic =
              p.direction === "down"
                ? (smoothedNodeRates?.down ?? edge.down)
                : (smoothedNodeRates?.up ?? edge.up);

            if (traffic <= 50) return;

            const isWan = edge.kind === "wan";
            const streamWidth = computeStreamWidth(traffic, isWan);
            if (streamWidth <= 0) return;

            // Speed formula: steady, smooth, natural drift
            const baseSpeed =
              0.00012 +
              Math.min(1, Math.log10(Math.max(1, traffic / 3000)) / 6) *
                0.00016;

            if (!paused) p.update(dt, baseSpeed);

            // Compute curve parameter s along the path
            const s = p.direction === "down" ? p.t : 1 - p.t;

            // Smooth fade in near source port, fade out near destination port
            const edgeFade = Math.min(
              1,
              Math.min(p.t / 0.08, (1 - p.t) / 0.08),
            );
            const totalAlpha = p.alpha * edgeFade * (related ? 1.0 : 0.15);
            if (totalAlpha <= 0.02) return;

            // Point along the curve + lateral stardust offset
            const evalPt = evalCurve(g, s);
            const offset = p.lateralRatio * (streamWidth / 2);
            const px = evalPt.x + offset * evalPt.nx;
            const py = evalPt.y + offset * evalPt.ny;

            if (p.colorType === "aqua") {
              aquaDots.push({ x: px, y: py, r: p.radius, a: totalAlpha });
            } else if (p.colorType === "purple") {
              purpleDots.push({ x: px, y: py, r: p.radius, a: totalAlpha });
            } else {
              whiteDots.push({
                x: px,
                y: py,
                r: p.radius * 0.9,
                a: totalAlpha,
              });
            }
          });
        });

        // Batch render all aqua stardust
        if (aquaDots.length > 0) {
          context.fillStyle = dark ? "#38bdf8" : "#0284c7";
          aquaDots.forEach((pt) => {
            context.globalAlpha = pt.a;
            context.beginPath();
            context.arc(pt.x, pt.y, pt.r, 0, Math.PI * 2);
            context.fill();
          });
        }

        // Batch render all purple stardust
        if (purpleDots.length > 0) {
          context.fillStyle = dark ? "#c084fc" : "#7c3aed";
          purpleDots.forEach((pt) => {
            context.globalAlpha = pt.a;
            context.beginPath();
            context.arc(pt.x, pt.y, pt.r, 0, Math.PI * 2);
            context.fill();
          });
        }

        // Batch render all white sparkle stardust
        if (whiteDots.length > 0) {
          context.fillStyle = "#ffffff";
          whiteDots.forEach((pt) => {
            context.globalAlpha = pt.a;
            context.beginPath();
            context.arc(pt.x, pt.y, pt.r, 0, Math.PI * 2);
            context.fill();
          });
        }

        context.globalAlpha = 1.0;
      }
      frame = requestAnimationFrame(render);
    };
    frame = requestAnimationFrame(render);
    return () => {
      alive = false;
      cancelAnimationFrame(frame);
    };
  }, [dark, edges, getPortOffset, hovered, nodes, paused, size]);

  const back = () => setCategory(null);
  return (
    <section
      ref={containerRef}
      style={{ height }}
      className="relative w-full overflow-hidden rounded-xl border border-border bg-surface-subtle/80 text-foreground shadow-sm dark:bg-[#07101d]"
    >
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
        const displayRates = smoothRates[node.id] ?? {
          down: node.down,
          up: node.up,
        };
        const displayDown = Math.round(displayRates.down);
        const displayUp = Math.round(displayRates.up);

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
            className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 w-[176px] h-[76px] rounded-xl bg-surface/95 px-3 py-2 text-left shadow-sm backdrop-blur transition-all duration-200 hover:shadow-md ${isDimmed ? "opacity-40 scale-[0.98]" : "opacity-100"} ${isHovered ? "ring-2 ring-sky-500 shadow-md shadow-sky-500/25 scale-[1.02]" : ""} ${interactive ? "cursor-pointer" : "cursor-default"} disabled:cursor-default dark:bg-slate-900/90 ${agent ? "border-2 border-sky-500/50" : wan ? "border border-purple-500/40" : selected ? "scale-105 border-2 border-sky-500" : "border border-border/80 hover:border-sky-500/60"}`}
          >
            <div className="flex items-center gap-2.5">
              <span
                className={`flex size-8 shrink-0 items-center justify-center rounded-lg border ${wan ? "border-purple-200 bg-purple-100 text-purple-700 dark:bg-purple-950/80 dark:text-purple-300" : agent ? "border-sky-200 bg-sky-100 text-sky-700 dark:bg-sky-950/80 dark:text-sky-300" : "border-cyan-200 bg-cyan-100 text-cyan-700 dark:bg-cyan-950/80 dark:text-cyan-300"}`}
              >
                {icon}
              </span>
              <span className="min-w-0 flex-1">
                <b className="block truncate text-xs font-semibold leading-tight">
                  {node.name}
                </b>
                <span
                  className="block truncate text-[10px] text-foreground-muted leading-tight mt-0.5"
                  title={node.meta}
                >
                  {node.meta}
                </span>
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between border-t border-border/70 pt-1.5 font-mono text-[10px] tabular-nums">
              <span className="flex items-center gap-1 text-sky-600 dark:text-sky-400 min-w-0 flex-1">
                <ArrowDown className="size-3 shrink-0" />
                <span className="truncate">{formatBitrate(displayDown)}</span>
              </span>
              <span className="flex items-center justify-end gap-1 text-emerald-600 dark:text-emerald-400 min-w-0 flex-1">
                <ArrowUp className="size-3 shrink-0" />
                <span className="truncate">{formatBitrate(displayUp)}</span>
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
          [
            t("totalDown"),
            formatBitrate(
              Math.round(smoothRates["internet"]?.down ?? totals.down),
            ),
            "text-sky-600 dark:text-sky-400",
          ],
          [
            t("totalUp"),
            formatBitrate(Math.round(smoothRates["internet"]?.up ?? totals.up)),
            "text-emerald-600 dark:text-emerald-400",
          ],
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
