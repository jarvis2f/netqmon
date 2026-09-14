"use client";

import { useId, useMemo } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Globe, HardDrive, Laptop, Smartphone } from "lucide-react";
import { NetqmonLogo } from "@/components/brand/logo";

interface NetworkTrafficIllustrationProps {
  className?: string;
}

export function NetworkTrafficIllustration({
  className,
}: NetworkTrafficIllustrationProps) {
  const prefersReducedMotion = useReducedMotion();
  const idPrefix = useId();

  // Packet animation variants for WAN -> Gateway -> Clients
  const packetDurations = useMemo(() => [2.4, 3.1, 2.7, 3.6, 2.2], []);

  return (
    <div
      className={`relative flex w-full flex-col items-center justify-center overflow-hidden rounded-2xl border border-blue-500/20 bg-slate-950/60 p-4 shadow-xl shadow-blue-950/40 backdrop-blur-xl ${className ?? ""}`}
    >
      {/* Ambient background glows */}
      <div className="pointer-events-none absolute -top-16 -left-16 h-56 w-56 rounded-full bg-blue-500/15 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-16 -right-16 h-56 w-56 rounded-full bg-cyan-500/15 blur-3xl" />
      <div className="pointer-events-none absolute top-1/2 left-1/2 h-44 w-44 -translate-x-1/2 -translate-y-1/2 rounded-full bg-emerald-500/10 blur-2xl" />

      {/* Top Telemetry Header Pill */}
      <div className="relative z-10 mb-2.5 flex w-full items-center justify-between border-b border-white/5 pb-2 font-mono text-[11px]">
        <div className="flex items-center gap-2 text-slate-300">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span className="text-xs font-semibold tracking-wider text-slate-200 uppercase">
            eBPF TELEMETRY
          </span>
          <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300">
            LIVE
          </span>
        </div>
        <div className="flex items-center gap-3 text-slate-400">
          <span>
            RTT: <strong className="text-emerald-400">1.8 ms</strong>
          </span>
          <span className="hidden sm:inline text-slate-600">|</span>
          <span className="hidden sm:inline">
            LOSS: <strong className="text-emerald-400">0.00%</strong>
          </span>
        </div>
      </div>

      {/* Main SVG Network Map */}
      <div className="relative z-10 w-full aspect-[520/240] max-w-[480px] mx-auto">
        <svg
          viewBox="0 0 520 240"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="h-full w-full select-none"
        >
          <defs>
            {/* Gradients for conduits */}
            <linearGradient
              id={`${idPrefix}-wan-gw`}
              x1="75"
              y1="105"
              x2="260"
              y2="105"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#2563eb" stopOpacity="0.8" />
            </linearGradient>

            <linearGradient
              id={`${idPrefix}-gw-c1`}
              x1="260"
              y1="105"
              x2="395"
              y2="42"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#2563eb" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.8" />
            </linearGradient>

            <linearGradient
              id={`${idPrefix}-gw-c2`}
              x1="260"
              y1="105"
              x2="405"
              y2="105"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#2563eb" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.8" />
            </linearGradient>

            <linearGradient
              id={`${idPrefix}-gw-c3`}
              x1="260"
              y1="105"
              x2="395"
              y2="168"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#2563eb" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.8" />
            </linearGradient>

            {/* Wave gradient */}
            <linearGradient
              id={`${idPrefix}-wave-grad`}
              x1="0"
              y1="190"
              x2="0"
              y2="235"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Conduit Guide Paths */}
          {/* Path 1: WAN to Gateway */}
          <path
            id={`${idPrefix}-path-wan`}
            d="M 75 105 L 260 105"
            stroke={`url(#${idPrefix}-wan-gw)`}
            strokeWidth="2"
            strokeDasharray="4 4"
            className="opacity-40"
          />

          {/* Path 2: Gateway to Client 1 (PC) */}
          <path
            id={`${idPrefix}-path-c1`}
            d="M 260 105 C 320 105, 345 42, 395 42"
            stroke={`url(#${idPrefix}-gw-c1)`}
            strokeWidth="1.75"
            strokeDasharray="4 4"
            className="opacity-40"
          />

          {/* Path 3: Gateway to Client 2 (Server/NAS) */}
          <path
            id={`${idPrefix}-path-c2`}
            d="M 260 105 L 405 105"
            stroke={`url(#${idPrefix}-gw-c2)`}
            strokeWidth="1.75"
            strokeDasharray="4 4"
            className="opacity-40"
          />

          {/* Path 4: Gateway to Client 3 (Mobile) */}
          <path
            id={`${idPrefix}-path-c3`}
            d="M 260 105 C 320 105, 345 168, 395 168"
            stroke={`url(#${idPrefix}-gw-c3)`}
            strokeWidth="1.75"
            strokeDasharray="4 4"
            className="opacity-40"
          />

          {/* Animated Flow Packets (Moving along paths) */}
          {!prefersReducedMotion && (
            <>
              {/* Downstream WAN -> GW packet */}
              <circle
                r="3.5"
                fill="#38bdf8"
                filter="drop-shadow(0 0 6px #38bdf8)"
              >
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[0]}s`}
                  path="M 75 105 L 260 105"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>
              <circle r="2" fill="#ffffff">
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[0]}s`}
                  path="M 75 105 L 260 105"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>

              {/* Upstream GW -> WAN packet */}
              <circle
                r="3"
                fill="#34d399"
                filter="drop-shadow(0 0 6px #34d399)"
              >
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[1]}s`}
                  path="M 260 105 L 75 105"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>

              {/* GW -> Client 1 packet */}
              <circle
                r="3"
                fill="#38bdf8"
                filter="drop-shadow(0 0 5px #38bdf8)"
              >
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[2]}s`}
                  path="M 260 105 C 320 105, 345 42, 395 42"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>

              {/* Client 2 -> GW packet */}
              <circle
                r="3"
                fill="#10b981"
                filter="drop-shadow(0 0 5px #10b981)"
              >
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[3]}s`}
                  path="M 405 105 L 260 105"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>

              {/* GW -> Client 3 packet */}
              <circle
                r="3"
                fill="#06b6d4"
                filter="drop-shadow(0 0 5px #06b6d4)"
              >
                <animateMotion
                  repeatCount="indefinite"
                  dur={`${packetDurations[4]}s`}
                  path="M 260 105 C 320 105, 345 168, 395 168"
                  keyPoints="0;1"
                  keyTimes="0;1"
                />
              </circle>
            </>
          )}

          {/* Gateway Pulse Wave (Center Node) */}
          <circle
            cx="260"
            cy="105"
            r="30"
            stroke="#3b82f6"
            strokeWidth="1"
            strokeOpacity="0.25"
          />
          {!prefersReducedMotion && (
            <>
              <motion.circle
                cx="260"
                cy="105"
                r="36"
                stroke="#60a5fa"
                strokeWidth="1.5"
                initial={{ r: 22, opacity: 0.8 }}
                animate={{ r: [22, 44], opacity: [0.8, 0] }}
                transition={{
                  duration: 2.2,
                  repeat: Infinity,
                  ease: "easeOut",
                }}
              />
              <motion.circle
                cx="260"
                cy="105"
                r="36"
                stroke="#34d399"
                strokeWidth="1"
                initial={{ r: 22, opacity: 0.8 }}
                animate={{ r: [22, 44], opacity: [0.8, 0] }}
                transition={{
                  duration: 2.2,
                  delay: 1.1,
                  repeat: Infinity,
                  ease: "easeOut",
                }}
              />
            </>
          )}

          {/* WAN Node (Left) */}
          <g transform="translate(55, 85)">
            <circle
              cx="20"
              cy="20"
              r="20"
              fill="#0f172a"
              stroke="#38bdf8"
              strokeWidth="1.5"
              strokeOpacity="0.6"
            />
            <foreignObject x="5" y="5" width="30" height="30">
              <div className="flex h-full w-full items-center justify-center text-sky-400">
                <Globe className="h-4 w-4" />
              </div>
            </foreignObject>
            <text
              x="20"
              y="54"
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="10"
              fontFamily="monospace"
            >
              WAN
            </text>
          </g>

          {/* Gateway Core Node (Center) */}
          <g transform="translate(238, 83)">
            <circle
              cx="22"
              cy="22"
              r="22"
              fill="#020617"
              stroke="#3b82f6"
              strokeWidth="2"
              filter="drop-shadow(0 0 12px rgba(59,130,246,0.4))"
            />
            <foreignObject x="6" y="6" width="32" height="32">
              <div className="flex h-full w-full items-center justify-center">
                <NetqmonLogo size={22} />
              </div>
            </foreignObject>
            <text
              x="22"
              y="58"
              textAnchor="middle"
              fill="#e2e8f0"
              fontSize="10"
              fontWeight="600"
              fontFamily="monospace"
            >
              ROUTER
            </text>
          </g>

          {/* LAN Client 1: Workstation */}
          <g transform="translate(379, 26)">
            <circle
              cx="16"
              cy="16"
              r="16"
              fill="#0f172a"
              stroke="#10b981"
              strokeWidth="1.5"
              strokeOpacity="0.6"
            />
            <foreignObject x="4" y="4" width="24" height="24">
              <div className="flex h-full w-full items-center justify-center text-emerald-400">
                <Laptop className="h-3.5 w-3.5" />
              </div>
            </foreignObject>
            <text
              x="40"
              y="14"
              fill="#cbd5e1"
              fontSize="9.5"
              fontWeight="600"
              fontFamily="monospace"
            >
              PC
            </text>
            <text
              x="40"
              y="26"
              fill="#64748b"
              fontSize="8"
              fontFamily="monospace"
            >
              192.168.1.102
            </text>
          </g>

          {/* LAN Client 2: NAS / Server */}
          <g transform="translate(389, 89)">
            <circle
              cx="16"
              cy="16"
              r="16"
              fill="#0f172a"
              stroke="#38bdf8"
              strokeWidth="1.5"
              strokeOpacity="0.6"
            />
            <foreignObject x="4" y="4" width="24" height="24">
              <div className="flex h-full w-full items-center justify-center text-sky-400">
                <HardDrive className="h-3.5 w-3.5" />
              </div>
            </foreignObject>
            <text
              x="40"
              y="14"
              fill="#cbd5e1"
              fontSize="9.5"
              fontWeight="600"
              fontFamily="monospace"
            >
              NAS
            </text>
            <text
              x="40"
              y="26"
              fill="#64748b"
              fontSize="8"
              fontFamily="monospace"
            >
              192.168.1.200
            </text>
          </g>

          {/* LAN Client 3: Mobile / IoT */}
          <g transform="translate(379, 152)">
            <circle
              cx="16"
              cy="16"
              r="16"
              fill="#0f172a"
              stroke="#06b6d4"
              strokeWidth="1.5"
              strokeOpacity="0.6"
            />
            <foreignObject x="4" y="4" width="24" height="24">
              <div className="flex h-full w-full items-center justify-center text-cyan-400">
                <Smartphone className="h-3.5 w-3.5" />
              </div>
            </foreignObject>
            <text
              x="40"
              y="14"
              fill="#cbd5e1"
              fontSize="9.5"
              fontWeight="600"
              fontFamily="monospace"
            >
              WLAN
            </text>
            <text
              x="40"
              y="26"
              fill="#64748b"
              fontSize="8"
              fontFamily="monospace"
            >
              192.168.1.45
            </text>
          </g>

          {/* Live Waveform Indicator at bottom */}
          <path
            d="M 30 220 Q 70 205 110 216 T 190 210 T 270 222 T 350 208 T 430 216 T 490 212 L 490 235 L 30 235 Z"
            fill={`url(#${idPrefix}-wave-grad)`}
          />
          <path
            d="M 30 220 Q 70 205 110 216 T 190 210 T 270 222 T 350 208 T 430 216 T 490 212"
            stroke="#38bdf8"
            strokeWidth="1.5"
            strokeOpacity="0.7"
            fill="none"
          />
        </svg>
      </div>

      {/* Bottom Live Metrics Strip */}
      <div className="relative z-10 mt-2.5 grid w-full grid-cols-3 gap-2 border-t border-white/5 pt-2 font-mono text-[9.5px]">
        <div className="rounded-lg bg-white/[0.02] p-2 border border-white/5">
          <span className="text-slate-400 block">DOWNSTREAM</span>
          <span className="text-sky-400 font-semibold text-xs tracking-tight">
            842.6 Mbps
          </span>
        </div>
        <div className="rounded-lg bg-white/[0.02] p-2 border border-white/5">
          <span className="text-slate-400 block">UPSTREAM</span>
          <span className="text-emerald-400 font-semibold text-xs tracking-tight">
            118.2 Mbps
          </span>
        </div>
        <div className="rounded-lg bg-white/[0.02] p-2 border border-white/5">
          <span className="text-slate-400 block">ACTIVE FLOWS</span>
          <span className="text-cyan-400 font-semibold text-xs tracking-tight">
            1,429
          </span>
        </div>
      </div>
    </div>
  );
}
