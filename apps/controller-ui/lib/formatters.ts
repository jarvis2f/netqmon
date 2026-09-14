/**
 * netqmon standard formatting utilities
 * Compliant with docs/UI_DESIGN_SPEC.md Section 58 & 59
 */

/**
 * Format raw bytes into human-readable binary units (B, KB, MB, GB, TB, PB)
 */
export function formatBytes(bytes: number, decimals = 1): string {
  if (isNaN(bytes) || bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];

  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  const clampedIndex = Math.min(i, sizes.length - 1);

  if (clampedIndex === 0) {
    return `${Math.round(bytes)} B`;
  }

  const value = bytes / Math.pow(k, clampedIndex);
  return `${value.toFixed(dm)} ${sizes[clampedIndex]}`;
}

/**
 * Format bandwidth in bits per second (bps, Kbps, Mbps, Gbps, Tbps)
 */
export function formatBitrate(bps: number, decimals = 1): string {
  if (isNaN(bps) || bps === null || bps === undefined) return "—";
  if (bps === 0) return "0 bps";

  const k = 1000;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];

  const i = Math.floor(Math.log(Math.abs(bps)) / Math.log(k));
  const clampedIndex = Math.min(i, sizes.length - 1);

  if (clampedIndex === 0) {
    return `${Math.round(bps)} bps`;
  }

  const value = bps / Math.pow(k, clampedIndex);
  return `${value.toFixed(dm)} ${sizes[clampedIndex]}`;
}

/**
 * Separate value and unit for bitrate formatting (useful for MetricCard with small unit)
 */
export function splitBitrate(
  bps: number,
  decimals = 1,
): { value: string; unit: string } {
  if (isNaN(bps) || bps === null || bps === undefined)
    return { value: "—", unit: "" };
  if (bps === 0) return { value: "0", unit: "bps" };

  const k = 1000;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];

  const i = Math.floor(Math.log(Math.abs(bps)) / Math.log(k));
  const clampedIndex = Math.min(i, sizes.length - 1);

  if (clampedIndex === 0) {
    return { value: `${Math.round(bps)}`, unit: "bps" };
  }

  const val = (bps / Math.pow(k, clampedIndex)).toFixed(dm);
  return { value: val, unit: sizes[clampedIndex] };
}

function getCurrentLocale(): string {
  if (typeof document !== "undefined" && document.documentElement.lang) {
    return document.documentElement.lang;
  }
  return "en";
}

/**
 * Format packet count with thousand separators or compact notation
 */
export function formatPackets(
  count: number,
  compact = false,
  locale?: string,
): string {
  if (isNaN(count) || count === null || count === undefined) return "—";
  if (count === 0) return "0";

  if (compact) {
    if (Math.abs(count) >= 1_000_000) {
      return `${(count / 1_000_000).toFixed(1)}M`;
    }
    if (Math.abs(count) >= 1_000) {
      return `${(count / 1_000).toFixed(1)}K`;
    }
  }

  return new Intl.NumberFormat(locale || getCurrentLocale()).format(count);
}

/**
 * Format duration in seconds into human-readable string
 * e.g. "45s", "3m 12s", "2h 15m", "3d 4h"
 */
export function formatDuration(seconds: number): string {
  if (isNaN(seconds) || seconds === null || seconds === undefined) return "—";
  if (seconds < 0) return "0s";
  if (seconds < 60) return `${Math.round(seconds)}s`;

  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);

  if (minutes < 60) {
    return remainingSeconds > 0
      ? `${minutes}m ${remainingSeconds}s`
      : `${minutes}m`;
  }

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  if (hours < 24) {
    return remainingMinutes > 0
      ? `${hours}h ${remainingMinutes}m`
      : `${hours}h`;
  }

  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`;
}

/**
 * Format ratio (0 to 1 or 0 to 100) into a percentage string
 */
export function formatPercent(
  ratio?: number | null,
  decimals = 1,
  isRatio = true,
): string {
  if (ratio === null || ratio === undefined || isNaN(ratio)) return "—";
  const val = isRatio ? ratio * 100 : ratio;
  return `${val.toFixed(decimals)}%`;
}

export function formatIdentifier(identifier: string): string {
  return identifier
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/**
 * Format timestamps into local display strings based on context
 */
export function formatTimestamp(
  timestamp: string | number | Date | null | undefined,
  format: "table" | "date" | "tooltip" | "relative" = "table",
  locale?: string,
): string {
  if (!timestamp) return "—";

  const date =
    typeof timestamp === "object"
      ? timestamp
      : new Date(
          typeof timestamp === "number" && timestamp < 1e12
            ? timestamp * 1000
            : timestamp,
        );

  if (isNaN(date.getTime())) return "—";

  const loc = locale || getCurrentLocale();

  if (format === "relative") {
    const now = Date.now();
    const diffMs = now - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 5) return loc === "zh-CN" ? "刚刚" : "just now";
    if (diffSec < 60)
      return loc === "zh-CN" ? `${diffSec} 秒前` : `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60)
      return loc === "zh-CN" ? `${diffMin} 分钟前` : `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24)
      return loc === "zh-CN" ? `${diffHours} 小时前` : `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 30)
      return loc === "zh-CN" ? `${diffDays} 天前` : `${diffDays}d ago`;
  }

  const pad = (n: number) => n.toString().padStart(2, "0");

  if (format === "table") {
    return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  }

  if (format === "date") {
    return new Intl.DateTimeFormat(loc, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(date);
  }

  if (format === "tooltip") {
    const y = date.getFullYear();
    const m = pad(date.getMonth() + 1);
    const d = pad(date.getDate());
    const hh = pad(date.getHours());
    const mm = pad(date.getMinutes());
    const ss = pad(date.getSeconds());
    const offset = -date.getTimezoneOffset();
    const sign = offset >= 0 ? "+" : "-";
    const offH = pad(Math.floor(Math.abs(offset) / 60));
    const offM = pad(Math.abs(offset) % 60);
    return `${y}-${m}-${d} ${hh}:${mm}:${ss} ${sign}${offH}:${offM}`;
  }

  return date.toLocaleString(loc);
}

/**
 * Generate Cloudflare Radar domain URL
 */
export function cloudflareDomainUrl(domain?: string | null): string {
  const clean = domain ? domain.trim() : "";
  return `https://radar.cloudflare.com/zh-cn/domains/domain/${encodeURIComponent(clean)}`;
}

/**
 * Generate Cloudflare Radar ASN URL
 */
export function cloudflareAsnUrl(asn: number | string): string {
  const cleanAsn = String(asn).replace(/^as/i, "").trim();
  return `https://radar.cloudflare.com/zh-cn/routing/as${cleanAsn}`;
}

/**
 * Checks whether an IP address is a local/private address.
 * Covers IPv4 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 * loopback (127.0.0.0/8), link-local (169.254.0.0/16), CGNAT (100.64.0.0/10),
 * unspecified (0.0.0.0), multicast (224.0.0.0/4), broadcast / reserved (240.0.0.0/4),
 * and IPv6 loopback (::1), link-local (fe80::/10), unique local (fc00::/7),
 * unspecified (::), multicast (ff00::/8), and IPv4-mapped IPv6.
 */
export function isLocalIp(rawIp?: string | null): boolean {
  if (!rawIp) return true;
  let ip = rawIp.trim();
  if (!ip || ip.toLowerCase() === "localhost") return true;

  // Handle bracketed IPv6 with port like [::1]:8080
  if (ip.startsWith("[") && ip.includes("]")) {
    const end = ip.indexOf("]");
    ip = ip.slice(1, end);
  } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(ip)) {
    // IPv4 with port like 192.168.1.1:80
    ip = ip.split(":")[0];
  }

  // Handle IPv4-mapped IPv6, e.g., ::ffff:192.168.1.1
  const ipv4Mapped = ip.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  const targetIp = ipv4Mapped ? ipv4Mapped[1] : ip;

  // IPv4 check
  const v4Parts = targetIp.split(".").map(Number);
  if (
    v4Parts.length === 4 &&
    v4Parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)
  ) {
    const [a, b] = v4Parts;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (Link-local)
    if (a === 169 && b === 254) return true;
    // 100.64.0.0/10 (Carrier Grade NAT: 100.64.0.0 - 100.127.255.255)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 0.0.0.0/8 (Current network / unspecified)
    if (a === 0) return true;
    // Multicast (224.0.0.0/4: 224 - 239)
    if (a >= 224 && a <= 239) return true;
    // Broadcast / Reserved (240.0.0.0/4: 240 - 255)
    if (a >= 240) return true;

    return false;
  }

  // IPv6 check
  const lower = targetIp.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  // Link-local: fe80::/10 (fe80... to febf...)
  if (/^fe[89ab]/i.test(lower)) return true;
  // Unique local: fc00::/7 (fc00... to fdff...)
  if (/^f[cd]/i.test(lower)) return true;
  // Multicast: ff00::/8
  if (/^ff/i.test(lower)) return true;

  return false;
}

/**
 * Generate ipinfo.io URL
 */
export function ipInfoUrl(ip?: string | null): string {
  const clean = ip ? ip.trim() : "";
  return `https://ipinfo.io/${encodeURIComponent(clean)}`;
}
