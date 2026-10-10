import { formatIdentifier } from "@/lib/formatters";

export const PROTOCOL_APPLICATION_PREFIX = "protocol:";

const PROTOCOL_LABELS: Record<string, string> = {
  bittorrent: "BitTorrent",
  dhcp: "DHCP",
  dns: "DNS",
  doh: "DoH",
  dot: "DoT",
  ftp: "FTP",
  gre: "GRE",
  http: "HTTP",
  https: "HTTPS",
  icmp: "ICMP",
  imap: "IMAP",
  ipsec: "IPsec",
  mqtt: "MQTT",
  ntp: "NTP",
  quic: "QUIC",
  smtp: "SMTP",
  ssh: "SSH",
  tcp: "TCP",
  tls: "TLS",
  udp: "UDP",
};

export function protocolFromApplicationId(id: string): string | null {
  if (!id.startsWith(PROTOCOL_APPLICATION_PREFIX)) return null;
  const protocol = id.slice(PROTOCOL_APPLICATION_PREFIX.length);
  return protocol || null;
}

export function protocolApplicationName(id: string): string | null {
  const protocol = protocolFromApplicationId(id);
  if (!protocol) return null;
  return protocolDisplayName(protocol);
}

export function protocolDisplayName(protocol: string): string {
  const normalized = protocol.toLowerCase();
  return Object.prototype.hasOwnProperty.call(PROTOCOL_LABELS, normalized)
    ? PROTOCOL_LABELS[normalized]
    : formatIdentifier(protocol);
}
