import {
  Activity,
  ArrowLeftRight,
  FileUp,
  Globe,
  Lock,
  Mail,
  MailOpen,
  Network,
  Radio,
  Route,
  Search,
  Send,
  Shield,
  ShieldCheck,
  Shuffle,
  Terminal,
  Zap,
} from "lucide-react";

export function protocolIcon(protocol: string) {
  const key = protocol.toLowerCase().replaceAll("_", "-");
  if (key === "tcp") return ArrowLeftRight;
  if (key === "udp") return Send;
  if (key === "icmp") return Activity;
  if (key === "http") return Globe;
  if (key === "https" || key === "tls" || key === "dot") return Lock;
  if (key === "quic") return Zap;
  if (key === "dns") return Search;
  if (key === "doh") return Shield;
  if (key === "ssh") return Terminal;
  if (key === "ftp") return FileUp;
  if (key === "smtp") return Mail;
  if (key === "imap") return MailOpen;
  if (key === "mqtt") return Radio;
  if (key === "gre") return Route;
  if (key === "ipsec" || key === "ipsec-esp") return ShieldCheck;
  if (key === "wireguard" || key === "openvpn") return Shield;
  if (key === "bittorrent") return Shuffle;
  return Network;
}
