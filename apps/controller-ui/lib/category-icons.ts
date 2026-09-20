import {
  ArrowRightLeft,
  BarChart2,
  Bot,
  Briefcase,
  CircleHelp,
  Cloud,
  Code,
  Cpu,
  EyeOff,
  FolderSync,
  Gamepad2,
  Globe,
  GraduationCap,
  Image,
  Landmark,
  Megaphone,
  MessageSquare,
  Newspaper,
  Plane,
  Server,
  Settings,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShoppingBag,
  Skull,
  Tv,
  Users,
  type LucideIcon,
} from "lucide-react";

export const categoryIcons: Record<string, LucideIcon> = {
  finance: Landmark,
  travel: Plane,
  news: Newspaper,
  education: GraduationCap,
  productivity: Briefcase,
  web: Globe,
  streaming: Tv,
  shopping: ShoppingBag,
  cdn: Server,
  iot: Cpu,
  adult: EyeOff,
  social: Users,
  development: Code,
  ai: Bot,
  cloud: Cloud,
  media: Image,
  gaming: Gamepad2,
  p2p: Share2,
  vpn: Shield,
  proxy: ArrowRightLeft,
  encrypted_dns: ShieldCheck,
  file_transfer: FolderSync,
  communication: MessageSquare,
  system: Settings,
  advertising: Megaphone,
  analytics: BarChart2,
  malware: Skull,
  security: ShieldAlert,
  unknown: CircleHelp,
};

export function getCategoryIcon(categoryId?: string | null): LucideIcon {
  if (!categoryId) return CircleHelp;
  const normalized = categoryId
    .toLowerCase()
    .trim()
    .replace(/[-\s]+/g, "_");
  return categoryIcons[normalized] ?? CircleHelp;
}
