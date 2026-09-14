"use client";

import { useTranslations } from "next-intl";

type ValueGroup =
  | "mode"
  | "role"
  | "nat"
  | "backend"
  | "order"
  | "coverage"
  | "status"
  | "scope"
  | "path";

const WARNING_KEYS: Record<
  string,
  | "warnings.icmpRedirect"
  | "warnings.ipv6Unavailable"
  | "warnings.flowOffload"
  | "warnings.asymmetricRouting"
> = {
  "Clients may bypass this agent through ICMP redirects.":
    "warnings.icmpRedirect",
  "IPv6 Internet coverage is unavailable (no IPv6 default route).":
    "warnings.ipv6Unavailable",
  "Flow offloading is enabled and may bypass eBPF/TC traffic visibility.":
    "warnings.flowOffload",
  "Asymmetric routing suspected: reply packet coverage is below 5%.":
    "warnings.asymmetricRouting",
};

function valueKey(value: string) {
  return value.trim().toLowerCase().replaceAll(" ", "-");
}

export function useTopologyLabels() {
  const t = useTranslations("topologyValues");

  return {
    value(group: ValueGroup, value: string | null | undefined) {
      if (!value) return value;
      if (group === "order") {
        const netlinkOrder = /^priority (\d+) \/ handle (.+)$/i.exec(value);
        if (netlinkOrder)
          return t("order.netlink", {
            priority: netlinkOrder[1],
            handle: netlinkOrder[2],
          });
      }
      const key = `${group}.${valueKey(value)}` as Parameters<typeof t>[0];
      return t.has(key) ? t(key) : value;
    },
    warning(value: string) {
      const key = WARNING_KEYS[value];
      return key ? t(key) : value;
    },
  };
}
