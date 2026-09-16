import { redirect } from "next/navigation";
import { TrafficDashboard } from "@/components/dashboard/traffic-dashboard";
import { verifySession } from "@/lib/auth";
import type { TimeRangeValue } from "@/components/data/time-range-picker";

const RANGES = new Set(["1h", "24h", "7d", "30d", "custom"]);
const DIRECTIONS = new Set(["both", "download", "upload"]);
const SCOPES = new Set(["internet", "internal", "tunnel", "all"]);
const GROUPS = new Set([
  "none",
  "client",
  "application",
  "category",
  "protocol_l7",
  "protocol_l4",
  "protocol",
]);

function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function TrafficPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const query = await searchParams;
  const range = valueOf(query.range);
  const direction = valueOf(query.direction);
  const group = valueOf(query.group);
  const scope = valueOf(query.scope);
  const normalizedGroup =
    group === "protocol"
      ? "protocol_l7"
      : group && GROUPS.has(group)
        ? group
        : "none";

  return (
    <TrafficDashboard
      username={session.username}
      initialRange={
        (range && RANGES.has(range) ? range : "24h") as TimeRangeValue
      }
      initialDirection={
        (direction && DIRECTIONS.has(direction) ? direction : "both") as
          "both" | "download" | "upload"
      }
      initialScope={
        (scope && SCOPES.has(scope) ? scope : "internet") as
          "internet" | "internal" | "tunnel" | "all"
      }
      initialGroupBy={
        normalizedGroup as
          | "none"
          | "client"
          | "application"
          | "category"
          | "protocol_l7"
          | "protocol_l4"
      }
      initialFrom={valueOf(query.from)}
      initialTo={valueOf(query.to)}
    />
  );
}
