import { redirect } from "next/navigation";
import { FlowsDashboard } from "@/components/dashboard/flows-dashboard";
import type { TimeRangeValue } from "@/components/data/time-range-picker";
import { verifySession } from "@/lib/auth";

const RANGES = new Set(["1h", "24h", "7d", "30d", "custom"]);
const SORTS = new Set([
  "last_seen",
  "started",
  "download",
  "upload",
  "duration",
]);
const ORDERS = new Set(["asc", "desc"]);
function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function FlowsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const query = await searchParams;
  const range = valueOf(query.range);
  const sort = valueOf(query.sort);
  const order = valueOf(query.order);
  const dataQuery = { ...query };
  delete dataQuery.flow;
  return (
    <FlowsDashboard
      key={JSON.stringify(dataQuery)}
      username={session.username}
      initialRange={
        (range && RANGES.has(range) ? range : "24h") as TimeRangeValue
      }
      initialFrom={valueOf(query.from)}
      initialTo={valueOf(query.to)}
      initialSearch={valueOf(query.search) ?? ""}
      initialClient={valueOf(query.client) ?? ""}
      initialApplication={valueOf(query.application) ?? ""}
      initialDomain={valueOf(query.domain) ?? ""}
      initialIp={valueOf(query.ip) ?? ""}
      initialProtocol={valueOf(query.protocol) ?? ""}
      initialPort={valueOf(query.port) ?? ""}
      initialDirection={valueOf(query.direction) ?? ""}
      initialScope={valueOf(query.scope) ?? ""}
      initialPathType={valueOf(query.path_type) ?? ""}
      initialNat={valueOf(query.nat) ?? ""}
      initialSort={sort && SORTS.has(sort) ? sort : "last_seen"}
      initialOrder={
        (order && ORDERS.has(order) ? order : "desc") as "asc" | "desc"
      }
      initialCursor={valueOf(query.cursor)}
      initialHistory={valueOf(query.history)}
      initialSelectedFlow={valueOf(query.flow)}
    />
  );
}
