import { redirect } from "next/navigation";
import { DestinationsDashboard } from "@/components/dashboard/destinations-dashboard";
import { verifySession } from "@/lib/auth";

function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function DestinationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const query = await searchParams;
  const page = Number(valueOf(query.page));
  const rangeParam = valueOf(query.range);
  const range = ["15m", "1h", "24h", "7d", "30d", "custom"].includes(
    rangeParam ?? "",
  )
    ? (rangeParam as import("@/components/data/time-range-picker").TimeRangeValue)
    : "24h";
  const viewParam = valueOf(query.view);
  const view = viewParam === "table" ? "table" : "map";

  return (
    <DestinationsDashboard
      username={session.username}
      initialPage={Number.isInteger(page) && page > 0 ? page : 1}
      initialSelectedIp={valueOf(query.ip)}
      initialRange={range}
      initialFrom={valueOf(query.from)}
      initialTo={valueOf(query.to)}
      initialView={view}
    />
  );
}
