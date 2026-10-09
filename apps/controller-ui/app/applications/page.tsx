import { redirect } from "next/navigation";
import { ApplicationsDashboard } from "@/components/dashboard/applications-dashboard";
import type { TimeRangeValue } from "@/components/data/time-range-picker";
import { verifySession } from "@/lib/auth";

const RANGES = new Set(["1h", "24h", "7d", "30d", "custom"]);

function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ApplicationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const query = await searchParams;
  const rangeParam = valueOf(query.range);
  const from = valueOf(query.from);
  const to = valueOf(query.to);
  const customFrom = from ? Date.parse(from) : Number.NaN;
  const customTo = to ? Date.parse(to) : Number.NaN;
  const validCustomRange =
    rangeParam === "custom" &&
    Number.isFinite(customFrom) &&
    Number.isFinite(customTo) &&
    customFrom < customTo;

  return (
    <ApplicationsDashboard
      username={session.username}
      initialSearch={valueOf(query.search) ?? ""}
      initialSelectedId={valueOf(query.id)}
      initialSelectedCategory={valueOf(query.category)}
      initialRange={
        (validCustomRange
          ? "custom"
          : rangeParam &&
              RANGES.has(rangeParam) &&
              (rangeParam !== "custom" || validCustomRange)
            ? rangeParam
            : "24h") as TimeRangeValue
      }
      initialFrom={validCustomRange ? from : undefined}
      initialTo={validCustomRange ? to : undefined}
    />
  );
}
