import { redirect } from "next/navigation";
import { ApplicationDetailDashboard } from "@/components/dashboard/application-detail-dashboard";
import type { TimeRangeValue } from "@/components/data/time-range-picker";
import { verifySession } from "@/lib/auth";

const TABS = new Set([
  "overview",
  "clients",
  "domains",
  "destinations",
  "flows",
]);
const RANGES = new Set(["1h", "24h", "7d", "30d", "custom"]);

function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ApplicationDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const { id } = await params;
  const applicationId = decodeURIComponent(id);
  const query = await searchParams;
  const rawTab = valueOf(query.tab);
  const rawCategory = valueOf(query.category);
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
  const tab = rawTab && TABS.has(rawTab) ? rawTab : "overview";
  return (
    <ApplicationDetailDashboard
      username={session.username}
      applicationId={applicationId}
      categoryId={rawCategory}
      initialRange={
        (validCustomRange
          ? "custom"
          : rangeParam && RANGES.has(rangeParam) && rangeParam !== "custom"
            ? rangeParam
            : "24h") as TimeRangeValue
      }
      initialFrom={validCustomRange ? from : undefined}
      initialTo={validCustomRange ? to : undefined}
      initialTab={
        tab as "overview" | "clients" | "domains" | "destinations" | "flows"
      }
    />
  );
}
