import { redirect } from "next/navigation";
import { ApplicationDetailDashboard } from "@/components/dashboard/application-detail-dashboard";
import { verifySession } from "@/lib/auth";

const TABS = new Set([
  "overview",
  "clients",
  "domains",
  "destinations",
  "flows",
]);

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
  const query = await searchParams;
  const rawTab = Array.isArray(query.tab) ? query.tab[0] : query.tab;
  const rawCategory = Array.isArray(query.category)
    ? query.category[0]
    : query.category;
  const tab = rawTab && TABS.has(rawTab) ? rawTab : "overview";
  return (
    <ApplicationDetailDashboard
      username={session.username}
      applicationId={id}
      categoryId={rawCategory}
      initialTab={
        tab as "overview" | "clients" | "domains" | "destinations" | "flows"
      }
    />
  );
}
