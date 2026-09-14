import { notFound, redirect } from "next/navigation";
import { ClientDetailDashboard } from "@/components/dashboard/client-detail-dashboard";
import { verifySession } from "@/lib/auth";

const TABS = new Set([
  "overview",
  "applications",
  "domains",
  "destinations",
  "flows",
]);
export default async function ClientDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const rawId = (await params).id;
  const id = Number(rawId);
  if (!Number.isInteger(id) || id <= 0) notFound();
  const query = await searchParams;
  const rawTab = Array.isArray(query.tab) ? query.tab[0] : query.tab;
  const tab = rawTab && TABS.has(rawTab) ? rawTab : "overview";
  return (
    <ClientDetailDashboard
      username={session.username}
      clientId={id}
      initialTab={
        tab as
          "overview" | "applications" | "domains" | "destinations" | "flows"
      }
    />
  );
}
