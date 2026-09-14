import { redirect } from "next/navigation";
import { InsightsDashboard } from "@/components/dashboard/insights-dashboard";
import { verifySession } from "@/lib/auth";

export default async function InsightsPage() {
  const session = await verifySession();
  if (!session) redirect("/login");
  return <InsightsDashboard username={session.username} />;
}
