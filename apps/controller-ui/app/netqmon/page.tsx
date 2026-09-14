import { redirect } from "next/navigation";
import { verifySession } from "@/lib/auth";
import { OverviewDashboard } from "@/components/dashboard/overview-dashboard";

export default async function NetqmonPage() {
  const session = await verifySession();
  if (!session) redirect("/login");

  return <OverviewDashboard username={session.username} />;
}
