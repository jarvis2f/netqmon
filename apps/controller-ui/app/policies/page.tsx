import { redirect } from "next/navigation";
import { PoliciesDashboard } from "@/components/dashboard/policies-dashboard";
import { verifySession } from "@/lib/auth";

export default async function PoliciesPage() {
  const session = await verifySession();
  if (!session) redirect("/login");
  return <PoliciesDashboard username={session.username} />;
}
