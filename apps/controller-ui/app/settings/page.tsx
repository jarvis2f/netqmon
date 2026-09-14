import { redirect } from "next/navigation";
import { SettingsDashboard } from "@/components/dashboard/settings-dashboard";
import { verifySession } from "@/lib/auth";

export default async function SettingsPage() {
  const session = await verifySession();
  if (!session) redirect("/login");
  return <SettingsDashboard username={session.username} />;
}
