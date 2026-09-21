import { redirect } from "next/navigation";
import { SettingsDashboard } from "@/components/dashboard/settings-dashboard";
import { verifySession } from "@/lib/auth";
import { isDemoMode } from "@/lib/runtime-mode";

export default async function SettingsPage() {
  if (isDemoMode()) redirect("/netqmon");
  const session = await verifySession();
  if (!session) redirect("/login");
  return <SettingsDashboard username={session.username} />;
}
