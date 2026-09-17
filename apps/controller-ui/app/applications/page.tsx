import { redirect } from "next/navigation";
import { ApplicationsDashboard } from "@/components/dashboard/applications-dashboard";
import { verifySession } from "@/lib/auth";

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
  return (
    <ApplicationsDashboard
      username={session.username}
      initialSearch={valueOf(query.search) ?? ""}
    />
  );
}
