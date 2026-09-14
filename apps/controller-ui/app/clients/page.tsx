import { redirect } from "next/navigation";
import { ClientsDashboard } from "@/components/dashboard/clients-dashboard";
import { verifySession } from "@/lib/auth";

function valueOf(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ClientsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const session = await verifySession();
  if (!session) redirect("/login");
  const query = await searchParams;
  const id = Number(valueOf(query.id));
  return (
    <ClientsDashboard
      username={session.username}
      initialSearch={valueOf(query.search) ?? ""}
      initialSelectedId={Number.isInteger(id) && id > 0 ? id : undefined}
    />
  );
}
