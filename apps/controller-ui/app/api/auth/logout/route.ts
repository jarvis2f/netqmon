import { cookies } from "next/headers";
import { sameOrigin } from "@/lib/auth";
import { collectorFetch } from "@/lib/collector";
import { openSession, SESSION_COOKIE } from "@/lib/session-token";

export async function POST(request: Request) {
  if (!sameOrigin(request))
    return Response.json({ error: "invalid origin" }, { status: 403 });
  const cookieStore = await cookies();
  const session = await openSession(cookieStore.get(SESSION_COOKIE)?.value);
  if (session) {
    try {
      await collectorFetch("internal/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${session.token}` },
      });
    } catch {
      // The local cookie must still be invalidated when Collector is restarting.
    }
  }
  cookieStore.delete(SESSION_COOKIE);
  return new Response(null, { status: 204 });
}
