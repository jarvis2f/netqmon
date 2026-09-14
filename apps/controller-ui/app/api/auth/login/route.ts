import { cookies } from "next/headers";
import { sameOrigin, requestUsesHttps } from "@/lib/auth";
import { collectorFetch, upstreamUnavailable } from "@/lib/collector";
import { sealSession, SESSION_COOKIE } from "@/lib/session-token";

export async function POST(request: Request) {
  if (!sameOrigin(request))
    return Response.json({ error: "invalid origin" }, { status: 403 });
  try {
    const response = await collectorFetch("internal/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: await request.text(),
    });
    const payload = await response.json();
    if (!response.ok)
      return Response.json(payload, { status: response.status });
    const session = payload.data;
    const sealed = await sealSession({
      token: session.session_token,
      userId: session.user.id,
      username: session.user.username,
      expiresAt: session.expires_at,
    });
    (await cookies()).set(SESSION_COOKIE, sealed, {
      httpOnly: true,
      sameSite: "lax",
      secure: requestUsesHttps(request),
      path: "/",
      expires: new Date(session.expires_at),
      priority: "high",
    });
    return Response.json({ schema_version: 1, data: { user: session.user } });
  } catch {
    return upstreamUnavailable();
  }
}
