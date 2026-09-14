import "server-only";

import { cookies } from "next/headers";
import { collectorFetch } from "@/lib/collector";
import {
  openSession,
  SESSION_COOKIE,
  type SessionPayload,
} from "@/lib/session-token";

export async function verifySession(): Promise<SessionPayload | null> {
  const sealed = (await cookies()).get(SESSION_COOKIE)?.value;
  const session = await openSession(sealed);
  if (!session) return null;
  try {
    const response = await collectorFetch("internal/auth/verify", {
      method: "POST",
      headers: { authorization: `Bearer ${session.token}` },
    });
    return response.ok ? session : null;
  } catch {
    return null;
  }
}

export function requestUsesHttps(request: Request) {
  return (
    request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim() ===
      "https" || new URL(request.url).protocol === "https:"
  );
}

export function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const expected = new URL(request.url);
  const forwardedHost =
    request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  const forwardedProto = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim();
  if (forwardedHost) expected.host = forwardedHost;
  if (forwardedProto) expected.protocol = `${forwardedProto}:`;
  return origin === expected.origin;
}
