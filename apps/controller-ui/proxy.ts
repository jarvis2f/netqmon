import { NextResponse, type NextRequest } from "next/server";
import { openSession, SESSION_COOKIE } from "@/lib/session-token";
import { isDemoMode } from "@/lib/runtime-mode";

const PUBLIC_PATHS = new Set([
  "/setup",
  "/login",
  "/api/auth/status",
  "/api/auth/setup",
  "/api/auth/login",
]);

export async function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const isDemo = isDemoMode();

  if (isDemo) {
    if (path === "/login" || path === "/setup") {
      return NextResponse.redirect(new URL("/netqmon", request.url));
    }
    if (path === "/settings" || path.startsWith("/settings/")) {
      return NextResponse.redirect(new URL("/netqmon", request.url));
    }
    if (path.startsWith("/api/")) {
      const method = request.method.toUpperCase();
      if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
        return Response.json(
          {
            error: {
              code: "demo_read_only",
              message: "This demo environment is read-only.",
            },
          },
          { status: 403 },
        );
      }
    }
    return NextResponse.next();
  }

  if (PUBLIC_PATHS.has(path)) {
    return NextResponse.next();
  }
  const session = await openSession(request.cookies.get(SESSION_COOKIE)?.value);
  if (!session) {
    if (path.startsWith("/api/"))
      return Response.json({ error: "unauthorized" }, { status: 401 });
    const login = new URL("/login", request.url);
    login.searchParams.set("next", path);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
