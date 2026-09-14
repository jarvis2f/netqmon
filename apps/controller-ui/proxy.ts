import { NextResponse, type NextRequest } from "next/server";
import { openSession, SESSION_COOKIE } from "@/lib/session-token";

const PUBLIC_PATHS = new Set([
  "/setup",
  "/login",
  "/api/auth/status",
  "/api/auth/setup",
  "/api/auth/login",
]);

export async function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
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
