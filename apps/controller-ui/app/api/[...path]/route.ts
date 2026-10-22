import { sameOrigin, verifySession } from "@/lib/auth";
import { collectorFetch, upstreamUnavailable } from "@/lib/collector";
import { isDemoMode } from "@/lib/runtime-mode";

const RESOURCES = new Set([
  "overview",
  "traffic",
  "clients",
  "applications",
  "organizations",
  "protocols",
  "domains",
  "destinations",
  "geo",
  "insights",
  "flows",
  "settings",
  "icons",
  "rules",
  "policies",
]);

export const dynamic = "force-dynamic";

function validatePath(path: string[]): boolean {
  return (
    path.length > 0 &&
    !(isDemoMode() && path[0] === "settings") &&
    RESOURCES.has(path[0]) &&
    path.every(
      (part: string, index: number) =>
        /^[a-zA-Z0-9._-]+$/.test(part) ||
        (path[0] === "applications" &&
          index === 1 &&
          /^protocol:[a-zA-Z0-9._-]+$/.test(part)),
    )
  );
}

function isPolicyPath(path: string[]) {
  return path[0] === "policies";
}

async function proxy(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
) {
  const { path } = await context.params;
  const demoPreview =
    method === "POST" &&
    path.length === 2 &&
    path[0] === "policies" &&
    path[1] === "preview";
  if (isDemoMode() && method !== "GET" && !demoPreview) {
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
  const session = await verifySession();
  if (!session)
    return Response.json({ error: "unauthorized" }, { status: 401 });

  if (!validatePath(path)) {
    return Response.json({ error: "unknown API resource" }, { status: 404 });
  }
  const policyPath = isPolicyPath(path);
  if ((method === "PATCH" || method === "DELETE") && !policyPath) {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }
  if (policyPath && method !== "GET" && !sameOrigin(request)) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }

  try {
    const incoming = new URL(request.url);
    const upstream = `internal/${path.join("/")}${incoming.search}`;
    const headers: Record<string, string> = {};
    if (policyPath && !isDemoMode()) {
      // verifySession() validates the sealed cookie with Collector first; never
      // forward a browser-supplied Authorization header to the internal API.
      headers.authorization = `Bearer ${session.token}`;
    }
    if (method === "GET") {
      const acceptLanguage = request.headers.get("accept-language");
      if (acceptLanguage) headers["accept-language"] = acceptLanguage;
    } else {
      const expectedRevision = request.headers.get("if-match");
      const expectedVersion = request.headers.get("x-expected-policy-version");
      if (policyPath && expectedRevision)
        headers["if-match"] = expectedRevision;
      if (policyPath && expectedVersion)
        headers["x-expected-policy-version"] = expectedVersion;
      if (method !== "DELETE") headers["content-type"] = "application/json";
    }

    const body =
      method === "GET" || method === "DELETE"
        ? undefined
        : await request.arrayBuffer();
    const response = await collectorFetch(upstream, {
      method,
      body: body && body.byteLength > 0 ? Buffer.from(body) : undefined,
      headers,
    });
    const responseHeaders = new Headers();
    const contentType = response.headers.get("content-type");
    if (contentType) responseHeaders.set("content-type", contentType);
    const cacheControl = response.headers.get("cache-control");
    if (cacheControl) responseHeaders.set("cache-control", cacheControl);
    return new Response(response.status === 204 ? null : response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch {
    return upstreamUnavailable();
  }
}

type RouteContext = { params: Promise<{ path: string[] }> };

export async function GET(request: Request, context: RouteContext) {
  return proxy(request, context, "GET");
}

export async function PUT(request: Request, context: RouteContext) {
  return proxy(request, context, "PUT");
}

export async function POST(request: Request, context: RouteContext) {
  return proxy(request, context, "POST");
}

export async function PATCH(request: Request, context: RouteContext) {
  return proxy(request, context, "PATCH");
}

export async function DELETE(request: Request, context: RouteContext) {
  return proxy(request, context, "DELETE");
}
