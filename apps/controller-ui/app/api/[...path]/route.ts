import { verifySession } from "@/lib/auth";
import { collectorFetch, upstreamUnavailable } from "@/lib/collector";

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
]);

export const dynamic = "force-dynamic";

function validatePath(path: string[]): boolean {
  return (
    path.length > 0 &&
    RESOURCES.has(path[0]) &&
    path.every((part: string) => /^[a-zA-Z0-9._-]+$/.test(part))
  );
}

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });
  const { path } = await context.params;
  if (!validatePath(path)) {
    return Response.json({ error: "unknown API resource" }, { status: 404 });
  }
  try {
    const incoming = new URL(request.url);
    const upstream = `internal/${path.join("/")}${incoming.search}`;
    const acceptLanguage = request.headers.get("accept-language");
    const response = await collectorFetch(upstream, {
      headers: acceptLanguage ? { "accept-language": acceptLanguage } : {},
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type":
          response.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return upstreamUnavailable();
  }
}

export async function PUT(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });
  const { path } = await context.params;
  if (!validatePath(path)) {
    return Response.json({ error: "unknown API resource" }, { status: 404 });
  }
  try {
    const incoming = new URL(request.url);
    const upstream = `internal/${path.join("/")}${incoming.search}`;
    const body = await request.arrayBuffer();
    const response = await collectorFetch(upstream, {
      method: "PUT",
      body: Buffer.from(body),
      headers: { "content-type": "application/json" },
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type":
          response.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return upstreamUnavailable();
  }
}

export async function POST(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });
  const { path } = await context.params;
  if (!validatePath(path)) {
    return Response.json({ error: "unknown API resource" }, { status: 404 });
  }
  try {
    const incoming = new URL(request.url);
    const upstream = `internal/${path.join("/")}${incoming.search}`;
    const body = await request.arrayBuffer();
    const response = await collectorFetch(upstream, {
      method: "POST",
      body: body.byteLength > 0 ? Buffer.from(body) : undefined,
      headers:
        body.byteLength > 0 ? { "content-type": "application/json" } : {},
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type":
          response.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return upstreamUnavailable();
  }
}
