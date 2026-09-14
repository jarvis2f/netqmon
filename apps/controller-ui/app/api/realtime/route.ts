import { verifySession } from "@/lib/auth";
import { collectorFetch, upstreamUnavailable } from "@/lib/collector";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });
  try {
    const response = await collectorFetch("internal/realtime/stream", {
      signal: request.signal,
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      },
    });
  } catch {
    return upstreamUnavailable();
  }
}
