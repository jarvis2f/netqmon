import { collectorFetch, upstreamUnavailable } from "@/lib/collector";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const response = await collectorFetch("internal/auth/status");
    return new Response(response.body, {
      status: response.status,
      headers: { "content-type": "application/json" },
    });
  } catch {
    return upstreamUnavailable();
  }
}
