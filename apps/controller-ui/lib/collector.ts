import "server-only";

const DEFAULT_INTERNAL_URL = "http://127.0.0.1:8091";

export function collectorUrl(path: string) {
  const base =
    process.env.NETQMON_COLLECTOR_INTERNAL_URL ?? DEFAULT_INTERNAL_URL;
  return new URL(path, base.endsWith("/") ? base : `${base}/`);
}

export async function collectorFetch(path: string, init: RequestInit = {}) {
  return fetch(collectorUrl(path), {
    ...init,
    cache: "no-store",
    headers: {
      accept: "application/json",
      ...init.headers,
    },
  });
}

export function upstreamUnavailable() {
  return Response.json(
    {
      schema_version: 1,
      error: {
        code: "collector_unavailable",
        message: "Collector is unavailable",
      },
    },
    { status: 503 },
  );
}
