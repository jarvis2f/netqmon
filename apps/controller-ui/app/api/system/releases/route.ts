import { unstable_cache } from "next/cache";
import { verifySession } from "@/lib/auth";
import { compareVersions, type Release } from "@/lib/releases";

// Releases change infrequently. Keep the successful result for six hours so
// page loads and multiple clients do not consume GitHub's anonymous API quota.
const RELEASE_CACHE_SECONDS = 6 * 60 * 60;
const RELEASE_RETRY_DELAY_MS = 60 * 60 * 1000;
let lastKnownGoodReleases: Release[] | undefined;
let retryAfter = 0;

// Cache the compact version list: GitHub's full response includes release notes
// and assets and can exceed the fetch cache's 2 MB entry limit.
const getReleases = unstable_cache(
  async (): Promise<Release[]> => {
    const response = await fetch(
      "https://api.github.com/repos/jarvis2f/netqmon/releases?per_page=100",
      {
        headers: { accept: "application/vnd.github+json" },
        cache: "no-store",
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (!response.ok) throw new Error("Release check failed");
    const values: unknown = await response.json();
    if (!Array.isArray(values)) throw new Error("Invalid release response");
    return values.flatMap((value) => {
      if (!value || typeof value !== "object") return [];
      const release = value as Record<string, unknown>;
      const tag = release.tag_name;
      if (
        release.draft !== false ||
        typeof tag !== "string" ||
        compareVersions(tag, tag) === null
      )
        return [];
      return [
        {
          version: tag.replace(/^v/, ""),
          url: `https://github.com/jarvis2f/netqmon/releases/tag/${encodeURIComponent(tag)}`,
        },
      ];
    });
  },
  ["netqmon-github-releases"],
  { revalidate: RELEASE_CACHE_SECONDS },
);

export async function GET() {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });

  // Avoid turning a GitHub outage or rate limit into a request on every page
  // load. If we have a successful result, keep serving it during the cooldown.
  if (Date.now() < retryAfter) {
    if (lastKnownGoodReleases)
      return Response.json({ data: { releases: lastKnownGoodReleases } });
    return Response.json(
      { error: "release_check_unavailable" },
      { status: 503 },
    );
  }

  try {
    const releases = await getReleases();
    lastKnownGoodReleases = releases;
    retryAfter = 0;
    return Response.json({ data: { releases } });
  } catch {
    retryAfter = Date.now() + RELEASE_RETRY_DELAY_MS;
    // A transient GitHub outage or rate limit should not hide a version list
    // already fetched successfully by this running controller process.
    if (lastKnownGoodReleases) {
      return Response.json({ data: { releases: lastKnownGoodReleases } });
    }
    return Response.json(
      { error: "release_check_unavailable" },
      { status: 503 },
    );
  }
}
