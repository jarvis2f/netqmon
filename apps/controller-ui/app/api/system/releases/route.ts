import { unstable_cache } from "next/cache";
import { verifySession } from "@/lib/auth";
import { compareVersions, type Release } from "@/lib/releases";

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
  { revalidate: 3600 },
);

export async function GET() {
  if (!(await verifySession()))
    return Response.json({ error: "unauthorized" }, { status: 401 });

  try {
    return Response.json({ data: { releases: await getReleases() } });
  } catch {
    return Response.json(
      { error: "release_check_unavailable" },
      { status: 503 },
    );
  }
}
