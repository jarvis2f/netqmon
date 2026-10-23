export interface Release {
  version: string;
  url: string;
}

function parseVersion(value: string) {
  const match =
    /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([\da-zA-Z-]+(?:\.[\da-zA-Z-]+)*))?(?:\+[\da-zA-Z-]+(?:\.[\da-zA-Z-]+)*)?$/.exec(
      value,
    );
  if (!match) return null;
  const prerelease = match[4]?.split(".") ?? [];
  if (
    prerelease.some(
      (part) => /^\d+$/.test(part) && part.length > 1 && part[0] === "0",
    )
  )
    return null;
  return { core: match.slice(1, 4).map(BigInt), prerelease };
}

// Build metadata does not affect precedence; beta.10 must sort after beta.9.
export function compareVersions(left: string, right: string): number | null {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index++) {
    if (a.core[index] !== b.core[index])
      return a.core[index] > b.core[index] ? 1 : -1;
  }
  if (!a.prerelease.length || !b.prerelease.length) {
    return a.prerelease.length === b.prerelease.length
      ? 0
      : a.prerelease.length
        ? -1
        : 1;
  }
  for (
    let index = 0;
    index < Math.max(a.prerelease.length, b.prerelease.length);
    index++
  ) {
    const x = a.prerelease[index];
    const y = b.prerelease[index];
    if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    if (xNumeric && yNumeric) return BigInt(x) > BigInt(y) ? 1 : -1;
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    return x > y ? 1 : -1;
  }
  return 0;
}

export function latestRelease(
  current: string,
  releases: Release[],
): Release | null {
  const version = parseVersion(current);
  if (!version) return null;
  return releases.reduce<Release | null>((latest, release) => {
    const candidate = parseVersion(release.version);
    if (
      !candidate ||
      (!version.prerelease.length && candidate.prerelease.length)
    )
      return latest;
    return !latest || compareVersions(release.version, latest.version)! > 0
      ? release
      : latest;
  }, null);
}
