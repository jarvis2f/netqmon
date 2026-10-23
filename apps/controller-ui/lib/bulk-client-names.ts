export interface ClientNameUpdate {
  line: number;
  mac: string;
  name: string;
}

export interface ClientNameIssue {
  line: number;
  reason: "invalidLine" | "duplicateMac";
}

export function normalizeClientMac(mac: string) {
  return mac.toLowerCase().replaceAll(/[:-]/g, "");
}

export function parseClientNameUpdates(input: string) {
  const entries: ClientNameUpdate[] = [];
  const issues: ClientNameIssue[] = [];
  const seen = new Set<string>();
  input.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line) return;
    const match = /^(\S+)\s+(.+)$/.exec(line);
    if (
      !match ||
      !/^(?:[\da-f]{12}|(?:[\da-f]{2}:){5}[\da-f]{2}|(?:[\da-f]{2}-){5}[\da-f]{2})$/i.test(
        match[1],
      )
    ) {
      issues.push({ line: index + 1, reason: "invalidLine" });
      return;
    }
    const mac = normalizeClientMac(match[1]);
    if (seen.has(mac)) {
      issues.push({ line: index + 1, reason: "duplicateMac" });
      return;
    }
    seen.add(mac);
    entries.push({ line: index + 1, mac: match[1], name: match[2].trim() });
  });
  return { entries, issues };
}
