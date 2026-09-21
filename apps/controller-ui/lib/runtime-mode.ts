export function isDemoMode(): boolean {
  const val = process.env.NETQMON_DEMO_MODE?.trim().toLowerCase();
  return val === "true" || val === "1";
}
