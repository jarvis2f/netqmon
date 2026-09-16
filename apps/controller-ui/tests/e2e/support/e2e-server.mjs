import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { createMockCollectorServer } from "./mock-collector.mjs";

const host = process.env.PLAYWRIGHT_HOST ?? "127.0.0.1";
const port = Number(process.env.PLAYWRIGHT_PORT ?? "3100");
const collectorPort = Number(process.env.NETQMON_E2E_COLLECTOR_PORT ?? "8099");
const appRoot = new URL("../../..", import.meta.url);
const standaloneRoot = new URL(".next/standalone/apps/controller-ui/", appRoot);
const standaloneStatic = new URL(".next/static/", standaloneRoot);
const standalonePublic = new URL("public/", standaloneRoot);

if (!existsSync(standaloneStatic)) {
  mkdirSync(new URL(".next/", standaloneRoot), { recursive: true });
  cpSync(new URL(".next/static/", appRoot), standaloneStatic, {
    recursive: true,
  });
}

if (!existsSync(standalonePublic)) {
  cpSync(new URL("public/", appRoot), standalonePublic, { recursive: true });
}

const collector = createMockCollectorServer();
const next = spawn(
  process.execPath,
  [".next/standalone/apps/controller-ui/server.js"],
  {
    cwd: appRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      HOSTNAME: host,
      PORT: String(port),
      NETQMON_COLLECTOR_INTERNAL_URL: `http://${host}:${collectorPort}`,
      NETQMON_SESSION_SECRET: "netqmon-e2e-session-secret-minimum-32-bytes",
    },
  },
);

collector.listen(collectorPort, host, () => {
  process.stdout.write(
    `Mock Collector listening on http://${host}:${collectorPort}\n`,
  );
});

function shutdown(code = 0) {
  collector.close();
  if (!next.killed) next.kill("SIGTERM");
  process.exit(code);
}

next.on("exit", (code) => shutdown(code ?? 0));
process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
