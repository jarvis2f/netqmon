import { execFileSync, spawn } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = fileURLToPath(new URL("../../", import.meta.url));
const repoRoot = resolve(appRoot, "../..");
const work = mkdtempSync(join(tmpdir(), "netqmon-demo-e2e-"));
const database = join(work, "demo.db");
const forbiddenPolicyFile = join(work, "must-not-create-policies.db");
const dist = process.env.NETQMON_NEXT_DIST_DIR ?? ".next-demo";
const standalone = join(appRoot, dist, "standalone/apps/controller-ui");
const port = process.env.PLAYWRIGHT_DEMO_PORT ?? "3101";
const internalPort = process.env.PLAYWRIGHT_DEMO_COLLECTOR_PORT ?? "8101";
const children = [];
let stopping = false;

async function shutdown(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  await Promise.all(
    children.map(
      (child) =>
        new Promise((resolve) => {
          if (child.exitCode !== null || child.signalCode !== null)
            return resolve();
          const timeout = setTimeout(() => {
            child.kill("SIGKILL");
            resolve();
          }, 5000);
          child.once("exit", () => {
            clearTimeout(timeout);
            resolve();
          });
        }),
    ),
  );
  const leaked = existsSync(forbiddenPolicyFile);
  rmSync(work, { recursive: true, force: true });
  if (leaked)
    console.error("Demo unexpectedly created a persistent policy database");
  process.exit(leaked ? 1 : code);
}

try {
  // Only synthetic generator output is used, never an existing local database.
  execFileSync(
    "python3",
    [
      join(repoRoot, "tools/demo-db/generate_demo_db.py"),
      "--output",
      database,
      "--hours",
      "1",
      "--now",
    ],
    { cwd: repoRoot, stdio: "inherit" },
  );
  cpSync(join(appRoot, dist, "static"), join(standalone, dist, "static"), {
    recursive: true,
  });
  cpSync(join(appRoot, "public"), join(standalone, "public"), {
    recursive: true,
  });
  const env = {
    ...process.env,
    ...(process.env.NETQMON_DEMO_LIBRARY_PATH
      ? { DYLD_LIBRARY_PATH: process.env.NETQMON_DEMO_LIBRARY_PATH }
      : {}),
    NETQMON_DEMO_MODE: "true",
    NETQMON_COLLECTOR_DATABASE_PATH: database,
    NETQMON_POLICY_DATABASE_PATH: forbiddenPolicyFile,
    NETQMON_COLLECTOR_INTERNAL_ADDR: `127.0.0.1:${internalPort}`,
    NETQMON_COLLECTOR_INTERNAL_URL: `http://127.0.0.1:${internalPort}`,
    NETQMON_COLLECTOR_GEO_DIR: join(work, "geo"),
    NETQMON_COLLECTOR_MAC_DATASET_PATH: join(work, "mac-prefixes.json"),
    NETQMON_SESSION_SECRET: "netqmon-demo-e2e-secret-minimum-32-bytes",
    HOSTNAME: "127.0.0.1",
    PORT: port,
  };
  children.push(
    spawn(join(repoRoot, "target/debug/netqmon-collector"), [], {
      cwd: repoRoot,
      env,
      stdio: "inherit",
    }),
  );
  children.push(
    spawn(process.execPath, [join(standalone, "server.js")], {
      cwd: standalone,
      env,
      stdio: "inherit",
    }),
  );
  for (const child of children) {
    child.once("error", (error) => {
      console.error(error);
      void shutdown(1);
    });
    child.once("exit", (code) => {
      if (!stopping) void shutdown(code || 1);
    });
  }
  process.once("SIGINT", () => void shutdown(0));
  process.once("SIGTERM", () => void shutdown(0));
} catch (error) {
  console.error(error);
  await shutdown(1);
}
