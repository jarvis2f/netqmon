import { defineConfig, devices } from "@playwright/test";

const host = "127.0.0.1";
const port = Number(process.env.PLAYWRIGHT_DEMO_PORT ?? "3101");
const baseURL = `http://${host}:${port}`;

export default defineConfig({
  testDir: "./tests/demo",
  outputDir: "test-results-demo",
  workers: 1,
  retries: 0,
  reporter: "list",
  use: { baseURL, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "node tests/demo/server.mjs",
    url: `${baseURL}/api/overview`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PLAYWRIGHT_DEMO_PORT: String(port),
      NETQMON_NEXT_DIST_DIR: ".next-demo",
    },
  },
});
