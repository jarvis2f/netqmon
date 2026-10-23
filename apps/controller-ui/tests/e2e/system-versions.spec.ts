import { expect, test } from "@playwright/test";
import { compareVersions, latestRelease } from "../../lib/releases";
import { login, setCollectorScenario } from "./support/session";

test("compares numeric prereleases and follows the installed release channel", () => {
  expect(compareVersions("1.1.0-beta.10", "1.1.0-beta.9")).toBe(1);
  expect(compareVersions("1.1.0", "1.1.0-beta.10")).toBe(1);
  expect(compareVersions("v1.1.0+build.2", "1.1.0")).toBe(0);
  expect(compareVersions("dev", "1.1.0")).toBeNull();
  expect(compareVersions("1.1.0-beta.01", "1.1.0")).toBeNull();
  const releases = ["1.0.0", "1.2.0-beta.10", "1.1.0", "invalid"].map(
    (version) => ({ version, url: "https://example.com" }),
  );
  expect(latestRelease("1.0.0", releases)?.version).toBe("1.1.0");
  expect(latestRelease("1.1.0-beta.5", releases)?.version).toBe(
    "1.2.0-beta.10",
  );
  expect(latestRelease("dev", releases)).toBeNull();
  expect(latestRelease("1.0.0", [])).toBeNull();
});

test("shows current component versions and links newer releases", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await page.route("**/api/system/releases", (route) =>
    route.fulfill({
      json: {
        data: {
          releases: [
            {
              version: "1.1.0-beta.10",
              url: "https://github.com/jarvis2f/netqmon/releases/tag/v1.1.0-beta.10",
            },
          ],
        },
      },
    }),
  );
  await login(page);
  const status = page.getByRole("region", { name: "System Status" });
  await expect(
    status.getByText("v1.1.0-beta.5", { exact: true }),
  ).toBeVisible();
  await expect(status.getByText("v0.1.0-e2e", { exact: true })).toBeVisible();
  await expect(
    status.getByRole("link", {
      name: "View Controller v1.1.0-beta.10 release notes",
    }),
  ).toHaveAttribute("href", /v1\.1\.0-beta\.10$/);
  await expect(
    status.getByRole("link", {
      name: "View Controller v1.1.0-beta.10 release notes",
    }),
  ).toHaveAttribute("title", "Update · v1.1.0-beta.10");
  await expect(
    status.getByRole("link", {
      name: "View Agent v1.1.0-beta.10 release notes",
    }),
  ).toBeVisible();
  await status.screenshot({ path: "/tmp/netqmon-system-status.png" });
  await page.setViewportSize({ width: 390, height: 700 });
  await page
    .getByRole("button", { name: "Open navigation menu", exact: true })
    .click();
  const mobile = page.getByRole("dialog", { name: "Mobile navigation" });
  await expect(
    mobile.getByText("v1.1.0-beta.5", { exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 720 });
  await page
    .context()
    .addCookies([{ name: "netqmon_locale", value: "zh-CN", url: page.url() }]);
  await page.reload();
  const chineseStatus = page.getByRole("region", { name: "系统状态" });
  await expect(
    chineseStatus.getByRole("link", {
      name: "查看 Controller v1.1.0-beta.10 发布说明",
    }),
  ).toBeVisible();
  await chineseStatus.screenshot({ path: "/tmp/netqmon-system-status-zh.png" });
  await page.getByRole("button", { name: /当前主题/ }).click();
  await page.getByRole("button", { name: /当前主题：light/ }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await chineseStatus.screenshot({
    path: "/tmp/netqmon-system-status-zh-dark.png",
  });
});

test("shows latest versions and preserves offline version context", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "offline");
  await page.route("**/api/system/releases", (route) =>
    route.fulfill({
      json: {
        data: {
          releases: [
            {
              version: "0.1.0-e2e",
              url: "https://github.com/jarvis2f/netqmon/releases/tag/v0.1.0-e2e",
            },
          ],
        },
      },
    }),
  );
  await login(page);
  const status = page.getByRole("region", { name: "System Status" });
  await expect(status.getByText("Up to date", { exact: true })).toHaveCount(2);
  await expect(status.getByText("Last connected version")).toBeVisible();
});

test("does not claim versions are current when the release check fails", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await page.route("**/api/system/releases", (route) =>
    route.fulfill({ status: 503, json: { error: "unavailable" } }),
  );
  await login(page);
  const status = page.getByRole("region", { name: "System Status" });
  await expect(status.getByText("Check failed", { exact: true })).toHaveCount(
    2,
  );
  await expect(status.getByText("Up to date", { exact: true })).toHaveCount(0);
  await expect(
    status.getByText("v1.1.0-beta.5", { exact: true }),
  ).toBeVisible();
});

test("does not invent an Agent version before a gateway is connected", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "offline");
  await page.route("**/api/realtime**", (route) => route.abort());
  await page.route("**/api/overview/status", (route) =>
    route.fulfill({
      json: {
        data: {
          gateway_status: "unenrolled",
          gateway: null,
          controller_version: "1.1.0-beta.5",
        },
      },
    }),
  );
  await page.route("**/api/system/releases", (route) =>
    route.fulfill({ json: { data: { releases: [] } } }),
  );
  await login(page);
  const status = page.getByRole("region", { name: "System Status" });
  await expect(status.getByText("Disconnected", { exact: true })).toBeVisible();
  await expect(
    status.getByText("v1.1.0-beta.5", { exact: true }),
  ).toBeVisible();
  await expect(status.getByText("Up to date", { exact: true })).toHaveCount(0);
});
