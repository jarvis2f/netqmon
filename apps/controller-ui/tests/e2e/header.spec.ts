import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

for (const scenario of ["live", "offline"] as const) {
  test(`shares ${scenario} gateway status across pages without reconnecting the header`, async ({
    page,
    request,
  }) => {
    await setCollectorScenario(request, scenario);
    let connections = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/api/realtime") connections++;
    });
    await login(page);
    const header = page.getByRole("banner");
    await expect(header.getByText("OpenWrt Dev Gateway")).toBeVisible();
    await expect(
      header.getByText(scenario === "live" ? "Online" : "Offline", {
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      header.getByText(scenario === "live" ? "LIVE" : "Delayed", {
        exact: true,
      }),
    ).toBeVisible();
    const initialConnections = connections;

    for (const name of [
      "Applications",
      "Traffic",
      "Destinations",
      "Flows",
      "Insights",
      "Traffic Policies",
      "Settings",
    ]) {
      await page.getByRole("link", { name, exact: true }).click();
      await expect(
        page.getByRole("heading", { name, exact: true }),
      ).toBeVisible();
      await expect(header.getByText("OpenWrt Dev Gateway")).toBeVisible();
      await expect(
        header.getByText(scenario === "live" ? "Online" : "Offline", {
          exact: true,
        }),
      ).toBeVisible();
      await expect(
        header.getByText(scenario === "live" ? "LIVE" : "Delayed", {
          exact: true,
        }),
      ).toBeVisible();
    }
    expect(connections).toBe(initialConnections);
  });
}

test("distinguishes a disconnected stream from an offline gateway on every page", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await page.route("**/api/realtime**", (route) => route.abort());
  await login(page);
  const header = page.getByRole("banner");
  await expect(header.getByText("Online", { exact: true })).toBeVisible();
  await expect(header.getByText("Delayed", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Traffic Policies" }).click();
  await expect(header.getByText("OpenWrt Dev Gateway")).toBeVisible();
  await expect(header.getByText("Online", { exact: true })).toBeVisible();
  await expect(header.getByText("Delayed", { exact: true })).toBeVisible();
});

test("polls only lightweight status and suspends connections in the background", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  let fullOverviewRequests = 0;
  let statusRequests = 0;
  let connections = 0;
  let closedConnections = 0;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/api/overview") fullOverviewRequests++;
    if (url.pathname === "/api/overview/status") statusRequests++;
    if (url.pathname === "/api/realtime") connections++;
  });
  page.on("requestfailed", (request) => {
    if (new URL(request.url()).pathname === "/api/realtime")
      closedConnections++;
  });
  await login(page);
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  const header = page.getByRole("banner");
  await expect(header.getByText("Online", { exact: true })).toBeVisible();
  const fullBefore = fullOverviewRequests;
  const connectionsBefore = connections;
  const closedBefore = closedConnections;
  const statusBefore = statusRequests;
  expect(statusBefore).toBeGreaterThan(0);
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", {
      configurable: true,
      value: true,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(() => closedConnections).toBeGreaterThan(closedBefore);
  await page.waitForTimeout(15_500);
  expect(statusRequests).toBe(statusBefore);
  expect(fullOverviewRequests).toBe(fullBefore);
  expect(connections).toBe(connectionsBefore);
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", {
      configurable: true,
      value: false,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(() => statusRequests).toBeGreaterThan(statusBefore);
  await expect.poll(() => connections).toBe(connectionsBefore + 1);
  await expect(header.getByText("LIVE", { exact: true })).toBeVisible();
});
