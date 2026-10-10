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
  await page.route("**/api/realtime", (route) => route.abort());
  await login(page);
  const header = page.getByRole("banner");
  await expect(header.getByText("Online", { exact: true })).toBeVisible();
  await expect(header.getByText("Delayed", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Traffic Policies" }).click();
  await expect(header.getByText("OpenWrt Dev Gateway")).toBeVisible();
  await expect(header.getByText("Online", { exact: true })).toBeVisible();
  await expect(header.getByText("Delayed", { exact: true })).toBeVisible();
});
