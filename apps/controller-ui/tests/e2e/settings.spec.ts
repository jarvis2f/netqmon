import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ request }) => {
  await setCollectorScenario(request, "live");
});

test("renders Settings with the current collector diagnostics contract", async ({
  page,
}) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await login(page);
  await page.goto("/settings");

  await expect(
    page.getByText("Backend Storage & Telemetry Metrics"),
  ).toBeVisible();
  await expect(
    page.locator("#section-diagnostics").getByText("DUCKDB"),
  ).toBeVisible();
  expect(pageErrors).toEqual([]);
});
