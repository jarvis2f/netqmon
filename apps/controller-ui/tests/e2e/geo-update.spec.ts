import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
  await page.goto("/settings");
  await expect(
    page.locator("#section-geo").getByText("Disabled", { exact: true }),
  ).toBeVisible();
});

test("updates Geo databases through the API proxy with a valid JSON request", async ({
  page,
}) => {
  const geo = page.locator("#section-geo");
  const updated = page.waitForResponse("**/api/settings/geo/update");
  await geo.getByRole("button", { name: "Update Now" }).click();
  const response = await updated;
  expect(response.status()).toBe(200);
  expect(response.request().headers()["content-type"]).toBe("application/json");
  expect(response.request().postDataJSON()).toEqual({});
  await expect(
    geo.getByText("Geo databases updated and hot-reloaded successfully"),
  ).toBeVisible();
  await expect(geo.getByText("Enabled", { exact: true })).toBeVisible();
  await expect(geo.getByText("Installed", { exact: true })).toHaveCount(2);
  await expect(geo.getByRole("button", { name: "Update Now" })).toBeEnabled();
});

test("shows a useful error for a non-JSON response and allows retrying", async ({
  page,
}) => {
  await page.route(
    "**/api/settings/geo/update",
    (route) =>
      route.fulfill({
        status: 502,
        contentType: "text/html",
        body: "<html>Bad Gateway</html>",
      }),
    { times: 1 },
  );
  const geo = page.locator("#section-geo");
  await geo.getByRole("button", { name: "Update Now" }).click();
  await expect(
    geo.getByText("Failed to update Geo databases", { exact: true }),
  ).toBeVisible();
  await expect(geo.getByRole("button", { name: "Update Now" })).toBeEnabled();
  await geo.getByRole("button", { name: "Update Now" }).click();
  await expect(
    geo.getByText("Geo databases updated and hot-reloaded successfully"),
  ).toBeVisible();
});

test("preserves the Collector's JSON error message", async ({ page }) => {
  await page.route("**/api/settings/geo/update", (route) =>
    route.fulfill({
      status: 500,
      json: {
        error: {
          code: "geo_update_error",
          message: "Could not download the City database",
        },
      },
    }),
  );
  const geo = page.locator("#section-geo");
  await geo.getByRole("button", { name: "Update Now" }).click();
  await expect(
    geo.getByText("Could not download the City database"),
  ).toBeVisible();
  await expect(geo.getByRole("button", { name: "Update Now" })).toBeEnabled();
});
