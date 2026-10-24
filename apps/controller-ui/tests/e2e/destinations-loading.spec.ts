import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
});

test("destination rows appear while the geo summary is still pending", async ({
  page,
}) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/geo?**", async (route) => {
    await pending;
    await route.fulfill({
      json: { schema_version: 1, data: { enabled: false } },
    });
  });
  try {
    await page.goto("/destinations?view=table");
    await expect(
      page.getByRole("cell", { name: "chatgpt.com", exact: true }),
    ).toBeVisible();
    await expect(
      page.locator('a[href="https://ipinfo.io/203.0.113.10"]'),
    ).toBeVisible();
  } finally {
    release();
  }
});

test("destination map becomes usable while the geo summary is pending", async ({
  page,
}) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/geo?**", async (route) => {
    await pending;
    await route.fulfill({
      json: { schema_version: 1, data: { enabled: false } },
    });
  });
  await page.route("https://server.arcgisonline.com/**", (route) =>
    route.abort(),
  );
  try {
    await page.goto("/destinations?view=map");
    await expect(page.locator(".leaflet-container")).toBeVisible();
    await expect(
      page.locator(".leaflet-container").locator("..").locator(".animate-spin"),
    ).toHaveCount(0);
  } finally {
    release();
  }
});

test("geo summary errors leave destination rows available", async ({
  page,
}) => {
  await page.route("**/api/geo?**", (route) =>
    route.fulfill({ status: 503, json: { error: "unavailable" } }),
  );
  await page.goto("/destinations?view=table");
  await expect(
    page.getByRole("cell", { name: "chatgpt.com", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/Geo summary request failed \(503\)/),
  ).toBeVisible();
});
