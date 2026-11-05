import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test("navigation stays responsive while a destination verifies the session", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await login(page);
  const collectorPort = process.env.NETQMON_E2E_COLLECTOR_PORT ?? "8099";
  const delayUrl = `http://127.0.0.1:${collectorPort}/__auth-delay`;
  try {
    await request.post(`${delayUrl}?ms=5000`);
    const navigation = page.getByRole("navigation", {
      name: "Main navigation",
    });
    await navigation
      .getByRole("link", { name: "Traffic", exact: true })
      .click();
    await expect(page).toHaveURL(/\/traffic$/, { timeout: 3000 });
    await expect(
      page.getByRole("status").filter({ hasText: "Loading" }),
    ).toBeVisible();
    await navigation
      .getByRole("link", { name: "Applications", exact: true })
      .click();
    await expect(page).toHaveURL(/\/applications$/, { timeout: 3000 });
  } finally {
    await request.post(`${delayUrl}?ms=0`);
  }
});

test("navigation does not wait for the current page's data", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await login(page);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  let requested = false;
  await page.route("**/api/overview?summary=true", async (route) => {
    requested = true;
    await pending;
    await route.abort().catch(() => {});
  });
  try {
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect.poll(() => requested).toBe(true);
    await page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: "Traffic", exact: true })
      .click();
    await expect(page).toHaveURL(/\/traffic$/, { timeout: 3000 });
  } finally {
    release();
  }
});
