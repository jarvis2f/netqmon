import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
});

test("renders ipinfo.io link for non-local destination without domain in /destinations", async ({
  page,
}) => {
  await page.goto("/destinations?view=table");
  await expect(
    page.getByRole("heading", { name: "Destinations" }),
  ).toBeVisible();

  const ipLink = page.locator(
    'a[href="https://ipinfo.io/203.0.113.10"][target="_blank"]',
  );
  await expect(ipLink).toBeVisible();
  await expect(ipLink).toHaveText(/203\.0\.113\.10/);
});

test("renders ipinfo.io link for non-local destination without domain in /flows", async ({
  page,
}) => {
  await page.goto("/flows");
  await expect(page.getByRole("heading", { name: "Flows" })).toBeVisible();

  const ipLink = page.locator(
    'a[href="https://ipinfo.io/203.0.113.10"][target="_blank"]',
  );
  await expect(ipLink).toBeVisible();
  await expect(ipLink).toHaveText(/203\.0\.113\.10/);
});

test("renders ipinfo.io link for non-local destination without domain in /applications/unknown?tab=destinations&category=unknown", async ({
  page,
}) => {
  await page.goto("/applications/unknown?tab=destinations&category=unknown");
  await expect(page.getByRole("tab", { name: "Destinations" })).toBeVisible();

  const ipLink = page.locator(
    'a[href="https://ipinfo.io/203.0.113.10"][target="_blank"]',
  );
  await expect(ipLink).toBeVisible();
  await expect(ipLink).toHaveText(/203\.0\.113\.10/);
});

test("renders ipinfo.io link for non-local destination without domain in /applications/unknown?tab=flows&category=unknown", async ({
  page,
}) => {
  await page.goto("/applications/unknown?tab=flows&category=unknown");
  await expect(page.getByRole("tab", { name: "Flows" })).toBeVisible();

  const ipLink = page.locator(
    'a[href="https://ipinfo.io/203.0.113.10"][target="_blank"]',
  );
  await expect(ipLink).toBeVisible();
  await expect(ipLink).toHaveText(/203\.0\.113\.10/);
});

test("opens flow details panel without error on /applications/unknown?tab=flows&category=unknown", async ({
  page,
}) => {
  await page.goto("/applications/unknown?tab=flows&category=unknown");
  await expect(page.getByRole("tab", { name: "Flows" })).toBeVisible();

  await page.getByRole("cell", { name: "192.168.2.77" }).click();
  await expect(
    page.getByRole("heading", { name: "203.0.113.10" }),
  ).toBeVisible();
  await expect(page.getByText("No matching evidence")).toBeVisible();
});
