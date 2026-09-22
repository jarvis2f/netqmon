import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
});

test("opens a client side panel and drills into full client details", async ({
  page,
}) => {
  await page.getByRole("link", { name: "Clients" }).click();
  await expect(page.getByRole("heading", { name: "Clients" })).toBeVisible();

  await page.getByRole("row", { name: /Office Laptop/ }).click();
  await expect(
    page.getByRole("heading", { name: "Office Laptop" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Open client details" }).click();

  await expect(page).toHaveURL(/\/clients\/101$/);
  await expect(page.getByText("Known addresses")).toBeVisible();
  await expect(
    page.getByText("Private/random MAC", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("90%", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("IPv4 · 192.168.2.42")).toBeVisible();

  await page.getByRole("tab", { name: "Applications" }).click();
  await expect(page).toHaveURL(/\/clients\/101\?tab=applications$/);
  await expect(page.getByRole("row", { name: /youtube/i })).toBeVisible();
});

test("uses last traffic for client online status and recovers with new traffic", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "offline");
  await page.getByRole("link", { name: "Clients" }).click();

  const row = page.getByRole("row", { name: /Office Laptop/ });
  await expect(row.getByRole("status")).toContainText("Offline");

  await setCollectorScenario(request, "live");
  await expect(
    page.getByRole("row", { name: /Office Laptop/ }).getByRole("status"),
  ).toContainText("Online");
});

test("opens an application side panel and drills into full application details", async ({
  page,
}) => {
  await page.getByRole("link", { name: "Applications" }).click();
  await expect(
    page.getByRole("heading", { name: "Applications" }),
  ).toBeVisible();

  await page.getByRole("row", { name: /youtube/i }).click();
  await expect(page.getByRole("heading", { name: "youtube" })).toBeVisible();
  await page.getByRole("link", { name: "Open full details" }).click();

  await expect(page).toHaveURL(/\/applications\/youtube\?category=streaming$/);
  await expect(
    page.getByRole("heading", { name: "Classification" }),
  ).toBeVisible();
  await expect(
    page.getByText("matched domain suffix youtube.com"),
  ).toBeVisible();

  await page.getByRole("tab", { name: "Flows" }).click();
  await expect(page).toHaveURL(
    /\/applications\/youtube\?tab=flows&category=streaming$/,
  );
  await expect(
    page.getByRole("row", { name: /video.youtube.com/ }),
  ).toBeVisible();
});

test("keeps duplicate unknown applications scoped to their traffic category", async ({
  page,
}) => {
  await page.getByRole("link", { name: "Applications" }).click();
  await page.getByRole("row", { name: /unknown.*communication/i }).click();
  await expect(page).toHaveURL(
    /\/applications\?id=unknown&category=communication$/,
  );
  await expect(page.getByText("Traffic class: communication")).toBeVisible();

  await page.getByRole("link", { name: "Open full details" }).click();
  await expect(page).toHaveURL(
    /\/applications\/unknown\?category=communication$/,
  );
  await expect(page.getByText(/communication/).first()).toBeVisible();
});
