import { expect, type Page, type APIRequestContext } from "@playwright/test";

const collectorPort = process.env.NETQMON_E2E_COLLECTOR_PORT ?? "8099";
const collectorBase = `http://127.0.0.1:${collectorPort}`;

export async function setCollectorScenario(
  request: APIRequestContext,
  scenario: "live" | "offline" | "hfo",
) {
  const response = await request.post(
    `${collectorBase}/__scenario/${scenario}`,
  );
  expect(response.ok()).toBeTruthy();
}

export async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/Username|用户名/).fill("admin");
  await page.getByLabel(/Password|密码/).fill("correct-horse-battery");
  await page.getByRole("button", { name: /Sign in|登录/ }).click();
  await expect(page).toHaveURL(/\/netqmon$/);
  await expect(
    page.getByRole("heading", { name: /Overview|概览/ }),
  ).toBeVisible();
}
