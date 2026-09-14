import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";
import { sealSession, SESSION_COOKIE } from "../../lib/session-token";

test.beforeEach(async ({ request }) => {
  await setCollectorScenario(request, "live");
});

test("logs in and logs out through the BFF session", async ({ page }) => {
  await login(page);

  await page.getByRole("button", { name: "User menu" }).click();
  await expect(page.getByText("Signed in as admin")).toBeVisible();
  await page.getByRole("button", { name: "Log out" }).click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", { name: /Sign in to Console|进入控制台/ }),
  ).toBeVisible();
});

test("redirects unauthenticated users to login", async ({ page }) => {
  await page.goto("/flows");
  await expect(page).toHaveURL(/\/login\?next=%2Fflows$/);
});

test("handles stale or invalid session cookie without infinite redirect loop", async ({
  page,
  context,
}) => {
  process.env.NETQMON_SESSION_SECRET = "0123456789abcdef0123456789abcdef";
  const sealed = await sealSession({
    token: "stale-revoked-token",
    userId: "admin",
    username: "admin",
    expiresAt: Date.now() + 86400000,
  });

  await context.addCookies([
    {
      name: SESSION_COOKIE,
      value: sealed,
      domain: "localhost",
      path: "/",
    },
  ]);

  await page.goto("/netqmon");
  await expect(page).toHaveURL(/\/login(\?.*)?$/);
  await expect(
    page.getByRole("heading", { name: /Sign in to Console|进入控制台/ }),
  ).toBeVisible();
});
