import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.describe("i18n internationalization", () => {
  test.beforeEach(async ({ page, request }) => {
    await setCollectorScenario(request, "live");
    await login(page);
  });

  test("defaults to English with clean URL and correct lang attribute", async ({
    page,
  }) => {
    await expect(page).toHaveURL(/\/netqmon$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "en");

    // Header and navigation should be in English
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByText("Active Internet Flows")).toBeVisible();
    await expect(page.getByText("Online Clients")).toBeVisible();
    await expect(page.getByText("Top Applications")).toBeVisible();
  });

  test("switches language to Simplified Chinese and persists via cookie", async ({
    page,
    context,
  }) => {
    await expect(page).toHaveURL(/\/netqmon$/);

    await page.getByRole("button", { name: "Switch language" }).click();
    await page.getByRole("option", { name: "简体中文" }).click();

    // Root html lang should update to zh-CN
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");

    // Header and metrics should now be in Chinese
    await expect(page.getByRole("heading", { name: "概览" })).toBeVisible();
    await expect(page.getByText("活跃互联网连接流")).toBeVisible();
    await expect(page.getByText("在线客户端")).toBeVisible();
    await expect(page.getByText("热门应用")).toBeVisible();

    // Verify cookie was set
    const cookies = await context.cookies();
    const localeCookie = cookies.find((c) => c.name === "netqmon_locale");
    expect(localeCookie).toBeDefined();
    expect(localeCookie?.value).toBe("zh-CN");

    // Navigate to another page (e.g. /traffic) without locale in path
    await page.getByRole("link", { name: "流量" }).click();
    await expect(page).toHaveURL(/\/traffic$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await expect(
      page.getByRole("heading", { name: "流量", exact: true }),
    ).toBeVisible();

    // Navigate to Settings
    await page.getByRole("link", { name: "设置" }).click();
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await expect(
      page.getByRole("heading", { name: "设置", exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "系统诊断" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "数据保留" })).toBeVisible();

    // Switch back to English from Settings
    await page.getByRole("button", { name: "切换语言" }).first().click();
    await page.getByRole("option", { name: "English" }).click();

    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(
      page.getByRole("heading", { name: "Settings", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "System Diagnostics" }),
    ).toBeVisible();
  });

  test("auth page displays language switcher and renders in Chinese", async ({
    page,
  }) => {
    // Navigate to /login directly without session
    await page.context().clearCookies();
    await page.goto("/login");

    // Default English
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(
      page.getByRole("heading", { name: "Sign in to Console" }),
    ).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();

    // Click Chinese toggle in auth page
    await page.getByRole("button", { name: "简体中文" }).click();

    // Now page should be in Chinese
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await expect(
      page.getByRole("heading", { name: "进入控制台" }),
    ).toBeVisible();
    await expect(page.getByLabel("用户名")).toBeVisible();
    await expect(page.getByLabel("密码", { exact: true })).toBeVisible();
  });
});
