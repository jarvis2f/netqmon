import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.describe("License & Edition Management", () => {
  test.beforeEach(async ({ page, request }) => {
    await setCollectorScenario(request, "live");
    await login(page);
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await page.getByRole("tab", { name: "License" }).click();
    await expect(
      page.getByRole("heading", { name: "License & Edition" }),
    ).toBeVisible();
    await expect(page.getByText("NetQMon License")).toBeVisible();
  });

  test("displays initial Community edition and status", async ({ page }) => {
    await expect(page.getByText("Community").first()).toBeVisible();
    await expect(page.getByText("unlicensed").first()).toBeVisible();
    await expect(
      page.getByText("00000000-0000-0000-0000-000000000001"),
    ).toBeVisible();
    await expect(page.getByText("2026.09.01")).toBeVisible();
  });

  test("activates Pro edition with valid license key and checks status", async ({
    page,
  }) => {
    const keyInput = page.getByPlaceholder("Paste your License Key");
    await expect(keyInput).toBeVisible();

    await keyInput.fill("valid-pro-license-key");
    const activateButton = page.getByRole("button", { name: "Activate" });
    await expect(activateButton).toBeEnabled();

    await activateButton.click();

    // Verify Pro state after activation
    await expect(page.getByText("Pro").first()).toBeVisible();
    await expect(page.getByText("active").first()).toBeVisible();
    await expect(page.getByText("2026.09.08-pro")).toBeVisible();

    // Key input should be cleared after activation
    await expect(keyInput).toHaveValue("");

    // Check Now button should now be enabled and work
    const checkButton = page.getByRole("button", { name: "Check Now" });
    await expect(checkButton).toBeEnabled();
    await checkButton.click();
    await expect(page.getByText(/checked|refreshed/i).first()).toBeVisible();
  });

  test("displays error when invalid license key is provided", async ({
    page,
  }) => {
    const keyInput = page.getByPlaceholder("Paste your License Key");
    await keyInput.fill("invalid-key");
    const activateButton = page.getByRole("button", { name: "Activate" });
    await activateButton.click();

    await expect(
      page.getByText(/Invalid license key|failed/i).first(),
    ).toBeVisible();
  });

  test("respects prefers-reduced-motion and responsive mobile layout", async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize({ width: 375, height: 667 });

    const keyInput = page.getByPlaceholder("Paste your License Key");
    await expect(keyInput).toBeVisible();
    await expect(page.getByRole("button", { name: "Activate" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Check Now" })).toBeVisible();
  });
});
