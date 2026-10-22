import { expect, test } from "@playwright/test";

test("demo renders example policies and disables every editing action", async ({
  page,
}) => {
  await page.goto("/policies");
  await expect(
    page.getByRole("heading", { name: "Traffic Policies" }),
  ).toBeVisible();
  await expect(
    page.getByText("Traffic policy demo", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "New policy", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Republish after restore" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("row").filter({ hasText: "Guest device bandwidth cap" }),
  ).toBeVisible();
  const row = page
    .getByRole("row")
    .filter({ hasText: "Block YouTube on study device" });
  for (const name of ["Edit", "Disable", "Delete"])
    await expect(row.getByRole("button", { name, exact: true })).toBeDisabled();
  await row
    .getByRole("button", { name: /Block YouTube on study device/ })
    .click();
  const detail = page.getByRole("dialog");
  await expect(
    detail.getByRole("button", { name: "Edit", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("link", { name: "Settings", exact: true }),
  ).toHaveCount(0);
});

test("demo preview evaluates examples through the real Collector without changing them", async ({
  page,
  request,
}) => {
  const before = await (
    await request.get("/api/policies?gateway_id=demo-gateway")
  ).json();
  const block = before.data.items.find(
    (item: { spec: { name: string } }) =>
      item.spec.name === "Block YouTube on study device",
  );
  await page.goto("/policies");
  await page.getByRole("button", { name: "Preview decision" }).click();
  const panel = page.getByRole("dialog");
  await panel
    .getByLabel("Client MAC", { exact: true })
    .fill(block.spec.selectors.clients[0]);
  await panel.getByLabel("Application ID", { exact: true }).fill("youtube");
  await panel.getByLabel("Category ID", { exact: true }).fill("streaming");
  await panel
    .getByLabel("Application confidence (0–1)", { exact: true })
    .fill("0.99");
  const response = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/policies/preview") &&
      r.request().method() === "POST",
  );
  await panel.getByRole("button", { name: "Run preview" }).click();
  expect((await response).status()).toBe(200);
  await expect(
    panel.getByText("Block this identified flow", { exact: true }).first(),
  ).toBeVisible();
  const after = await (
    await request.get("/api/policies?gateway_id=demo-gateway")
  ).json();
  expect(after).toEqual(before);
});

test("demo proxy rejects mutations and cross-origin previews in both locales", async ({
  page,
  request,
  context,
  baseURL,
}) => {
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    const response = await request.fetch("/api/policies", {
      method,
      data: {},
      headers: { origin: baseURL! },
    });
    expect(response.status()).toBe(403);
    expect((await response.json()).error.code).toBe("demo_read_only");
  }
  expect(
    (
      await request.post("/api/policies/republish?gateway_id=demo-gateway", {
        data: {},
      })
    ).status(),
  ).toBe(403);
  expect(
    (
      await request.post("/api/policies/preview", {
        data: {},
        headers: { origin: "https://untrusted.example" },
      })
    ).status(),
  ).toBe(403);
  expect((await request.get("/api/settings/diagnostics")).status()).toBe(404);
  await context.addCookies([
    { name: "netqmon_locale", value: "zh-CN", url: baseURL! },
  ]);
  await page.goto("/policies");
  await expect(page.getByText("流量策略演示", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "新建策略", exact: true }),
  ).toBeDisabled();
  await page.goto("/settings");
  await expect(page).toHaveURL(/\/netqmon$/);
});
