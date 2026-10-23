import { expect, test, type Page } from "@playwright/test";
import type { ApiEnvelope, ClientSummary } from "../../lib/network-types";
import { login, setCollectorScenario } from "./support/session";

async function mockClients(page: Page, count = 2) {
  const response = await page.request.get("/api/clients?limit=200");
  const { data } = (await response.json()) as ApiEnvelope<ClientSummary[]>;
  const clients = Array.from({ length: count }, (_, index) => ({
    ...data[index % data.length],
    id: 1000 + index,
    mac: `02:00:00:00:${Math.floor(index / 256)
      .toString(16)
      .padStart(2, "0")}:${(index % 256).toString(16).padStart(2, "0")}`,
  }));
  const updates: Array<{ id: number; payload: unknown }> = [];
  const failures = new Set<number>();
  await page.route("**/api/clients?*", (route) => {
    const offset = Number(
      new URL(route.request().url()).searchParams.get("offset") ?? 0,
    );
    return route.fulfill({
      json: {
        schema_version: 1,
        data: clients.slice(offset, offset + 200),
        pagination: { limit: 200, offset, total: clients.length },
      },
    });
  });
  await page.route(/\/api\/clients\/\d+$/, async (route) => {
    if (route.request().method() !== "PUT") return route.continue();
    const id = Number(new URL(route.request().url()).pathname.split("/").pop());
    const payload = route.request().postDataJSON();
    updates.push({ id, payload });
    if (failures.has(id))
      return route.fulfill({
        status: 503,
        json: { error: { message: "Temporary failure" } },
      });
    const client = clients.find((item) => item.id === id)!;
    client.name = payload.name;
    return route.fulfill({ json: { schema_version: 1, data: { client } } });
  });
  await page.goto("/clients");
  await page.getByRole("button", { name: "Bulk update names" }).click();
  return {
    clients,
    updates,
    failures,
    dialog: page.getByRole("dialog", { name: "Bulk update client names" }),
  };
}

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
});

test("matches MAC variants across pages and updates only names outside the current filter", async ({
  page,
}) => {
  const { clients, updates, dialog } = await mockClients(page, 201);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page
    .getByRole("searchbox", { name: "Search clients" })
    .fill("does-not-match");
  await page.getByRole("button", { name: "Bulk update names" }).click();
  const input = dialog.getByLabel("MAC addresses and client names");
  await input.fill(
    `\n${clients[0].mac.toUpperCase().replaceAll(":", "-")} 客厅电视 Living Room\r\n${clients[200].mac.replaceAll(":", "")}\tOffice Workstation\n`,
  );
  await dialog.getByRole("button", { name: "Confirm update" }).click();
  await expect(dialog).toHaveCount(0);
  expect(updates).toEqual([
    { id: 1000, payload: { name: "客厅电视 Living Room" } },
    { id: 1200, payload: { name: "Office Workstation" } },
  ]);
  await page.getByRole("searchbox", { name: "Search clients" }).fill("");
  await page.getByRole("searchbox", { name: "Search clients" }).press("Enter");
  await expect(
    page.getByRole("row", { name: /客厅电视 Living Room/ }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("row", { name: /客厅电视 Living Room/ }),
  ).toBeVisible();
});

test("rejects malformed, duplicate, and unknown MAC entries before writing", async ({
  page,
}) => {
  const { clients, updates, dialog } = await mockClients(page);
  const input = dialog.getByLabel("MAC addresses and client names");
  const confirm = dialog.getByRole("button", { name: "Confirm update" });
  await input.fill(
    `invalid-mac Name\n${clients[0].mac}\n${clients[0].mac} First\n${clients[0].mac.replaceAll(":", "-")} Duplicate`,
  );
  await confirm.click();
  await expect(dialog.getByRole("alert")).toContainText("Line 1");
  await expect(dialog.getByRole("alert")).toContainText("Line 2");
  await expect(dialog.getByRole("alert")).toContainText("Line 4: duplicate");
  expect(updates).toEqual([]);
  await input.fill(`${clients[0].mac} Valid\nFF:FF:FF:FF:FF:FF Unknown`);
  await confirm.click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Line 2: client not found",
  );
  expect(updates).toEqual([]);
});

test("keeps only failed entries for retry and refreshes successful names immediately", async ({
  page,
}) => {
  const { clients, updates, failures, dialog } = await mockClients(page);
  failures.add(clients[1].id);
  const input = dialog.getByLabel("MAC addresses and client names");
  await input.fill(
    `${clients[0].mac} Updated Laptop\n${clients[1].mac} Updated TV`,
  );
  await dialog.getByRole("button", { name: "Confirm update" }).click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Updated 1 clients; 1 failed",
  );
  await expect(input).toHaveValue(`${clients[1].mac} Updated TV`);
  await expect(
    page.locator("tbody").getByText("Updated Laptop", { exact: true }),
  ).toBeAttached();
  failures.clear();
  await dialog.getByRole("button", { name: "Confirm update" }).click();
  await expect(dialog).toHaveCount(0);
  expect(updates.map((update) => update.id)).toEqual([1000, 1001, 1001]);
  await expect(page.getByRole("row", { name: /Updated TV/ })).toBeVisible();
});

test("opens a usable mobile dialog and places the button before the topology toggle", async ({
  page,
}) => {
  await page.goto("/clients");
  const bulk = page.getByRole("button", { name: "Bulk update names" });
  const topology = page.getByRole("button", { name: "Hide Topology" });
  // Both actions are ordered in the same toolbar; the toggle is hidden on mobile.
  expect(
    await bulk.evaluate((button) => button.nextElementSibling?.textContent),
  ).toContain("Hide");
  await page.setViewportSize({ width: 375, height: 667 });
  await bulk.click();
  const dialog = page.getByRole("dialog", { name: "Bulk update client names" });
  await expect(
    dialog.getByLabel("MAC addresses and client names"),
  ).toBeFocused();
  const bounds = await dialog.boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(375);
  await expect(topology).toBeHidden();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
});
