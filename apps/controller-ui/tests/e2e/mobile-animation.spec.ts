import { expect, test, type Locator } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.use({
  viewport: { width: 390, height: 667 },
  hasTouch: true,
  deviceScaleFactor: 3,
});

async function drawCount(canvas: Locator) {
  return Number((await canvas.getAttribute("data-test-draws")) ?? 0);
}

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await page.addInitScript(() => {
    const clear = CanvasRenderingContext2D.prototype.clearRect;
    CanvasRenderingContext2D.prototype.clearRect = function (...args) {
      this.canvas.dataset.testDraws = String(
        Number(this.canvas.dataset.testDraws ?? 0) + 1,
      );
      return clear.apply(this, args);
    };
  });
  await login(page);
  const response = await page.request.get("/api/clients?limit=200");
  const { data } = await response.json();
  const types = ["laptop", "smartphone", "tv", "nas", "iot", "unknown"];
  const clients = Array.from({ length: 200 }, (_, index) => ({
    ...data[index % data.length],
    id: 5000 + index,
    name: `Mobile test ${index}`,
    mac: (index + 1).toString(16).padStart(12, "0").match(/../g)!.join(":"),
    identity: { device_type: types[index % types.length] },
  }));
  await page.route("**/api/clients?*", (route) =>
    route.fulfill({ json: { schema_version: 1, data: clients } }),
  );
  await page.goto("/clients");
});

test("limits touch canvas work and stops its loop when paused or offscreen", async ({
  page,
}) => {
  const region = page.getByRole("region", {
    name: "Logical Topology",
    exact: true,
  });
  const canvas = region.locator("canvas");
  await expect.poll(() => drawCount(canvas)).toBeGreaterThan(2);
  await expect
    .poll(() =>
      canvas.evaluate(
        (el) =>
          Number(el.getAttribute("width")) / el.getBoundingClientRect().width,
      ),
    )
    .toBeCloseTo(1, 2);
  const before = await drawCount(canvas);
  await page.waitForTimeout(1_100);
  expect((await drawCount(canvas)) - before).toBeLessThanOrEqual(30);
  const pause = region
    .locator("..")
    .getByRole("button", { name: "Pause traffic animation" });
  await pause.click();
  const paused = await drawCount(canvas);
  await page.waitForTimeout(1_100);
  expect((await drawCount(canvas)) - paused).toBeLessThanOrEqual(4);
  await region
    .locator("..")
    .getByRole("button", { name: "Resume traffic animation" })
    .click();
  await expect.poll(() => drawCount(canvas)).toBeGreaterThan(paused + 4);
  await page.getByRole("row").last().scrollIntoViewIfNeeded();
  await page.waitForTimeout(100);
  const offscreen = await drawCount(canvas);
  await page.waitForTimeout(1_100);
  expect((await drawCount(canvas)) - offscreen).toBeLessThanOrEqual(1);
  await region.scrollIntoViewIfNeeded();
  await expect.poll(() => drawCount(canvas)).toBeGreaterThan(offscreen + 2);
});

test("keeps topology readable without a continuous loop for reduced motion", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const region = page.getByRole("region", {
    name: "Logical Topology",
    exact: true,
  });
  const canvas = region.locator("canvas");
  await expect.poll(() => drawCount(canvas)).toBeGreaterThan(0);
  await expect(
    region.getByRole("button", { name: /Internet \/ WAN/ }),
  ).toBeVisible();
  const before = await drawCount(canvas);
  await page.waitForTimeout(1_100);
  expect((await drawCount(canvas)) - before).toBeLessThanOrEqual(4);
});
