import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test("renders live overview metrics and links to ranked applications", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await login(page);

  await expect(page.getByText("LIVE", { exact: true })).toBeVisible();
  await expect(page.getByText("Internet Download").first()).toBeVisible();
  await expect(page.getByText("Internet Upload").first()).toBeVisible();
  await expect(page.getByText("Active Internet Flows")).toBeVisible();
  await expect(page.getByText("Top Applications")).toBeVisible();
  await expect(page.getByText("youtube").first()).toBeVisible();
  await expect(
    page.getByText("video.youtube.com", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("chatgpt.com", { exact: true })).toBeVisible();

  await page.getByText("youtube").first().click();
  await expect(page).toHaveURL(/\/applications\?id=youtube$/);
  await expect(
    page.getByRole("heading", { name: "Applications" }),
  ).toBeVisible();
});

test("shows offline gateway state without fake zero throughput", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "offline");
  await login(page);

  await expect(page.getByText("Delayed")).toBeVisible();
  await expect(page.getByText("Offline").first()).toBeVisible();
  await expect(
    page.getByText("Waiting for gateway telemetry").first(),
  ).toBeVisible();
  await expect(page.getByText("Gateway is offline")).toBeVisible();
  await expect(page.getByText("0 bps")).toHaveCount(0);
});

test("surfaces hardware flow offload capture warnings", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "hfo");
  await login(page);

  await expect(
    page
      .getByLabel("Gateway Health")
      .getByText(/Capture degraded: hardware flow offloading is enabled/),
  ).toBeVisible();
  await expect(page.getByText("enabled").first()).toBeVisible();
  await expect(page.getByText("degraded").first()).toBeVisible();
  await expect(
    page
      .locator("main")
      .getByText(/Capture degraded: hardware flow offloading is enabled/),
  ).toBeVisible();
});
