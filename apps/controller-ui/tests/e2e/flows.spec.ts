import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test.beforeEach(async ({ page, request }) => {
  await setCollectorScenario(request, "live");
  await login(page);
});

test("combines flow filters in the URL and keeps list context when a flow opens", async ({
  page,
}) => {
  let flowRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/flows") flowRequests += 1;
  });
  await page.getByRole("link", { name: "Flows" }).click();
  await expect(page.getByRole("heading", { name: "Flows" })).toBeVisible();

  await page
    .getByPlaceholder("Search IP, domain, client, or application")
    .fill("youtube");
  await expect(page).toHaveURL(/search=youtube/);

  await page.getByRole("button", { name: "Filter records" }).click();
  await page.getByRole("button", { name: "TCP" }).click();
  await expect(page).toHaveURL(/protocol=tcp/);
  await expect(page.getByText("Protocol:")).toBeVisible();
  await expect(page.getByText("TCP").first()).toBeVisible();
  await expect(
    page.getByRole("row", { name: /video.youtube.com/ }),
  ).toBeVisible();

  const requestsBeforeOpen = flowRequests;
  await page.getByRole("row", { name: /video.youtube.com/ }).click();
  await expect(page).toHaveURL(/flow=flow-youtube-1/);
  await expect(
    page.getByRole("heading", { name: "video.youtube.com" }),
  ).toBeVisible();
  await expect(
    page.getByText("matched domain suffix youtube.com"),
  ).toBeVisible();
  await expect(
    page.getByText("dns:video.youtube.com", { exact: true }),
  ).toBeVisible();
  expect(flowRequests).toBe(requestsBeforeOpen);

  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/search=youtube/);
  await expect(page).toHaveURL(/protocol=tcp/);
});
