import { expect, test } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

test("opens insights with nested evidence values without crashing", async ({
  page,
  request,
}) => {
  await setCollectorScenario(request, "live");
  await login(page);
  await page.getByRole("link", { name: "Insights" }).click();

  await page.getByRole("button", { name: /Inspect evidence/ }).click();
  await expect(
    page.getByText('{"protocols":["quic","https"],"sampled":true}'),
  ).toBeVisible();
  await expect(
    page.getByText(/Application error|value\.replaceAll is not a function/),
  ).toHaveCount(0);
});
