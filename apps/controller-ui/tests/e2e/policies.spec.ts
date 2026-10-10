import { expect, test, type Page } from "@playwright/test";
import { login, setCollectorScenario } from "./support/session";

const gatewayId = "openwrt-dev";

async function openPolicies(page: Page) {
  await login(page);
  await page.getByRole("link", { name: "Traffic Policies" }).click();
  await expect(page).toHaveURL(/\/policies$/);
  await expect(
    page.getByRole("heading", { name: "Traffic Policies" }),
  ).toBeVisible();
}

async function createPolicy(page: Page, name: string) {
  await page.getByRole("button", { name: "New policy" }).first().click();
  const editor = page.getByRole("dialog");
  await editor.getByLabel("Policy name").fill(name);
  await editor
    .getByRole("group", { name: "Clients" })
    .getByLabel(/Office Laptop/)
    .check();
  await editor.getByRole("button", { name: "Validate" }).click();
  await expect(editor.getByText("Policy is valid")).toBeVisible();
  await editor.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(name, { exact: true })).toBeVisible();
}

test.describe("traffic policies", () => {
  test.beforeEach(async ({ request }) => {
    await setCollectorScenario(request, "live");
  });

  test("keeps unsafe YAML in advanced mode and localizes the standalone page", async ({
    page,
  }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "New policy" }).first().click();
    const editor = page.getByRole("dialog");
    await editor.getByRole("tab", { name: "Advanced YAML" }).click();
    const yaml = editor.getByLabel("Advanced policy YAML editor");
    await yaml.fill("name: &anchor value");
    await expect(editor.getByRole("alert")).toContainText(
      "anchors are not supported",
    );
    await editor.getByRole("tab", { name: "Visual configuration" }).click();
    await expect(
      editor.getByRole("tab", { name: "Advanced YAML" }),
    ).toHaveAttribute("aria-selected", "true");
    await editor.getByRole("button", { name: "Cancel" }).click();

    await page.getByRole("button", { name: "Switch language" }).first().click();
    await page.getByRole("option", { name: "简体中文" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await expect(page.getByRole("heading", { name: "流量策略" })).toBeVisible();
    await expect(
      page.getByRole("button", { name: "新建策略" }).first(),
    ).toBeVisible();
  });

  test("round-trips YAML through visual configuration without losing fields", async ({
    page,
  }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "New policy" }).first().click();
    const editor = page.getByRole("dialog");
    await editor.getByRole("tab", { name: "Advanced YAML" }).click();

    const yaml = editor.getByLabel("Advanced policy YAML editor");
    await yaml.fill(
      [
        "schema_version: 1",
        `gateway_id: ${gatewayId}`,
        "name: YAML round-trip policy",
        "description: Values survive both editor modes",
        "enabled: false",
        "priority: 275",
        "selectors:",
        '  clients: ["AA:BB:CC:DD:EE:01"]',
        "  applications: []",
        "  categories: []",
        "  min_application_confidence: 0.9",
        "network:",
        "  scope: internet",
        "  direction: both",
        "action:",
        "  type: limit",
        "  download_bps: 7500000",
        "  upload_bps: 1500000",
        "schedule: null",
      ].join("\n"),
    );
    await editor.getByRole("tab", { name: "Visual configuration" }).click();

    await expect(editor.getByLabel("Policy name")).toHaveValue(
      "YAML round-trip policy",
    );
    await expect(editor.getByLabel("Description")).toHaveValue(
      "Values survive both editor modes",
    );
    await expect(editor.getByLabel("Priority")).toHaveValue("275");
    await expect(
      editor.getByLabel("Minimum application confidence"),
    ).toHaveValue("0.9");
    await expect(editor.getByLabel("Action")).toHaveText("Limit");
    await expect(editor.getByLabel("Download ceiling")).toHaveValue("7.5");
    await expect(editor.getByLabel("Upload ceiling")).toHaveValue("1.5");

    await editor.getByRole("tab", { name: "Advanced YAML" }).click();
    await expect(yaml).toHaveValue(/priority: 275/);
    await expect(yaml).toHaveValue(/download_bps: 7500000/);
    await expect(yaml).toHaveValue(/upload_bps: 1500000/);
    await expect(yaml).toHaveValue(/min_application_confidence: 0.9/);
  });

  test("preserves the visual draft after a policy save failure", async ({
    page,
  }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "New policy" }).first().click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Policy name").fill("Draft survives failed save");
    await editor
      .getByRole("group", { name: "Clients" })
      .getByLabel(/Office Laptop/)
      .check();
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();

    await page.route("**/api/policies", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          schema_version: 1,
          error: {
            code: "policy_store_unavailable",
            message: "Policy save failed for test.",
          },
        }),
      });
    });
    await editor.getByRole("button", { name: "Save", exact: true }).click();

    await expect(editor.getByRole("alert")).toContainText(
      "Policy save failed for test.",
    );
    await expect(editor.getByLabel("Policy name")).toHaveValue(
      "Draft survives failed save",
    );
  });

  test("creates, toggles, edits and deletes through the authenticated BFF", async ({
    page,
  }) => {
    await openPolicies(page);
    await createPolicy(page, "Evening TV policy");
    await expect(
      page.getByRole("button", { name: "Evening TV policy" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Evening TV policy" }).click();
    const details = page.getByRole("dialog");
    await expect(details.getByText("Change history")).toBeVisible();
    await details.getByRole("button", { name: "Close property panel" }).click();

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Enable", exact: true }).click();
    await expect(
      page
        .getByRole("row", { name: /Evening TV policy/ })
        .getByText("Unsupported", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Desired state enabled and queued for Agent delivery."),
    ).toBeVisible();

    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Description").fill("Evening viewing only");
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    await editor.getByRole("button", { name: "Save Changes" }).click();
    await expect(
      page.getByText("Policy changes saved and queued for Agent delivery."),
    ).toBeVisible();

    await page.getByRole("button", { name: "Delete", exact: true }).click();
    const deleteConfirmation = page.getByRole("dialog");
    await expect(
      deleteConfirmation.getByRole("heading", { name: "Delete policy?" }),
    ).toBeVisible();
    await deleteConfirmation
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByText("Evening TV policy", { exact: true }),
    ).toHaveCount(0);
  });

  test("renders per-client application block counters", async ({ page }) => {
    await page.route("**/api/policies/deployment?*", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.data.policies = payload.data.policies.map(
        (policy: { policy_id: string; [key: string]: unknown }) => ({
          ...policy,
          traffic_metrics: [
            {
              policy_id: policy.policy_id,
              mac: "AA:BB:CC:DD:EE:01",
              upload: {
                interface: "policy-block",
                bytes: 4096,
                packets: 12,
                drops: 12,
                overlimits: null,
              },
              download: null,
            },
          ],
        }),
      );
      await route.fulfill({ response, body: JSON.stringify(payload) });
    });
    await openPolicies(page);
    await createPolicy(page, "Blocked traffic metrics policy");
    await page
      .getByRole("button", { name: "Blocked traffic metrics policy" })
      .click();
    const details = page.getByRole("dialog");
    await expect(
      details.getByRole("heading", { name: "Blocked traffic", exact: true }),
    ).toBeVisible();
    const blockMetric = details.getByTestId("policy-block-metric-row");
    await expect(
      blockMetric.getByText("AA:BB:CC:DD:EE:01", { exact: true }),
    ).toBeVisible();
    await expect(details.getByText(/Dropped packets: 12/)).toBeVisible();
    await expect(details.getByText(/Dropped bytes: 4.1 KB/)).toBeVisible();
  });

  test("shows delivered, acknowledged and applied revisions independently", async ({
    page,
  }) => {
    await page.route("**/api/policies/deployment?*", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.data.desired_revision = 7;
      payload.data.delivered_revision = 7;
      payload.data.delivery_status = "delivered";
      payload.data.acknowledged_revision = 6;
      payload.data.acknowledged_status = "failed";
      payload.data.status = "failed";
      payload.data.applied_revision = 5;
      await route.fulfill({ response, body: JSON.stringify(payload) });
    });

    await openPolicies(page);
    const overview = page.getByRole("region", { name: "Policy overview" });
    await expect(
      overview.getByRole("group", { name: /Sent: r7\. The Collector wrote/ }),
    ).toBeVisible();
    await expect(
      overview.getByRole("status", { name: /Failed/ }),
    ).toBeVisible();
    await expect(
      overview.getByRole("group", { name: /Acknowledged: r6/ }),
    ).toBeVisible();
    await expect(
      overview.getByRole("group", { name: /Applied: r5/ }),
    ).toBeVisible();
  });

  test("rejects cross-origin policy mutations at the BFF", async ({ page }) => {
    await openPolicies(page);
    const response = await page
      .context()
      .request.post("http://127.0.0.1:3100/api/policies/validate", {
        headers: {
          origin: "https://attacker.example",
          "content-type": "application/json",
        },
        data: { spec: { gateway_id: gatewayId } },
      });
    expect(response.status()).toBe(403);
    expect((await response.json()).error).toBe("forbidden");
  });

  test("previews an application decision without changing policy state", async ({
    page,
  }) => {
    await openPolicies(page);
    const listResponse = await page
      .context()
      .request.get(
        "http://127.0.0.1:3100/api/policies?gateway_id=openwrt-dev&page=1&page_size=100",
      );
    const before = await listResponse.json();

    await page.getByRole("button", { name: "Preview decision" }).click();
    const panel = page.getByRole("dialog", {
      name: "Application policy preview",
    });
    await panel.getByLabel("Client MAC").fill("AA:BB:CC:DD:EE:01");
    await panel.getByLabel("Application ID").fill("youtube");
    await panel.getByLabel("Category ID").fill("streaming");
    await panel.getByRole("button", { name: "Run preview" }).click();
    await expect(
      panel.getByText("No enabled application policy matched these inputs."),
    ).toBeVisible();

    const afterResponse = await page
      .context()
      .request.get(
        "http://127.0.0.1:3100/api/policies?gateway_id=openwrt-dev&page=1&page_size=100",
      );
    const after = await afterResponse.json();
    expect(after.data.desired_revision).toBe(before.data.desired_revision);
    expect(after.data.items).toEqual(before.data.items);
  });

  test("shows the server snapshot instead of overwriting a concurrent edit", async ({
    page,
  }) => {
    await openPolicies(page);
    await createPolicy(page, "Conflict policy");

    const listResponse = await page
      .context()
      .request.get(
        "http://127.0.0.1:3100/api/policies?gateway_id=openwrt-dev&page=1&page_size=100",
      );
    const list = await listResponse.json();
    const policy = list.data.items[0];
    const revision = list.data.desired_revision;
    const localEditor = page.getByRole("button", { name: "Edit", exact: true });
    await localEditor.click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Description").fill("local unsaved draft");
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();

    const remoteSpec = {
      ...policy.spec,
      description: "saved by another editor",
    };
    const remoteUpdate = await page
      .context()
      .request.put(
        `http://127.0.0.1:3100/api/policies/${encodeURIComponent(policy.id)}`,
        {
          headers: {
            origin: "http://127.0.0.1:3100",
            "content-type": "application/json",
            "if-match": `"rev:${revision}"`,
            "x-expected-policy-version": String(policy.version),
          },
          data: remoteSpec,
        },
      );
    expect(remoteUpdate.status()).toBe(200);

    page.once("dialog", (dialog) => dialog.accept());
    await editor.getByRole("button", { name: "Save Changes" }).click();
    await expect(editor.getByText("Concurrent edit detected")).toBeVisible();
    await expect(
      editor.getByRole("textbox", { name: "Description" }),
    ).toHaveValue("local unsaved draft");
    await expect(editor.getByText("saved by another editor")).toBeVisible();
  });
});
