import { expect, test, type Page } from "@playwright/test";
import type { PolicyRecord } from "../../lib/network-types";
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

  test("requires component confirmation for toggles, deletion and republishing", async ({
    page,
  }) => {
    page.on("dialog", () => {
      throw new Error("Unexpected browser-native dialog");
    });
    await openPolicies(page);
    await createPolicy(page, "Confirmation policy");
    const row = page.getByRole("row", { name: /Confirmation policy/ });
    let mutations = 0;
    page.on("request", (request) => {
      if (
        ["POST", "PATCH", "PUT", "DELETE"].includes(request.method()) &&
        new URL(request.url()).pathname.startsWith("/api/policies")
      )
        mutations++;
    });
    await row.getByRole("button", { name: "Enable", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Enable policy?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    expect(mutations).toBe(0);
    await row.getByRole("button", { name: "Enable", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Enable policy?" })
      .getByRole("button", { name: "Enable", exact: true })
      .click();
    await expect(
      row.getByRole("button", { name: "Disable", exact: true }),
    ).toBeVisible();
    expect(mutations).toBe(1);
    await row.getByRole("button", { name: "Disable", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Disable policy?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    expect(mutations).toBe(1);
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Delete policy?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    expect(mutations).toBe(1);

    const republish = page.getByRole("button", {
      name: "Republish after restore",
    });
    await republish.click();
    await page
      .getByRole("dialog", { name: "Republish policies?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    expect(mutations).toBe(1);
    await republish.click();
    await page
      .getByRole("dialog", { name: "Republish policies?" })
      .getByRole("button", { name: "Republish", exact: true })
      .click();
    await expect(
      page.getByText("A new desired revision was created and queued for push."),
    ).toBeVisible();
    expect(mutations).toBe(2);
  });

  test("keeps editor focus across background deployment refreshes", async ({
    page,
  }) => {
    await openPolicies(page);
    const trigger = page.getByRole("button", { name: "New policy" }).first();
    await trigger.click();
    const editor = page.getByRole("dialog");
    const name = editor.getByLabel("Policy name");
    await name.fill("Persistent draft");

    const waitForRefresh = async () => {
      await Promise.all([
        page.waitForResponse("**/api/policies/deployment?*"),
        // Keep the field idle through a full polling cycle and its render.
        page.waitForTimeout(5_500),
      ]);
    };

    await waitForRefresh();
    await expect(name).toBeFocused();
    await page.keyboard.type(" after refresh");
    await expect(name).toHaveValue("Persistent draft after refresh");

    await editor.getByRole("tab", { name: "Advanced YAML" }).click();
    const yaml = editor.getByLabel("Advanced policy YAML editor");
    await yaml.click();
    await waitForRefresh();
    await expect(yaml).toBeFocused();
    await expect(yaml).toHaveValue(/Persistent draft after refresh/);

    await page.keyboard.press("Escape");
    await expect(editor).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test("keeps preview input focus while typing", async ({ page }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "Preview decision" }).click();
    const preview = page.getByRole("dialog");
    for (const [label, value] of [
      ["Client MAC", "AA:BB:CC:DD:EE:01"],
      ["Application ID", "youtube"],
      ["Category ID", "streaming"],
    ]) {
      const input = preview.getByLabel(label, { exact: true });
      await input.clear();
      await input.pressSequentially(value, { delay: 20 });
      await expect(input).toHaveValue(value);
      await expect(input).toBeFocused();
    }
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
        "  scope: agent",
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
    ).toHaveCount(0);
    await expect(editor.getByLabel("Action")).toHaveText("Limit");
    await expect(editor.getByLabel("Download ceiling")).toHaveValue("7.5");
    await expect(editor.getByLabel("Upload ceiling")).toHaveValue("1.5");
    await expect(
      editor.getByText("Client total · Both directions"),
    ).toBeVisible();

    await editor.getByRole("tab", { name: "Advanced YAML" }).click();
    await expect(yaml).toHaveValue(/priority: 275/);
    await expect(yaml).toHaveValue(/download_bps: 7500000/);
    await expect(yaml).toHaveValue(/upload_bps: 1500000/);
    await expect(yaml).toHaveValue(/min_application_confidence: 0.9/);
    await expect(yaml).toHaveValue(/scope: agent/);
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();
    const creation = page.waitForRequest(
      (request) =>
        request.method() === "POST" &&
        new URL(request.url()).pathname === "/api/policies",
    );
    await editor.getByRole("button", { name: "Save", exact: true }).click();
    expect((await creation).postDataJSON().network.scope).toBe("agent");
    const row = page.getByRole("row", { name: /YAML round-trip policy/ });
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    const reopened = page.getByRole("dialog", { name: "Edit traffic policy" });
    await expect(reopened.getByLabel("Download ceiling")).toHaveValue("7.5");
    await expect(
      reopened.getByText("Client total · Both directions"),
    ).toBeVisible();
    await reopened.getByLabel("Description").fill("Updated client total");
    await reopened.getByRole("button", { name: "Validate" }).click();
    await expect(reopened.getByText("Policy is valid")).toBeVisible();
    await reopened.getByRole("button", { name: "Save Changes" }).click();
    const update = page.waitForRequest(
      (request) =>
        request.method() === "PUT" &&
        new URL(request.url()).pathname.startsWith("/api/policies/"),
    );
    await page
      .getByRole("dialog", { name: "Save policy changes?" })
      .getByRole("button", { name: "Save Changes" })
      .click();
    expect((await update).postDataJSON().network.scope).toBe("agent");
  });

  test("selects client-total or Internet scope when visual selectors and actions change", async ({
    page,
  }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "New policy" }).first().click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Policy name").fill("Visual client total");
    const client = editor
      .getByRole("group", { name: "Clients" })
      .getByLabel(/Office Laptop/);
    await client.check();
    const action = editor.getByLabel("Action", { exact: true });
    const selectAction = async (name: string) => {
      await action.click();
      await page.getByRole("option", { name, exact: true }).click();
    };
    const validateScope = async (scope: "agent" | "internet") => {
      const response = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname === "/api/policies/validate",
      );
      await editor.getByRole("button", { name: "Validate" }).click();
      expect((await response).request().postDataJSON().spec.network.scope).toBe(
        scope,
      );
      await expect(editor.getByText("Policy is valid")).toBeVisible();
    };
    await selectAction("Limit");
    await editor.getByLabel("Download ceiling").fill("20");
    await editor.getByLabel("Upload ceiling").fill("5");
    await expect(
      editor.getByText("Client total · Both directions"),
    ).toBeVisible();
    await validateScope("agent");
    const app = editor
      .getByRole("group", { name: "Applications", exact: true })
      .getByLabel("YouTube", { exact: true });
    await app.check();
    await expect(editor.getByText("Internet · Both directions")).toBeVisible();
    await validateScope("internet");
    await app.uncheck();
    await validateScope("agent");
    const category = editor
      .getByRole("group", { name: "Categories", exact: true })
      .getByLabel("Streaming", { exact: true });
    await category.check();
    await validateScope("internet");
    await category.uncheck();
    await validateScope("agent");
    await selectAction("Block");
    await validateScope("internet");
    await selectAction("Allow");
    await validateScope("internet");
    await selectAction("Limit");
    await editor.getByLabel("Download ceiling").fill("20");
    await validateScope("agent");
    await client.uncheck();
    await expect(editor.getByText("Internet · Both directions")).toBeVisible();
    await client.check();
    await validateScope("agent");
  });

  test("rejects Agent scope outside client-only aggregate limits", async ({
    page,
  }) => {
    await openPolicies(page);
    await page.getByRole("button", { name: "New policy" }).first().click();
    const editor = page.getByRole("dialog");
    await editor.getByRole("tab", { name: "Advanced YAML" }).click();
    const yaml = editor.getByLabel("Advanced policy YAML editor");
    const base = {
      schema_version: 1,
      gateway_id: gatewayId,
      name: "Invalid Agent scope",
      description: "",
      enabled: false,
      priority: 500,
      selectors: {
        clients: ["AA:BB:CC:DD:EE:01"],
        applications: [],
        categories: [],
        min_application_confidence: 0.8,
      },
      network: { scope: "agent", direction: "both" },
      action: { type: "limit", download_bps: 20000000, upload_bps: null },
      schedule: null,
    };
    let validations = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/api/policies/validate")
        validations++;
    });
    for (const spec of [
      { ...base, action: { ...base.action, type: "block" } },
      { ...base, action: { ...base.action, type: "allow" } },
      { ...base, selectors: { ...base.selectors, clients: [] } },
      { ...base, selectors: { ...base.selectors, applications: ["youtube"] } },
      { ...base, selectors: { ...base.selectors, categories: ["streaming"] } },
    ]) {
      await yaml.fill(JSON.stringify(spec));
      await editor.getByRole("button", { name: "Validate" }).click();
      await expect(editor.getByRole("alert")).toContainText(
        "The YAML does not match PolicySpecV1.",
      );
      await editor.getByRole("tab", { name: "Visual configuration" }).click();
      await expect(
        editor.getByRole("tab", { name: "Advanced YAML" }),
      ).toHaveAttribute("aria-selected", "true");
    }
    expect(validations).toBe(0);
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
    const creation = page.waitForRequest(
      (request) =>
        request.method() === "POST" &&
        new URL(request.url()).pathname === "/api/policies",
    );
    await createPolicy(page, "Evening TV policy");
    expect(
      (await creation).postDataJSON().selectors.min_application_confidence,
    ).toBe(0.8);
    await expect(
      page.getByRole("button", { name: "Evening TV policy" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Evening TV policy" }).click();
    const details = page.getByRole("dialog");
    await expect(details.getByText("Change history")).toBeVisible();
    await details.getByRole("button", { name: "Close property panel" }).click();

    await page.getByRole("button", { name: "Enable", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Enable policy?" })
      .getByRole("button", { name: "Enable", exact: true })
      .click();
    await expect(
      page
        .getByRole("row", { name: /Evening TV policy/ })
        .getByText("Unsupported", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Desired state enabled and queued for Agent delivery."),
    ).toBeVisible();

    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const editor = page.getByRole("dialog", { name: "Edit traffic policy" });
    await editor.getByLabel("Description").fill("Evening viewing only");
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();
    await editor.getByRole("button", { name: "Save Changes" }).click();
    await page
      .getByRole("dialog", { name: "Save policy changes?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    await expect(
      page.getByRole("dialog", { name: "Save policy changes?" }),
    ).toBeHidden();
    await expect(editor.getByLabel("Description")).toHaveValue(
      "Evening viewing only",
    );
    await expect(
      editor.getByRole("button", { name: "Save Changes" }),
    ).toBeFocused();
    await editor.getByRole("button", { name: "Save Changes" }).click();
    await page.keyboard.press("Escape");
    await expect(editor.getByLabel("Description")).toHaveValue(
      "Evening viewing only",
    );
    await editor.getByRole("button", { name: "Save Changes" }).click();
    await page
      .getByRole("dialog", { name: "Save policy changes?" })
      .getByRole("button", { name: "Save Changes" })
      .click();
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
      overview.getByRole("group", { name: /Last fully applied: r5/ }),
    ).toBeVisible();
  });

  test("localizes policy reason tooltips and preserves unknown diagnostics", async ({
    page,
  }) => {
    await openPolicies(page);
    await createPolicy(page, "Localized policy");
    let reasonCode = "one_arm_icmp_redirects_enabled";
    let reasonMessage =
      "One-arm forwarding is active and ICMP redirects are enabled";
    await page.route("**/api/policies?*", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.data.items = payload.data.items.map((record: PolicyRecord) => ({
        ...record,
        spec: { ...record.spec, enabled: true },
        execution_status: "degraded",
        execution_reason_code: reasonCode,
        execution_message: reasonMessage,
      }));
      await route.fulfill({ response, body: JSON.stringify(payload) });
    });
    await page.route("**/api/policies/deployment?*", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.data.last_error_code = "one_arm_redirects_unsafe";
      payload.data.last_error_message =
        "ICMP redirects must be confirmed disabled";
      await route.fulfill({ response, body: JSON.stringify(payload) });
    });
    await page.getByRole("button", { name: "Refresh", exact: true }).click();

    const row = page.getByRole("row", { name: /Localized policy/ });
    await row.getByText("Degraded", { exact: true }).hover();
    await expect(page.getByRole("tooltip")).toContainText(
      "Clients may learn the upstream gateway and bypass this policy.",
    );
    await expect(page.getByRole("tooltip")).toContainText(reasonCode);

    await page.getByRole("button", { name: "Switch language" }).first().click();
    await page.getByRole("option", { name: "简体中文" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await row.getByText("已降级", { exact: true }).focus();
    await expect(page.getByRole("tooltip")).toContainText(
      "客户端可能学习到上游网关，从而绕过此策略。",
    );
    const deployment = page.getByRole("group", {
      name: "下发状态",
      exact: true,
    });
    await deployment.getByRole("status").hover();
    await expect(
      page.getByRole("tooltip").filter({ hasText: "one_arm_redirects_unsafe" }),
    ).toContainText("必须确认 ICMP 重定向已关闭，才能执行单臂限速。");

    reasonCode = "future_policy_reason";
    reasonMessage = "Diagnostic from a newer Agent";
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    await row.getByText("已降级", { exact: true }).hover();
    await expect(
      page.getByRole("tooltip").filter({ hasText: reasonCode }),
    ).toContainText(reasonMessage);
  });

  test("rejects cross-origin policy mutations at the BFF", async ({ page }) => {
    await openPolicies(page);
    const response = await page
      .context()
      .request.post("/api/policies/validate", {
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
      .request.get("/api/policies?gateway_id=openwrt-dev&page=1&page_size=100");
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
      .request.get("/api/policies?gateway_id=openwrt-dev&page=1&page_size=100");
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
      .request.get("/api/policies?gateway_id=openwrt-dev&page=1&page_size=100");
    const list = await listResponse.json();
    const policy = list.data.items[0];
    const revision = list.data.desired_revision;
    const localEditor = page.getByRole("button", { name: "Edit", exact: true });
    await localEditor.click();
    const editor = page.getByRole("dialog", { name: "Edit traffic policy" });
    await editor.getByLabel("Description").fill("local unsaved draft");
    await editor.getByRole("button", { name: "Validate" }).click();
    await expect(editor.getByText("Policy is valid")).toBeVisible();

    const remoteSpec = {
      ...policy.spec,
      description: "saved by another editor",
    };
    const remoteUpdate = await page
      .context()
      .request.put(`/api/policies/${encodeURIComponent(policy.id)}`, {
        headers: {
          origin: new URL(page.url()).origin,
          "content-type": "application/json",
          "if-match": `"rev:${revision}"`,
          "x-expected-policy-version": String(policy.version),
        },
        data: remoteSpec,
      });
    expect(remoteUpdate.status()).toBe(200);

    await editor.getByRole("button", { name: "Save Changes" }).click();
    await page
      .getByRole("dialog", { name: "Save policy changes?" })
      .getByRole("button", { name: "Save Changes" })
      .click();
    await expect(editor.getByText("Concurrent edit detected")).toBeVisible();
    await expect(
      editor.getByRole("textbox", { name: "Description" }),
    ).toHaveValue("local unsaved draft");
    await expect(editor.getByText("saved by another editor")).toBeVisible();
    await editor.getByRole("button", { name: "Reload server version" }).click();
    await page
      .getByRole("dialog", { name: "Replace local draft?" })
      .getByRole("button", { name: "Cancel" })
      .click();
    await expect(editor.getByLabel("Description")).toHaveValue(
      "local unsaved draft",
    );
    await editor.getByRole("button", { name: "Reload server version" }).click();
    await page
      .getByRole("dialog", { name: "Replace local draft?" })
      .getByRole("button", { name: "Reload server version" })
      .click();
    await expect(editor.getByLabel("Description")).toHaveValue(
      "saved by another editor",
    );
  });
});
