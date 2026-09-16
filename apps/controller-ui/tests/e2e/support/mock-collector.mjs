import http from "node:http";

const gatewayId = "openwrt-dev";
const token = "netqmon-e2e-session-token";

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function envelope(data, pagination = null) {
  return { schema_version: 1, data, pagination };
}

function textBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function applicationRows(now) {
  return [
    {
      application_id: "youtube",
      category_id: "streaming",
      organization_id: "google",
      upload_bytes: 64_000_000,
      download_bytes: 860_000_000,
      packets: 18_420,
      flow_count: 12,
      last_seen: now - 4_000,
      client_count: 2,
      confidence: 0.96,
      classifier_reason: "matched domain suffix youtube.com",
      domain_count: 3,
      destination_count: 4,
      observed_protocols: [
        { id: "quic", flows: 7 },
        { id: "https", flows: 5 },
      ],
    },
    {
      application_id: "openai",
      category_id: "ai",
      organization_id: "openai",
      upload_bytes: 11_000_000,
      download_bytes: 44_000_000,
      packets: 3_200,
      flow_count: 5,
      last_seen: now - 8_000,
      client_count: 1,
      confidence: 0.93,
      classifier_reason: "matched DNS attribution for chatgpt.com",
      domain_count: 2,
      destination_count: 2,
      observed_protocols: [{ id: "https", flows: 5 }],
    },
    {
      application_id: "unknown",
      category_id: "communication",
      organization_id: "unknown",
      upload_bytes: 6_000_000,
      download_bytes: 9_000_000,
      packets: 820,
      flow_count: 4,
      last_seen: now - 40_000,
      client_count: 1,
      confidence: 0.2,
      classifier_reason: "",
      domain_count: 0,
      destination_count: 1,
      observed_protocols: [{ id: "https", flows: 4 }],
    },
    {
      application_id: "unknown",
      category_id: "unknown",
      organization_id: "unknown",
      upload_bytes: 2_000_000,
      download_bytes: 1_000_000,
      packets: 310,
      flow_count: 2,
      last_seen: now - 80_000,
      client_count: 1,
      confidence: 0.1,
      classifier_reason: "",
      domain_count: 0,
      destination_count: 1,
      observed_protocols: [{ id: "unknown", flows: 2 }],
    },
  ];
}

function clientRows(now) {
  return [
    {
      id: 101,
      mac: "AA:BB:CC:DD:EE:01",
      ip: "192.168.2.42",
      name: "Office Laptop",
      vendor: "Framework",
      identity: {
        vendor: "Framework",
        device_type: "laptop",
        os_family: "Linux",
        model: null,
        confidence: "medium",
        vendor_confidence: 0.9,
        device_type_confidence: 0.78,
        os_confidence: 0.65,
        model_confidence: 0,
        private_mac: true,
        evidence: [
          {
            source: "mac_oui",
            field: "vendor",
            value: "Framework",
            confidence: 0.9,
            observed_at: now - 3_000,
          },
          {
            source: "dhcp_vendor_class",
            field: "os_family",
            value: "Linux",
            confidence: 0.65,
            observed_at: now - 3_000,
          },
        ],
      },
      last_seen: now - 3_000,
      upload_bytes: 81_000_000,
      download_bytes: 904_000_000,
      flow_count: 19,
    },
    {
      id: 102,
      mac: "AA:BB:CC:DD:EE:02",
      ip: "192.168.2.77",
      name: "Living Room TV",
      vendor: "Sony",
      identity: {
        vendor: "Sony",
        device_type: "smart_tv",
        os_family: null,
        model: null,
        confidence: "medium",
        evidence: [
          {
            source: "mac_oui",
            field: "vendor",
            value: "Sony",
            confidence: 0.9,
            observed_at: now - 11_000,
          },
          {
            source: "hostname",
            field: "device_type",
            value: "smart_tv",
            confidence: 0.7,
            observed_at: now - 11_000,
          },
        ],
      },
      last_seen: now - 11_000,
      upload_bytes: 7_000_000,
      download_bytes: 520_000_000,
      flow_count: 8,
    },
  ];
}

function destinationRows(now) {
  return [
    {
      remote_ip: "142.250.72.238",
      domain: "video.youtube.com",
      application: "youtube",
      country_code: "US",
      country_name: "United States",
      region: "California",
      city: "Mountain View",
      latitude: 37.386,
      longitude: -122.0838,
      asn: 15169,
      organization: "Google LLC",
      upload_bytes: 31_000_000,
      download_bytes: 720_000_000,
      packets: 12_000,
      flow_count: 6,
      client_count: 2,
      last_seen: now - 5_000,
    },
    {
      remote_ip: "104.18.32.47",
      domain: "chatgpt.com",
      country_code: "US",
      country_name: "United States",
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      asn: 13335,
      organization: "Cloudflare",
      upload_bytes: 11_000_000,
      download_bytes: 44_000_000,
      packets: 3_200,
      flow_count: 5,
      client_count: 1,
      last_seen: now - 8_000,
    },
    {
      remote_ip: "203.0.113.10",
      domain: null,
      application: "unknown",
      country_code: null,
      country_name: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      asn: null,
      organization: null,
      upload_bytes: 2_000_000,
      download_bytes: 1_000_000,
      packets: 310,
      flow_count: 1,
      client_count: 1,
      last_seen: now - 80_000,
    },
  ];
}

function domainRows(now, application = null) {
  const rows = [
    {
      domain: "video.youtube.com",
      upload_bytes: 31_000_000,
      download_bytes: 720_000_000,
      packets: 12_000,
      flow_count: 6,
      last_seen: now - 5_000,
    },
    {
      domain: "chatgpt.com",
      upload_bytes: 11_000_000,
      download_bytes: 44_000_000,
      packets: 3_200,
      flow_count: 5,
      last_seen: now - 8_000,
    },
  ];
  return application === "youtube" ? rows.slice(0, 1) : rows;
}

function flowRows(now) {
  return [
    {
      id: "flow-youtube-1",
      client_id: 101,
      client_name: "Office Laptop",
      client_mac: "AA:BB:CC:DD:EE:01",
      client_ip: "192.168.2.42",
      client_port: 53124,
      remote_ip: "142.250.72.238",
      remote_port: 443,
      protocol: 6,
      direction: 2,
      domain: "video.youtube.com",
      organization: "google",
      application: "youtube",
      category: "streaming",
      traffic_role: "video",
      protocol_id: "https",
      organization_confidence: 0.96,
      application_confidence: 0.96,
      protocol_confidence: 0.9,
      confidence: 0.96,
      reason: "matched domain suffix youtube.com",
      evidence: '["dns:video.youtube.com","tls:sni"]',
      upload_bytes: 4_000_000,
      download_bytes: 140_000_000,
      packets: 2_340,
      started_at: now - 120_000,
      last_seen: now - 5_000,
      ended_at: null,
    },
    {
      id: "flow-openai-1",
      client_id: 101,
      client_name: "Office Laptop",
      client_mac: "AA:BB:CC:DD:EE:01",
      client_ip: "192.168.2.42",
      client_port: 53200,
      remote_ip: "104.18.32.47",
      remote_port: 443,
      protocol: 6,
      direction: 1,
      domain: "chatgpt.com",
      organization: "openai",
      application: "openai",
      category: "ai",
      traffic_role: "interactive",
      protocol_id: "https",
      organization_confidence: 0.92,
      application_confidence: 0.93,
      protocol_confidence: 0.9,
      confidence: 0.93,
      reason: "matched DNS attribution for chatgpt.com",
      evidence: '["dns:chatgpt.com"]',
      upload_bytes: 11_000_000,
      download_bytes: 44_000_000,
      packets: 3_200,
      started_at: now - 90_000,
      last_seen: now - 8_000,
      ended_at: null,
    },
    {
      id: "flow-unknown-1",
      client_id: 102,
      client_name: "Living Room TV",
      client_mac: "AA:BB:CC:DD:EE:02",
      client_ip: "192.168.2.77",
      client_port: 49000,
      remote_ip: "203.0.113.10",
      remote_port: 9999,
      protocol: 17,
      direction: 0,
      domain: null,
      organization: "unknown",
      application: "unknown",
      category: "unknown",
      traffic_role: "unknown",
      protocol_id: "unknown",
      organization_confidence: 0,
      application_confidence: 0,
      protocol_confidence: 0,
      confidence: 0,
      reason: "No matching rule",
      evidence: "[]",
      upload_bytes: 2_000_000,
      download_bytes: 1_000_000,
      packets: 310,
      started_at: now - 240_000,
      last_seen: now - 80_000,
      ended_at: now - 60_000,
    },
  ].map((row) => ({
    scope: "internet",
    path_type: "forwarded",
    nat: "snat",
    source_segment: "192.168.2.0/24",
    destination_segment: "internet",
    ...row,
  }));
}

function realtimeSnapshot(now, scenario) {
  const offline = scenario === "offline";
  const hfo = scenario === "hfo";
  const generatedAt = offline ? now - 120_000 : now;
  const internet = {
    upload_bytes_per_second: offline ? 0 : 1_150_000,
    download_bytes_per_second: offline ? 0 : 8_250_000,
  };
  const internal = {
    upload_bytes_per_second: offline ? 0 : 100_000,
    download_bytes_per_second: offline ? 0 : 500_000,
  };
  const zero = { upload_bytes_per_second: 0, download_bytes_per_second: 0 };
  const clientScopes = offline
    ? {}
    : {
        "AA:BB:CC:DD:EE:01": {
          internet: {
            upload_bytes_per_second: 850_000,
            download_bytes_per_second: 6_100_000,
          },
          internal: {
            upload_bytes_per_second: 50_000,
            download_bytes_per_second: 400_000,
          },
          tunnel: zero,
          unknown: zero,
        },
        "AA:BB:CC:DD:EE:02": {
          internet: {
            upload_bytes_per_second: 300_000,
            download_bytes_per_second: 2_150_000,
          },
          internal: {
            upload_bytes_per_second: 50_000,
            download_bytes_per_second: 100_000,
          },
          tunnel: zero,
          unknown: zero,
        },
      };
  return {
    generated_at: generatedAt,
    total: {
      upload_bytes_per_second: offline ? 0 : 1_250_000,
      download_bytes_per_second: offline ? 0 : 8_750_000,
    },
    internet,
    internal,
    tunnel: zero,
    unknown: zero,
    clients: offline
      ? {}
      : {
          "AA:BB:CC:DD:EE:01": {
            upload_bytes_per_second: 900_000,
            download_bytes_per_second: 6_500_000,
          },
          "AA:BB:CC:DD:EE:02": {
            upload_bytes_per_second: 350_000,
            download_bytes_per_second: 2_250_000,
          },
        },
    client_scopes: clientScopes,
    applications: offline
      ? {}
      : {
          youtube: {
            upload_bytes_per_second: 440_000,
            download_bytes_per_second: 6_800_000,
          },
          openai: {
            upload_bytes_per_second: 180_000,
            download_bytes_per_second: 900_000,
          },
        },
    active_flows: offline
      ? []
      : [
          {
            id: "flow-youtube-1",
            client_ip: "192.168.2.42",
            scope: "internet",
          },
          { id: "flow-openai-1", client_ip: "192.168.2.42", scope: "internet" },
        ],
    history: offline
      ? []
      : Array.from({ length: 8 }, (_, index) => ({
          timestamp: now - (7 - index) * 15_000,
          upload_bytes_per_second: 600_000 + index * 25_000,
          download_bytes_per_second: 4_000_000 + index * 400_000,
        })),
    gateway_health: {
      observed_at: generatedAt,
      dropped_batches: 0,
      dns_dropped_events: 0,
      protocol_probe_dropped_events: 0,
      agent_version: "0.1.0-e2e",
      kernel_version: "6.6.54",
      openwrt_version: "23.05.5",
      hardware_flow_offload: hfo ? "enabled" : "disabled",
      capture_interface: "br-lan",
      interface_delta_bytes: hfo ? 800_000_000 : 720_000_000,
      flow_delta_bytes: hfo ? 520_000_000 : 719_500_000,
      interface_counter_sanity: hfo ? "degraded" : "ok",
      topology: {
        topology_mode: "one-arm-router",
        agent_addresses: ["192.168.2.8"],
        upstream_gateway: "192.168.2.1",
        segments: [
          {
            subnet: "192.168.2.0/24",
            interface: "br-lan",
            role: "lan",
            confidence: 95,
          },
        ],
        nat_status: "snat",
        attach_backend: "tcx",
        attach_order: "first",
        ipv4_coverage: "full",
        ipv6_coverage: "partial",
        icmp_redirect: "disabled",
        software_flow_offload: "disabled",
        hardware_flow_offload: hfo ? "enabled" : "disabled",
        topology_warnings: [],
        confidence: 95,
        capture_interface: "br-lan",
      },
    },
  };
}

function gateway(now, scenario) {
  const offline = scenario === "offline";
  const hfo = scenario === "hfo";
  return {
    id: gatewayId,
    name: "OpenWrt Dev Gateway",
    status: offline ? "offline" : "online",
    last_seen: offline ? now - 120_000 : now,
    agent_version: "0.1.0-e2e",
    kernel_version: "6.6.54",
    openwrt_version: "23.05.5",
    offloading_status: hfo ? "enabled" : "disabled",
    capture_interface: "br-lan",
    interface_counter_sanity: hfo ? "degraded" : "ok",
    interface_delta_bytes: hfo ? 800_000_000 : 720_000_000,
    flow_delta_bytes: hfo ? 520_000_000 : 719_500_000,
    capture_warning: offline
      ? "No gateway telemetry has arrived within the offline threshold"
      : hfo
        ? "Capture degraded: hardware flow offloading is enabled; interface counters exceeded captured flow deltas (800000000B interface, 520000000B flows)"
        : null,
    offline_after_ms: 30_000,
  };
}

function filterFlows(rows, params) {
  const search = params.get("search")?.toLowerCase();
  const client = params.get("client")?.toLowerCase();
  const application = params.get("application")?.toLowerCase();
  const domain = params.get("domain")?.toLowerCase();
  const ip = params.get("ip")?.toLowerCase();
  const protocol = params.get("protocol")?.toLowerCase();
  const port = params.get("port");
  const direction = params.get("direction")?.toLowerCase();
  const scope = params.get("scope")?.toLowerCase();
  const pathType = params.get("path_type")?.toLowerCase();
  const nat = params.get("nat")?.toLowerCase();
  return rows.filter((row) => {
    if (
      search &&
      ![
        row.client_ip,
        row.remote_ip,
        row.domain,
        row.client_name,
        row.application,
      ].some((value) => value?.toLowerCase().includes(search))
    )
      return false;
    if (
      client &&
      ![
        String(row.client_id),
        row.client_ip,
        row.client_name?.toLowerCase(),
        row.client_mac?.toLowerCase(),
      ].includes(client)
    )
      return false;
    if (application && row.application.toLowerCase() !== application)
      return false;
    if (domain && row.domain?.toLowerCase() !== domain) return false;
    if (
      ip &&
      row.remote_ip.toLowerCase() !== ip &&
      row.client_ip.toLowerCase() !== ip
    )
      return false;
    if (
      protocol &&
      !(
        (protocol === "tcp" && row.protocol === 6) ||
        (protocol === "udp" && row.protocol === 17)
      )
    )
      return false;
    if (
      port &&
      String(row.remote_port) !== port &&
      String(row.client_port) !== port
    )
      return false;
    if (
      direction &&
      !(
        (direction === "upload" && row.direction === 1) ||
        (direction === "download" && row.direction === 2) ||
        (direction === "unknown" && row.direction === 0)
      )
    )
      return false;
    if (scope && row.scope !== scope) return false;
    if (pathType && row.path_type !== pathType) return false;
    if (nat && row.nat !== nat) return false;
    return true;
  });
}

function writeSse(response, event, data) {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(data)}\n\n`);
}

function handleInternal(request, response, pathname, params, state) {
  const now = Date.now();
  const scenario = state.scenario;
  const path = pathname.replace(/^\/internal\/?/, "");

  if (path === "settings/diagnostics" && request.method === "GET") {
    json(
      response,
      200,
      envelope({
        collector_version: "0.1.0-beta.8",
        analytics_backend: "duckdb",
        metadata_database_size_bytes: 1048576,
        analytics_database_size_bytes: 2097152,
        analytics_outbox_depth: 0,
        analytics_outbox_oldest_age_ms: 0,
        analytics_last_success_at: now,
        analytics_last_error: null,
        gateway: null,
        active_flow_count: 4,
        unknown_ratio: 0.1,
        geo_enabled: false,
        topology: realtimeSnapshot(Date.now(), state.scenario).gateway_health
          .topology,
        retention: {
          flow_sessions_days: 7,
          dns_days: 7,
          minute_days: 7,
          hour_days: 30,
          day_days: 365,
        },
        sampling: {
          engine: "ndpi",
          enabled: true,
          available: true,
          window_seconds: 3600,
          configs: [
            {
              gateway_id: gatewayId,
              enabled: true,
              max_bytes_per_flow: 4096,
              max_packets_per_direction: 4,
              max_bytes_per_packet: 1024,
            },
          ],
          sample_count: 9730,
          packet_count: 20000,
          sampled_flows: 9000,
          sample_bytes: 21400000,
          average_sample_bytes: 2199.38,
          p95_sample_bytes: 4096,
          max_sample_bytes: 4096,
          dpi_success_rate: 0.8,
          sample_drops: 10,
          sample_drop_rate: 0.0005,
          new_flows: 18240,
          new_flows_per_second: 5.0667,
          network_bytes: 26750000000,
          bandwidth_kbps: 47.56,
          traffic_ratio: 0.0008,
          theoretical_max_kbps: 166.0245,
          impact: "Low",
        },
      }),
    );
    return true;
  }
  if (path === "settings/license" && request.method === "GET") {
    state.license = state.license || {
      installation_id: "00000000-0000-0000-0000-000000000001",
      activated: false,
      edition: "community",
      license_status: "unlicensed",
      rule_version: "2026.09.01",
      lease_valid_until: null,
      last_success_at: null,
      last_error: null,
    };
    json(response, 200, envelope(state.license));
    return true;
  }
  if (path === "settings/license/activate" && request.method === "POST") {
    textBody(request).then((raw) => {
      let body = {};
      try {
        body = JSON.parse(raw || "{}");
      } catch {}
      if (!body.license_key || body.license_key === "invalid-key") {
        json(response, 400, {
          schema_version: 1,
          error: { message: "Invalid license key" },
        });
        return;
      }
      state.license = {
        installation_id: "00000000-0000-0000-0000-000000000001",
        activated: true,
        edition: "pro",
        license_status: "active",
        rule_version: "2026.09.08-pro",
        lease_valid_until: Math.floor(Date.now() / 1000) + 86400,
        last_success_at: Math.floor(Date.now() / 1000),
        last_error: null,
      };
      json(response, 200, envelope(state.license));
    });
    return true;
  }
  if (path === "settings/license/check" && request.method === "POST") {
    if (!state.license || !state.license.activated) {
      json(response, 502, {
        schema_version: 1,
        error: { message: "No active license" },
      });
      return true;
    }
    state.license.last_success_at = Math.floor(Date.now() / 1000);
    json(response, 200, envelope(state.license));
    return true;
  }
  if (path === "auth/status" && request.method === "GET") {
    json(response, 200, envelope({ setup_required: false }));
    return true;
  }
  if (path === "auth/login" && request.method === "POST") {
    textBody(request)
      .then(() => {
        json(
          response,
          200,
          envelope({
            session_token: token,
            expires_at: now + 7 * 24 * 60 * 60 * 1_000,
            user: { id: "admin", username: "admin" },
          }),
        );
      })
      .catch(() =>
        json(response, 400, {
          schema_version: 1,
          error: { message: "invalid request" },
        }),
      );
    return true;
  }
  if (path === "auth/verify" && request.method === "POST") {
    const authorized = request.headers.authorization === `Bearer ${token}`;
    json(
      response,
      authorized ? 200 : 401,
      authorized
        ? envelope({ user: { id: "admin", username: "admin" } })
        : { schema_version: 1, error: { message: "unauthorized" } },
    );
    return true;
  }
  if (path === "auth/logout" && request.method === "POST") {
    response.writeHead(204);
    response.end();
    return true;
  }
  if (path === "realtime/stream" && request.method === "GET") {
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    writeSse(response, "snapshot", realtimeSnapshot(now, scenario));
    writeSse(response, "gateway_status", {
      status: scenario === "offline" ? "offline" : "online",
      gateway_id: gatewayId,
    });
    const timer = setInterval(
      () =>
        writeSse(
          response,
          "snapshot",
          realtimeSnapshot(Date.now(), state.scenario),
        ),
      1_000,
    );
    request.on("close", () => clearInterval(timer));
    return true;
  }
  if (path === "overview" && request.method === "GET") {
    json(
      response,
      200,
      envelope({
        gateway_status: scenario === "offline" ? "offline" : "online",
        realtime: realtimeSnapshot(now, scenario),
        device_count: clientRows(now).length,
        gateway: gateway(now, scenario),
      }),
    );
    return true;
  }
  if (path === "applications" && request.method === "GET") {
    json(response, 200, envelope(applicationRows(now)));
    return true;
  }
  if (path === "insights" && request.method === "GET") {
    json(
      response,
      200,
      envelope([
        {
          id: "insight-nested-evidence",
          category: "classification",
          code: "classification.unknown_ratio_high",
          severity: "warning",
          time: now - 5_000,
          source: "traffic_analysis",
          affected_client: null,
          params: {
            ratio: 0.25,
            unknown_bytes: 250,
            total_bytes: 1_000,
            threshold: 0.2,
          },
          evidence: {
            ratio: 0.25,
            details: { protocols: ["quic", "https"], sampled: true },
          },
        },
      ]),
    );
    return true;
  }
  if (path.startsWith("applications/") && request.method === "GET") {
    const [, encodedId, relation] = path.split("/");
    const id = decodeURIComponent(encodedId);
    const category = params.get("category");
    const app =
      applicationRows(now).find(
        (row) =>
          row.application_id === id &&
          (!category || row.category_id === category),
      ) ?? applicationRows(now)[2];
    if (!relation) json(response, 200, envelope(app));
    else if (relation === "traffic")
      json(
        response,
        200,
        envelope({
          bucket_ms: 60_000,
          points: realtimeSnapshot(now, scenario).history.map((point) => ({
            timestamp: point.timestamp,
            upload_bytes: 600_000,
            download_bytes: 4_000_000,
          })),
        }),
      );
    else if (relation === "clients")
      json(
        response,
        200,
        envelope(clientRows(now).slice(0, id === "youtube" ? 2 : 1)),
      );
    else if (relation === "domains")
      json(response, 200, envelope(domainRows(now, id)));
    else if (relation === "destinations")
      json(
        response,
        200,
        envelope(
          id === "unknown"
            ? destinationRows(now).filter(
                (row) => row.application === "unknown",
              )
            : destinationRows(now).slice(0, id === "youtube" ? 1 : 2),
        ),
      );
    else if (relation === "flows")
      json(
        response,
        200,
        envelope(flowRows(now).filter((row) => row.application === id)),
      );
    else
      json(response, 404, {
        schema_version: 1,
        error: { message: "not found" },
      });
    return true;
  }
  if (path === "clients" && request.method === "GET") {
    json(response, 200, envelope(clientRows(now)));
    return true;
  }
  if (path.startsWith("clients/") && request.method === "GET") {
    const [, id, relation] = path.split("/");
    const client =
      clientRows(now).find((row) => String(row.id) === id) ??
      clientRows(now)[0];
    if (!relation)
      json(
        response,
        200,
        envelope({
          client: { ...client, first_seen: now - 86_400_000 },
          addresses: [
            {
              ip: client.ip,
              ip_version: client.ip?.includes(":") ? 6 : 4,
              first_seen: now - 86_400_000,
              last_seen: client.last_seen,
            },
          ],
        }),
      );
    else if (relation === "traffic")
      json(
        response,
        200,
        envelope({
          bucket_ms: 60_000,
          points: realtimeSnapshot(now, scenario).history.map((point) => ({
            timestamp: point.timestamp,
            upload_bytes: 700_000,
            download_bytes: 5_000_000,
          })),
        }),
      );
    else if (relation === "applications")
      json(
        response,
        200,
        envelope(applicationRows(now).slice(0, client.id === 101 ? 2 : 1)),
      );
    else if (relation === "domains")
      json(response, 200, envelope(domainRows(now)));
    else if (relation === "destinations")
      json(response, 200, envelope(destinationRows(now)));
    else if (relation === "flows")
      json(
        response,
        200,
        envelope(flowRows(now).filter((row) => row.client_id === client.id)),
      );
    else
      json(response, 404, {
        schema_version: 1,
        error: { message: "not found" },
      });
    return true;
  }
  if (path === "traffic" && request.method === "GET") {
    const groupBy = params.get("group_by") ?? "none";
    json(
      response,
      200,
      envelope({
        from: Number(params.get("from") ?? now - 86_400_000),
        to: Number(params.get("to") ?? now),
        bucket_ms: 60_000,
        group_by: groupBy,
        points: realtimeSnapshot(now, scenario).history.map((point) => ({
          timestamp: point.timestamp,
          upload_bytes: 500_000,
          download_bytes: 3_000_000,
          packets: 1_200,
          flow_count: 8,
        })),
        breakdown: [
          {
            id: "1",
            name: "Office Laptop",
            mac: "00:11:22:33:44:55",
            upload_bytes: 20_000_000,
            download_bytes: 120_000_000,
            packets: 45_000,
            flow_count: 24,
            last_seen: now - 30_000,
          },
        ],
      }),
    );
    return true;
  }
  if (path === "destinations" && request.method === "GET") {
    const rows = destinationRows(now);
    const limit = Number(params.get("limit") ?? "50");
    const offset = Number(params.get("offset") ?? "0");
    json(
      response,
      200,
      envelope(rows.slice(offset, offset + limit), {
        limit,
        offset,
        total: rows.length,
      }),
    );
    return true;
  }
  if (path === "flows" && request.method === "GET") {
    const rows = filterFlows(flowRows(now), params);
    const limit = Number(params.get("limit") ?? "50");
    json(
      response,
      200,
      envelope(rows.slice(0, limit), {
        limit,
        next_cursor: rows.length > limit ? "next" : null,
        sort: params.get("sort") ?? "last_seen",
        order: params.get("order") ?? "desc",
      }),
    );
    return true;
  }
  return false;
}

export function createMockCollectorServer() {
  const state = { scenario: "live" };
  return http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname.startsWith("/__scenario/") && request.method === "POST") {
      const scenario = url.pathname.split("/").pop();
      state.scenario = ["live", "offline", "hfo"].includes(scenario)
        ? scenario
        : "live";
      state.license = {
        installation_id: "00000000-0000-0000-0000-000000000001",
        activated: false,
        edition: "community",
        license_status: "unlicensed",
        rule_version: "2026.09.01",
        lease_valid_until: null,
        last_success_at: null,
        last_error: null,
      };
      json(response, 200, envelope({ scenario: state.scenario }));
      return;
    }
    if (
      url.pathname.startsWith("/internal/") &&
      handleInternal(request, response, url.pathname, url.searchParams, state)
    )
      return;
    json(response, 404, { schema_version: 1, error: { message: "not found" } });
  });
}
