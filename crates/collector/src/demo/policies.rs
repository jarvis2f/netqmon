//! Read-only example policies. The demo owns an in-memory repository and never
//! connects these examples to an Agent or persists them in a live policy store.

use serde_json::json;

use crate::CollectorState;
use crate::policy::{PolicyCapabilities, PolicyDeployment, PolicyDetail, PolicyPage, PolicyRecord};
use netqmon_protocol::policy::PolicySpecV1;

pub(crate) fn initialize(state: &CollectorState) -> Result<(), String> {
    if !state.is_demo() {
        return Err("example policies require a demo state".to_owned());
    }
    let (gateway_id, macs) = {
        let inner = state.lock();
        let gateway = inner
            .storage
            .gateway()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "demo database has no gateway".to_owned())?;
        let (_, _, clients, _, _, _, _) =
            super::DemoRealtimeProvider::load_baseline_from_db(inner.storage.connection());
        let macs = clients
            .into_iter()
            .filter_map(|client| client.mac)
            .collect::<Vec<_>>();
        (gateway.id, macs)
    };
    let mac = macs
        .first()
        .ok_or_else(|| "demo database has no client identity".to_owned())?;
    // Initialization is idempotent, including for tests that restart the demo
    // provider while retaining its repository.
    if state
        .policy_service
        .snapshot(&gateway_id)
        .map_err(|error| format!("{error:?}"))?
        .0
        > 0
    {
        return Ok(());
    }
    for (index, (name, action, applications, scope, enabled)) in [
        ("Guest device bandwidth cap", "limit", vec![], "agent", true),
        (
            "Block YouTube on study device",
            "block",
            vec!["youtube"],
            "internet",
            true,
        ),
        (
            "Allow development tools",
            "allow",
            vec!["github"],
            "internet",
            true,
        ),
        (
            "Pause guest internet access",
            "block",
            vec![],
            "internet",
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let client = macs.get(index).unwrap_or(mac);
        let spec: PolicySpecV1 = serde_json::from_value(json!({
            "schema_version": 1,
            "gateway_id": gateway_id,
            "name": name,
            "description": "Read-only example. This policy is not sent to an Agent.",
            "enabled": enabled,
            "priority": 100 + index * 100,
            "selectors": {
                "clients": [client], "applications": applications, "categories": [],
                "min_application_confidence": 0.8
            },
            "network": {"scope": scope, "direction": "both"},
            "action": {
                "type": action,
                "download_bps": if action == "limit" {Some(20_000_000)} else {None},
                "upload_bps": if action == "limit" {Some(5_000_000)} else {None}
            },
            "schedule": null
        }))
        .map_err(|error| error.to_string())?;
        state
            .policy_service
            .create(&spec, "demo", index as u64)
            .map_err(|error| format!("initialize demo policy: {error:?}"))?;
    }
    Ok(())
}

fn capabilities() -> PolicyCapabilities {
    PolicyCapabilities {
        enforcement_supported: false,
        status: "demo".to_owned(),
        reason: "demo_read_only".to_owned(),
        client_block: "demo".to_owned(),
        client_limit: "demo".to_owned(),
        application_block: "demo".to_owned(),
        application_limit: "demo".to_owned(),
    }
}

fn example_status(policy: &mut PolicyRecord) {
    if policy.spec.enabled {
        policy.execution_status = "demo".to_owned();
        policy.execution_reason_code = Some("demo_read_only".to_owned());
        policy.execution_message = None;
    }
}

pub(crate) fn page(mut page: PolicyPage) -> PolicyPage {
    page.items.iter_mut().for_each(example_status);
    page.capabilities = capabilities();
    page
}

pub(crate) fn detail(mut detail: PolicyDetail) -> PolicyDetail {
    example_status(&mut detail.policy);
    detail
}

pub(crate) fn deployment(mut deployment: PolicyDeployment) -> PolicyDeployment {
    deployment.status = "demo".to_owned();
    deployment.capabilities = capabilities();
    // Keep delivery/ACK revisions and connection state truthful: there is no
    // Agent, no fabricated acknowledgement and no claimed runtime enforcement.
    for policy in &mut deployment.policies {
        if policy.status != "disabled" {
            policy.status = "demo".to_owned();
            policy.reason_code = Some("demo_read_only".to_owned());
            policy.message = None;
        }
    }
    deployment
}
