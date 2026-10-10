mod capabilities;
#[cfg(target_os = "linux")]
pub(crate) mod executor;
pub(crate) mod flow_alias;
#[cfg(target_os = "linux")]
pub(crate) mod flow_verdict;
mod identity;
mod mark;
#[cfg(target_os = "linux")]
mod nft;
#[cfg(target_os = "linux")]
mod qdisc;
#[cfg(target_os = "linux")]
pub(crate) mod receiver;
mod schedule;
mod shaper;
mod state;

use crate::config::{AgentConfig, PoliciesAction, PoliciesArgs};

pub(crate) fn handle_command(args: PoliciesArgs, config: &AgentConfig) -> Result<(), String> {
    match args.action {
        PoliciesAction::Status => {
            let status = if args.json {
                serde_json::to_string_pretty(&status_value(config))
                    .map_err(|error| error.to_string())?
            } else {
                let value = status_value(config);
                format!(
                    "Policy revision: {}\nGateway: {}\nClient block: {}\nClient aggregate limit: {}\nLimit reason: {}\nEmergency disabled: {}\nCapability reason: {}\n",
                    value["config_revision"].as_u64().unwrap_or(0),
                    value["gateway_id"].as_str().unwrap_or("unknown"),
                    value["client_block"].as_str().unwrap_or("unsupported"),
                    value["client_limit"].as_str().unwrap_or("unsupported"),
                    value["client_limit_reason"].as_str().unwrap_or("none"),
                    value["emergency_disabled"].as_bool().unwrap_or(false),
                    value["capability_reason"].as_str().unwrap_or("none"),
                )
            };
            print!("{status}");
            Ok(())
        }
        PoliciesAction::Unlock => {
            #[cfg(target_os = "linux")]
            {
                executor::unlock_command(config)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                Err("policy enforcement management requires Linux".to_owned())
            }
        }
        PoliciesAction::Resume => {
            #[cfg(target_os = "linux")]
            {
                executor::restore_command(config)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                Err("policy enforcement management requires Linux".to_owned())
            }
        }
    }
}

fn status_value(config: &AgentConfig) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        executor::status_json(config)
    }
    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({
            "config_revision": 0,
            "gateway_id": serde_json::Value::Null,
            "client_block": "unsupported",
            "client_limit": "unsupported",
            "client_limit_reason_code": "unsupported_topology",
            "client_limit_reason": "policy enforcement is only available on Linux",
            "capability_reason": "policy enforcement is only available on Linux",
            "emergency_disabled": std::path::Path::new(&config.policy_disabled_path).exists(),
            "policy_state_valid": false,
        })
    }
}

pub(crate) fn doctor_text(config: &AgentConfig) -> String {
    capabilities::report_text(config)
}
