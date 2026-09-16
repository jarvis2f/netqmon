use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::v1::probe_request::Target;
use netqmon_protocol::v1::probe_result::Outcome;
use netqmon_protocol::v1::{ProbeRequest, ProbeResult};

pub(super) fn execute(request: &ProbeRequest) -> ProbeResult {
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let (outcome, status) = match request.target.as_ref() {
        Some(Target::Favicon(target)) => {
            let (result, status) = crate::favicon_probe::execute(target);
            (Some(Outcome::Favicon(result)), status)
        }
        None => (None, "unsupported".to_owned()),
    };
    ProbeResult {
        request_id: request.request_id.clone(),
        observed_at_unix_ms,
        outcome,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netqmon_protocol::v1::FaviconProbe;

    #[test]
    fn generic_envelope_reports_an_unsupported_missing_target() {
        let result = execute(&ProbeRequest {
            request_id: "probe-1".to_owned(),
            target: None,
        });
        assert_eq!(result.request_id, "probe-1");
        assert_eq!(result.status, "unsupported");
        assert!(result.outcome.is_none());
    }

    #[test]
    fn dispatcher_wraps_favicon_outcome_without_changing_correlation_id() {
        let result = execute(&ProbeRequest {
            request_id: "probe-2".to_owned(),
            target: Some(Target::Favicon(FaviconProbe {
                target_ip: vec![8, 8, 8, 8],
                port: 80,
            })),
        });
        assert_eq!(result.request_id, "probe-2");
        assert_eq!(result.status, "invalid_target");
        assert!(matches!(result.outcome, Some(Outcome::Favicon(_))));
    }
}
