//! Pure packet observation: no protocol detection or payload logging.
use crate::{
    conntrack::ConntrackContext,
    flow::{FLOW_KEY_SIZE, FlowKey, policy_flow_id},
    normalization::{Direction, FlowScope, NetworkContext, normalize},
    telemetry::ip_bytes,
};
use netqmon_protocol::v1::{Direction as WireDirection, FlowSample, FlowSampleKey, SamplePacket};

pub const SAMPLE_EVENT_SIZE: usize = 4176;
const SAMPLE_EVENT_HEADER_SIZE: usize = 80;

/// Decode metadata first; allocate/copy payload only for eligible observations.
pub fn decode_sample(
    bytes: &[u8],
    network: &NetworkContext,
    boot_epoch_ms: u64,
    enabled: bool,
    excluded: &[std::net::SocketAddr],
    conntrack: &ConntrackContext,
    boot_id: &str,
    policy_ids_enabled: bool,
) -> Option<FlowSample> {
    if !enabled || bytes.len() < SAMPLE_EVENT_HEADER_SIZE {
        return None;
    }
    let key = FlowKey::try_from(&bytes[..FLOW_KEY_SIZE]).ok()?;
    let flow = normalize(&key, network, conntrack)?;
    if flow.scope != FlowScope::Client {
        return None;
    }
    if excluded
        .iter()
        .any(|address| address.ip() == flow.remote_addr && address.port() == flow.remote_port)
    {
        return None;
    }
    let direction = match flow.direction {
        Direction::Upload => WireDirection::Upload,
        Direction::Download => WireDirection::Download,
        _ => return None,
    };
    let original_length = u32::from_ne_bytes(bytes[44..48].try_into().ok()?);
    let timestamp_ns = u64::from_ne_bytes(bytes[48..56].try_into().ok()?);
    let first_seen_ns = u64::from_ne_bytes(bytes[56..64].try_into().ok()?);
    let flow_first_seen_ns = u64::from_ne_bytes(bytes[64..72].try_into().ok()?);
    let captured_length = u32::from_ne_bytes(bytes[72..76].try_into().ok()?);
    let captured_length_usize = usize::try_from(captured_length).ok()?;
    if captured_length == 0
        || captured_length > 4096
        || captured_length > original_length
        || timestamp_ns < first_seen_ns
        || captured_length_usize > bytes.len().saturating_sub(SAMPLE_EVENT_HEADER_SIZE)
    {
        return None;
    }
    Some(FlowSample {
        flow_id: format!(
            "{}:{}-{}:{}-{}-{first_seen_ns}",
            flow.client_addr, flow.client_port, flow.remote_addr, flow.remote_port, key.protocol
        ),
        policy_flow_id: if policy_ids_enabled {
            policy_flow_id(boot_id, &key, flow_first_seen_ns)
        } else {
            String::new()
        },
        key: Some(FlowSampleKey {
            ip_version: u32::from(key.ip_version),
            protocol: u32::from(key.protocol),
            client_ip: ip_bytes(flow.client_addr),
            client_port: u32::from(flow.client_port),
            remote_ip: ip_bytes(flow.remote_addr),
            remote_port: u32::from(flow.remote_port),
            first_seen_unix_ms: boot_epoch_ms.saturating_add(first_seen_ns / 1_000_000),
        }),
        packets: vec![SamplePacket {
            direction: direction.into(),
            timestamp_unix_ms: boot_epoch_ms.saturating_add(timestamp_ns / 1_000_000),
            original_length,
            captured_length,
            payload: bytes
                [SAMPLE_EVENT_HEADER_SIZE..SAMPLE_EVENT_HEADER_SIZE + captured_length_usize]
                .to_vec(),
        }],
        total_captured_bytes: captured_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> (Vec<u8>, NetworkContext) {
        let mut bytes = vec![0; SAMPLE_EVENT_SIZE];
        bytes[0] = 4;
        bytes[1] = 17;
        bytes[8..12].copy_from_slice(&[192, 168, 1, 2]);
        bytes[24..28].copy_from_slice(&[8, 8, 8, 8]);
        bytes[40..42].copy_from_slice(&50000u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&443u16.to_be_bytes());
        bytes[44..48].copy_from_slice(&100u32.to_ne_bytes());
        bytes[48..56].copy_from_slice(&2_000_000u64.to_ne_bytes());
        bytes[56..64].copy_from_slice(&1_000_000u64.to_ne_bytes());
        bytes[64..72].copy_from_slice(&1_000_000u64.to_ne_bytes());
        bytes[72..76].copy_from_slice(&64u32.to_ne_bytes());
        bytes[80] = 0x45;
        let mut network = NetworkContext::default();
        network
            .add_interface_address("192.168.1.1".parse().unwrap(), 24)
            .unwrap();
        (bytes, network)
    }
    #[test]
    fn disabled_and_collector_traffic_never_produce_payload() {
        let (bytes, network) = event();
        assert!(
            decode_sample(
                &bytes,
                &network,
                1000,
                false,
                &[],
                &ConntrackContext::default(),
                "test-boot",
                false,
            )
            .is_none()
        );
        assert!(
            decode_sample(
                &bytes,
                &network,
                1000,
                true,
                &["8.8.8.8:443".parse().unwrap()],
                &ConntrackContext::default(),
                "test-boot",
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn router_local_traffic_never_produces_a_sample() {
        let (mut bytes, network) = event();
        bytes[8..12].copy_from_slice(&[192, 168, 1, 1]);
        assert!(
            decode_sample(
                &bytes,
                &network,
                1000,
                true,
                &[],
                &ConntrackContext::default(),
                "test-boot",
                false,
            )
            .is_none()
        );
    }
    #[test]
    fn sample_identity_uses_the_exact_flow_lifetime_key() {
        let (mut bytes, network) = event();
        let upload_key = FlowKey::try_from(&bytes[..FLOW_KEY_SIZE]).unwrap();
        let upload = decode_sample(
            &bytes,
            &network,
            1000,
            true,
            &[],
            &ConntrackContext::default(),
            "test-boot",
            true,
        )
        .unwrap();
        for i in 0..16 {
            bytes.swap(8 + i, 24 + i);
        }
        for i in 0..2 {
            bytes.swap(40 + i, 42 + i);
        }
        let download = decode_sample(
            &bytes,
            &network,
            1000,
            true,
            &[],
            &ConntrackContext::default(),
            "test-boot",
            true,
        )
        .unwrap();
        assert_eq!(upload.flow_id, download.flow_id);
        assert_ne!(upload.policy_flow_id, download.policy_flow_id);
        let raw_key = FlowKey::try_from(&bytes[..FLOW_KEY_SIZE]).unwrap();
        assert_eq!(
            download.policy_flow_id,
            policy_flow_id("test-boot", &raw_key, 1_000_000)
        );
        assert_eq!(
            upload.policy_flow_id,
            policy_flow_id("test-boot", &upload_key, 1_000_000)
        );
        assert_ne!(upload.policy_flow_id, download.policy_flow_id);
        assert_eq!(upload.key, download.key);
        assert_ne!(upload.packets[0].direction, download.packets[0].direction);
        assert_eq!(upload.packets[0].timestamp_unix_ms, 1002);
        assert_eq!(upload.total_captured_bytes, 64);
    }

    #[test]
    fn decodes_ring_record_with_only_captured_payload() {
        let (mut bytes, network) = event();
        bytes.truncate(SAMPLE_EVENT_HEADER_SIZE + 64);
        let decoded = decode_sample(
            &bytes,
            &network,
            1000,
            true,
            &[],
            &ConntrackContext::default(),
            "test-boot",
            true,
        )
        .unwrap();
        assert_eq!(decoded.packets[0].payload.len(), 64);
    }
}
