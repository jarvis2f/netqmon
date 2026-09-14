//! Bounded, memory-only packet sample wire validation.
use std::{collections::HashSet, error::Error, fmt};

use crate::{
    BatchMetadataError,
    v1::{Direction, FlowSampleBatch, SamplePacket, TelemetryBatch},
    validate_batch_metadata,
};

/// Default capture budget, shared by future Agent and Collector configuration.
pub const DEFAULT_SAMPLE_BYTES_PER_FLOW: u32 = 4096;
pub const DEFAULT_SAMPLE_PACKETS_PER_DIRECTION: u32 = 4;
pub const DEFAULT_SAMPLE_BYTES_PER_PACKET: u32 = 1024;
/// Hard protocol ceilings; deployment configuration may impose lower limits.
pub const MAX_SAMPLE_BYTES_PER_FLOW: u32 = 65536;
pub const MAX_SAMPLE_PACKETS_PER_DIRECTION: usize = 32;
pub const MAX_SAMPLE_BYTES_PER_PACKET: u32 = 4096;
pub const MAX_SAMPLES_PER_BATCH: usize = 128;

impl fmt::Debug for SamplePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamplePacket")
            .field("direction", &self.direction)
            .field("timestamp_unix_ms", &self.timestamp_unix_ms)
            .field("original_length", &self.original_length)
            .field("captured_length", &self.captured_length)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SampleValidationError {
    Metadata(BatchMetadataError),
    Invalid(&'static str),
}

impl fmt::Display for SampleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(error) => write!(f, "{error}"),
            Self::Invalid(reason) => write!(f, "invalid flow sample: {reason}"),
        }
    }
}
impl Error for SampleValidationError {}

/// Validates envelope metadata, tuples, packet boundaries and hard limits.
/// Each flow appears at most once per batch. Receivers must additionally enforce
/// cumulative capture budgets across batches for each gateway/boot/flow ID.
///
/// # Errors
/// Rejects malformed metadata, lengths, directions, tuples and oversized samples.
pub fn validate_flow_sample_batch(batch: &FlowSampleBatch) -> Result<(), SampleValidationError> {
    validate_batch_metadata(&TelemetryBatch {
        gateway_id: batch.gateway_id.clone(),
        boot_id: batch.boot_id.clone(),
        sequence: batch.sequence,
        sent_at: batch.sent_at,
        agent_version: batch.agent_version.clone(),
        protocol_version: batch.protocol_version,
        ..TelemetryBatch::default()
    })
    .map_err(SampleValidationError::Metadata)?;
    let invalid = SampleValidationError::Invalid;
    if batch.samples.is_empty() || batch.samples.len() > MAX_SAMPLES_PER_BATCH {
        return Err(invalid("batch sample count"));
    }
    let mut ids = HashSet::new();
    for sample in &batch.samples {
        if sample.flow_id.is_empty() || sample.flow_id.len() > 128 || !ids.insert(&sample.flow_id) {
            return Err(invalid("missing, oversized or duplicate flow ID"));
        }
        let key = sample.key.as_ref().ok_or(invalid("missing flow key"))?;
        let ip_len = match key.ip_version {
            4 => 4,
            6 => 16,
            _ => return Err(invalid("IP version")),
        };
        if key.client_ip.len() != ip_len
            || key.remote_ip.len() != ip_len
            || key.protocol == 0
            || key.protocol > 255
            || key.client_port > 65535
            || key.remote_port > 65535
            || key.first_seen_unix_ms == 0
        {
            return Err(invalid("flow key"));
        }
        if sample.packets.is_empty() || sample.packets.len() > 2 * MAX_SAMPLE_PACKETS_PER_DIRECTION
        {
            return Err(invalid("packet count"));
        }
        let mut counts = [0; 2];
        let mut total = 0u32;
        for packet in &sample.packets {
            let direction = match Direction::try_from(packet.direction) {
                Ok(Direction::Upload) => 0,
                Ok(Direction::Download) => 1,
                _ => return Err(invalid("packet direction")),
            };
            counts[direction] += 1;
            if counts[direction] > MAX_SAMPLE_PACKETS_PER_DIRECTION {
                return Err(invalid("direction packet limit"));
            }
            if packet.timestamp_unix_ms < key.first_seen_unix_ms
                || packet.captured_length == 0
                || packet.captured_length > MAX_SAMPLE_BYTES_PER_PACKET
                || packet.captured_length > packet.original_length
                || packet.payload.len() != packet.captured_length as usize
            {
                return Err(invalid("packet timestamp or length"));
            }
            if u32::from(packet.payload[0] >> 4) != key.ip_version {
                return Err(invalid("packet IP version"));
            }
            total += packet.captured_length;
        }
        if total > MAX_SAMPLE_BYTES_PER_FLOW || total != sample.total_captured_bytes {
            return Err(invalid("flow byte limit or total"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContentEncoding, PROTOCOL_VERSION, decode_flow_sample_batch, encode_flow_sample_batch,
        v1::{FlowSample, FlowSampleKey},
    };

    fn batch(ip_version: u32) -> FlowSampleBatch {
        let size = if ip_version == 4 { 4 } else { 16 };
        let packet = SamplePacket {
            direction: Direction::Upload.into(),
            timestamp_unix_ms: 100,
            original_length: 1500,
            captured_length: 1024,
            payload: vec![u8::try_from(ip_version).unwrap() << 4; 1024],
        };
        FlowSampleBatch {
            gateway_id: "gateway-a".into(),
            boot_id: "boot-a".into(),
            sequence: 1,
            sent_at: 101,
            agent_version: "test".into(),
            protocol_version: PROTOCOL_VERSION,
            samples: vec![FlowSample {
                flow_id: "flow-1".into(),
                key: Some(FlowSampleKey {
                    ip_version,
                    protocol: 17,
                    client_ip: vec![1; size],
                    client_port: 50000,
                    remote_ip: vec![2; size],
                    remote_port: 443,
                    first_seen_unix_ms: 100,
                }),
                packets: vec![
                    packet.clone(),
                    SamplePacket {
                        direction: Direction::Download.into(),
                        ..packet
                    },
                ],
                total_captured_bytes: 2048,
            }],
        }
    }

    #[test]
    fn bidirectional_ipv4_ipv6_roundtrip_with_both_encodings() {
        for version in [4, 6] {
            for threshold in [0, usize::MAX] {
                let original = batch(version);
                assert_eq!(validate_flow_sample_batch(&original), Ok(()));
                let encoded = encode_flow_sample_batch(&original, threshold).unwrap();
                let decoded = decode_flow_sample_batch(&encoded.body, encoded.encoding).unwrap();
                assert_eq!(decoded, original);
            }
        }
    }

    #[test]
    fn rejects_malformed_metadata_and_packets() {
        let mutations: Vec<fn(&mut FlowSampleBatch)> = vec![
            |b| b.gateway_id.clear(),
            |b| b.boot_id.clear(),
            |b| b.sequence = 0,
            |b| b.protocol_version = 999,
            |b| b.samples.clear(),
            |b| b.samples.push(b.samples[0].clone()),
            |b| b.samples[0].flow_id.clear(),
            |b| b.samples[0].key = None,
            |b| b.samples[0].key.as_mut().unwrap().remote_ip.clear(),
            |b| b.samples[0].key.as_mut().unwrap().client_port = 65536,
            |b| b.samples[0].packets.clear(),
            |b| b.samples[0].packets[0].direction = 99,
            |b| b.samples[0].packets[0].timestamp_unix_ms = 99,
            |b| b.samples[0].packets[0].captured_length = 0,
            |b| b.samples[0].packets[0].original_length = 1,
            |b| b.samples[0].packets[0].payload.pop().map(|_| ()).unwrap(),
            |b| b.samples[0].packets[0].payload[0] = 0x60,
            |b| b.samples[0].total_captured_bytes += 1,
        ];
        for mutate in mutations {
            let mut candidate = batch(4);
            mutate(&mut candidate);
            assert!(validate_flow_sample_batch(&candidate).is_err());
        }
    }

    #[test]
    fn enforces_direction_and_byte_ceilings() {
        let mut candidate = batch(4);
        let packet = candidate.samples[0].packets[0].clone();
        candidate.samples[0].packets = vec![packet.clone(); 32];
        candidate.samples[0].total_captured_bytes = 32768;
        assert!(validate_flow_sample_batch(&candidate).is_ok());
        candidate.samples[0].packets.push(packet);
        candidate.samples[0].total_captured_bytes += 1024;
        assert!(validate_flow_sample_batch(&candidate).is_err());
        let mut candidate = batch(4);
        for packet in &mut candidate.samples[0].packets {
            packet.payload.resize(4096, 0);
            packet.captured_length = 4096;
            packet.original_length = 4096;
        }
        candidate.samples[0].packets = candidate.samples[0]
            .packets
            .iter()
            .cycle()
            .take(16)
            .cloned()
            .collect();
        candidate.samples[0].total_captured_bytes = 65536;
        assert!(validate_flow_sample_batch(&candidate).is_ok());
        let extra = candidate.samples[0].packets[0].clone();
        candidate.samples[0].packets.push(extra);
        candidate.samples[0].total_captured_bytes += 4096;
        assert!(validate_flow_sample_batch(&candidate).is_err());
    }

    #[test]
    fn debug_redacts_nested_payload() {
        let mut candidate = batch(4);
        candidate.samples[0].packets[0].payload = b"PRIVATE_PAYLOAD".to_vec();
        let output = format!("{candidate:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("PRIVATE_PAYLOAD"));
        assert!(!output.contains("80, 82, 73"));
    }

    #[test]
    fn rejects_malformed_and_oversized_wire_data() {
        assert!(decode_flow_sample_batch(&[0xff], ContentEncoding::Identity).is_err());
        let oversized = vec![0; 16 * 1024 * 1024 + 1];
        for encoding in [ContentEncoding::Identity, ContentEncoding::Zstd] {
            let body = if encoding == ContentEncoding::Zstd {
                zstd::stream::encode_all(oversized.as_slice(), 1).unwrap()
            } else {
                oversized.clone()
            };
            assert!(matches!(
                decode_flow_sample_batch(&body, encoding),
                Err(crate::DecodeError::TooLarge)
            ));
        }
    }
}
