use std::error::Error;
use std::fmt;

use crate::PROTOCOL_VERSION;
use crate::v1::TelemetryBatch;

/// Validates all metadata required for versioning and batch idempotency.
///
/// # Errors
///
/// Returns the first missing field or an unsupported protocol version.
pub fn validate_batch_metadata(batch: &TelemetryBatch) -> Result<(), BatchMetadataError> {
    if batch.gateway_id.is_empty() {
        return Err(BatchMetadataError::MissingGatewayId);
    }
    if batch.boot_id.is_empty() {
        return Err(BatchMetadataError::MissingBootId);
    }
    if batch.sequence == 0 {
        return Err(BatchMetadataError::MissingSequence);
    }
    if batch.sent_at == 0 {
        return Err(BatchMetadataError::MissingSentAt);
    }
    if batch.agent_version.is_empty() {
        return Err(BatchMetadataError::MissingAgentVersion);
    }
    if batch.protocol_version != PROTOCOL_VERSION {
        return Err(BatchMetadataError::UnsupportedProtocolVersion(
            batch.protocol_version,
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchMetadataError {
    MissingGatewayId,
    MissingBootId,
    MissingSequence,
    MissingSentAt,
    MissingAgentVersion,
    UnsupportedProtocolVersion(u32),
}

impl fmt::Display for BatchMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGatewayId => write!(formatter, "gateway_id is required"),
            Self::MissingBootId => write!(formatter, "boot_id is required"),
            Self::MissingSequence => write!(formatter, "sequence must start at one"),
            Self::MissingSentAt => write!(formatter, "sent_at is required"),
            Self::MissingAgentVersion => write!(formatter, "agent_version is required"),
            Self::UnsupportedProtocolVersion(version) => {
                write!(formatter, "unsupported protocol_version {version}")
            }
        }
    }
}

impl Error for BatchMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    type MetadataMutation = (fn(&mut TelemetryBatch), BatchMetadataError);

    fn valid_batch() -> TelemetryBatch {
        TelemetryBatch {
            gateway_id: "gateway-1".to_owned(),
            boot_id: "boot-1".to_owned(),
            sequence: 1,
            sent_at: 1_700_000_000_000,
            agent_version: "0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            ..TelemetryBatch::default()
        }
    }

    #[test]
    fn accepts_complete_batch_metadata() {
        assert_eq!(validate_batch_metadata(&valid_batch()), Ok(()));
    }

    #[test]
    fn rejects_each_missing_or_incompatible_metadata_field() {
        let mutations: Vec<MetadataMutation> = vec![
            (
                |batch| batch.gateway_id.clear(),
                BatchMetadataError::MissingGatewayId,
            ),
            (
                |batch| batch.boot_id.clear(),
                BatchMetadataError::MissingBootId,
            ),
            (
                |batch| batch.sequence = 0,
                BatchMetadataError::MissingSequence,
            ),
            (|batch| batch.sent_at = 0, BatchMetadataError::MissingSentAt),
            (
                |batch| batch.agent_version.clear(),
                BatchMetadataError::MissingAgentVersion,
            ),
            (
                |batch| batch.protocol_version = 2,
                BatchMetadataError::UnsupportedProtocolVersion(2),
            ),
        ];

        for (mutate, expected) in mutations {
            let mut batch = valid_batch();
            mutate(&mut batch);
            assert_eq!(validate_batch_metadata(&batch), Err(expected));
        }
    }
}
