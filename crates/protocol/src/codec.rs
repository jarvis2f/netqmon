use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read};

use prost::Message;

use crate::v1::{FlowSampleBatch, TelemetryBatch};

const ZSTD_LEVEL: i32 = 3;
const MAX_DECODED_BATCH_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ContentEncoding {
    #[default]
    Identity,
    Zstd,
}

impl ContentEncoding {
    #[must_use]
    pub const fn http_value(self) -> Option<&'static str> {
        match self {
            Self::Identity => None,
            Self::Zstd => Some("zstd"),
        }
    }

    /// Parses an HTTP `Content-Encoding` value used by telemetry ingestion.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnsupportedEncoding`] for encodings other than
    /// `identity` and `zstd`.
    pub fn from_http_value(value: Option<&str>) -> Result<Self, DecodeError> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some("identity") => Ok(Self::Identity),
            Some("zstd") => Ok(Self::Zstd),
            Some(value) => Err(DecodeError::UnsupportedEncoding(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedTelemetryBatch {
    pub body: Vec<u8>,
    pub encoding: ContentEncoding,
}

/// Encodes a protobuf batch and applies zstd at or above the supplied threshold.
///
/// # Errors
///
/// Returns [`EncodeError::Compression`] when zstd cannot encode the payload.
pub fn encode_telemetry_batch(
    batch: &TelemetryBatch,
    compression_threshold_bytes: usize,
) -> Result<EncodedTelemetryBatch, EncodeError> {
    encode_message(batch, compression_threshold_bytes)
}

/// Encodes an independent sample batch using the telemetry compression format.
///
/// # Errors
/// Returns an error when compression fails.
pub fn encode_flow_sample_batch(
    batch: &FlowSampleBatch,
    compression_threshold_bytes: usize,
) -> Result<EncodedTelemetryBatch, EncodeError> {
    encode_message(batch, compression_threshold_bytes)
}

fn encode_message(
    batch: &impl Message,
    compression_threshold_bytes: usize,
) -> Result<EncodedTelemetryBatch, EncodeError> {
    let protobuf = batch.encode_to_vec();
    if protobuf.len() < compression_threshold_bytes {
        return Ok(EncodedTelemetryBatch {
            body: protobuf,
            encoding: ContentEncoding::Identity,
        });
    }

    let body = zstd::stream::encode_all(Cursor::new(protobuf), ZSTD_LEVEL)
        .map_err(EncodeError::Compression)?;
    Ok(EncodedTelemetryBatch {
        body,
        encoding: ContentEncoding::Zstd,
    })
}

/// Decodes an identity or zstd-compressed protobuf telemetry batch.
///
/// # Errors
///
/// Returns an error for malformed protobuf or zstd data, or when the decoded
/// payload exceeds the 16 MiB protocol limit.
pub fn decode_telemetry_batch(
    payload: &[u8],
    encoding: ContentEncoding,
) -> Result<TelemetryBatch, DecodeError> {
    decode_message(payload, encoding)
}

/// Decodes a sample envelope; call `validate_flow_sample_batch` before use.
///
/// # Errors
/// Rejects malformed data and decompressed bodies exceeding 16 MiB.
pub fn decode_flow_sample_batch(
    payload: &[u8],
    encoding: ContentEncoding,
) -> Result<FlowSampleBatch, DecodeError> {
    decode_message(payload, encoding)
}

fn decode_message<M: Message + Default>(
    payload: &[u8],
    encoding: ContentEncoding,
) -> Result<M, DecodeError> {
    let protobuf = match encoding {
        ContentEncoding::Identity => {
            if payload.len() as u64 > MAX_DECODED_BATCH_BYTES {
                return Err(DecodeError::TooLarge);
            }
            payload.to_vec()
        }
        ContentEncoding::Zstd => {
            let decoder = zstd::stream::Decoder::new(Cursor::new(payload))
                .map_err(DecodeError::Decompression)?;
            let mut protobuf = Vec::new();
            decoder
                .take(MAX_DECODED_BATCH_BYTES + 1)
                .read_to_end(&mut protobuf)
                .map_err(DecodeError::Decompression)?;
            if protobuf.len() as u64 > MAX_DECODED_BATCH_BYTES {
                return Err(DecodeError::TooLarge);
            }
            protobuf
        }
    };
    M::decode(protobuf.as_slice()).map_err(DecodeError::Protobuf)
}

#[derive(Debug)]
pub enum EncodeError {
    Compression(std::io::Error),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compression(error) => write!(formatter, "zstd compression failed: {error}"),
        }
    }
}

impl Error for EncodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Compression(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    UnsupportedEncoding(String),
    Decompression(std::io::Error),
    TooLarge,
    Protobuf(prost::DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEncoding(value) => {
                write!(formatter, "unsupported content encoding: {value}")
            }
            Self::Decompression(error) => write!(formatter, "zstd decompression failed: {error}"),
            Self::TooLarge => write!(formatter, "decoded telemetry batch exceeds 16 MiB"),
            Self::Protobuf(error) => write!(formatter, "protobuf decoding failed: {error}"),
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decompression(error) => Some(error),
            Self::Protobuf(error) => Some(error),
            Self::UnsupportedEncoding(_) | Self::TooLarge => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zstd_payload_expanding_beyond_decoded_limit() {
        let limit = usize::try_from(MAX_DECODED_BATCH_BYTES).unwrap();
        let oversized = vec![0; limit + 1];
        let compressed = zstd::stream::encode_all(Cursor::new(oversized), ZSTD_LEVEL).unwrap();

        assert!(matches!(
            decode_telemetry_batch(&compressed, ContentEncoding::Zstd),
            Err(DecodeError::TooLarge)
        ));
    }
}
