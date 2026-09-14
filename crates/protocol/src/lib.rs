//! Versioned protobuf messages and wire encoding shared by netqmon components.

mod codec;
mod sample;
mod validation;

#[allow(clippy::doc_markdown, clippy::must_use_candidate)]
pub mod v1 {
    //! Generated `netqmon.v1` protobuf messages.

    include!(concat!(env!("OUT_DIR"), "/netqmon.v1.rs"));
}

pub use codec::{
    ContentEncoding, DecodeError, EncodeError, EncodedTelemetryBatch, decode_telemetry_batch,
    encode_telemetry_batch,
};
pub use codec::{decode_flow_sample_batch, encode_flow_sample_batch};
pub use sample::*;
pub use validation::{BatchMetadataError, validate_batch_metadata};

/// Protocol version emitted by this crate's v1 messages.
pub const PROTOCOL_VERSION: u32 = 1;
