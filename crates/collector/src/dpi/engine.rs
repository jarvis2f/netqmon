use netqmon_protocol::v1::{FlowSampleKey, SamplePacket};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct DpiResult {
    pub protocol: String,
    pub confidence: f64,
    pub metadata: BTreeMap<String, String>,
    pub source: String,
}

/// Per-flow state contains only the engine's analysis state, never a sample queue.
pub trait DpiFlow: Send {
    fn classify(&mut self, packets: &[SamplePacket]) -> Option<DpiResult>;
    fn finish(&mut self) -> Option<DpiResult> {
        None
    }
}
pub trait DpiEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn start(&self, flow: &FlowSampleKey) -> Result<Box<dyn DpiFlow>, String>;
}
