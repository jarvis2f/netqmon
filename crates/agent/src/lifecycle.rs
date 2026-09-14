use std::fmt;

use crate::flow::FlowKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    Active,
    Idle,
    End,
}

impl fmt::Display for FlowState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Active => "active",
            Self::Idle => "idle",
            Self::End => "end",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowLifecycleEvent {
    pub key: FlowKey,
    pub state: FlowState,
}
