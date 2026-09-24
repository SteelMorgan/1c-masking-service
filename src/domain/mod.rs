mod error;
mod mapping;
mod masking;
//++agent TASK-222 [05.10.2026]
pub(crate) mod manifest;
//++agent TASK-222
mod models;
mod service;

pub use error::{ErrorCode, ProcessingError, ServiceError};
pub use mapping::{MappingCandidate, MappingLimits, MappingStore};
pub use masking::{
    MaskEngine, MaskingOutput, PolicyRule, PolicySnapshot, RuleAction, RuleSelector,
};
pub use models::*;
pub use service::MaskingService;
