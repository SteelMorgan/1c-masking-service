mod error;
mod mapping;
mod masking;
//++agent TASK-222 [05.10.2026]
pub(crate) mod manifest;
//++agent TASK-222
mod models;
mod service;
//++agent TASK-225 [26.09.2026]
pub(crate) mod setup;
//++agent TASK-225

pub use error::{ErrorCode, ProcessingError, ServiceError};
pub use mapping::{MappingCandidate, MappingLimits, MappingStore};
pub use masking::{
    dictionary_fingerprint, DictionaryIndex, MaskEngine, MaskingOutput, PolicyRule, PolicySnapshot,
    RuleAction, RuleSelector,
};

//++agent TASK-225
pub use models::*;
pub use service::{DryRunOutcome, MaskingService};
//++agent TASK-225 [26.09.2026] §3.4: F9-предикат для DiffContext.
pub(crate) use service::metadata_expandable_basics;
//++agent TASK-225
