//! YL Agent Runtime policy engine
//!
//! Evaluates every operation against scoped permission grants.
//! Separates policy decisions from enforcement (PRD section 3.2).

pub mod engine;
pub mod evaluator;
pub mod profiles;
pub mod store;

pub use engine::PolicyEngine;
pub use evaluator::*;
pub use profiles::*;
pub use store::*;