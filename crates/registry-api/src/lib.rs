//! HTTP surface and storage contract for the Agent Card Registry.
//!
//! The router in [`api`] is transport-only: it parses, delegates every
//! authorization decision to [`registry_core`], and commits through a
//! [`store::Store`]. That split is what lets the whole surface be exercised
//! against [`memory::MemoryStore`] with no AWS in sight.

pub mod api;
pub mod catalog;
pub mod memory;
pub mod problem;
pub mod store;

pub use api::{AppState, RegistryConfig, router};
pub use catalog::{CATALOG, ProblemDoc};
pub use memory::MemoryStore;
pub use problem::Problem;
pub use store::{AgentRecord, Commit, Store, StoreError, VersionRecord};
