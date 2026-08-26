//! Key identity, JWS verification and write authorization for the Agent Card
//! Registry.
//!
//! Like [`a2a_card`], this crate is pure: it decides whether a write is
//! allowed, and never performs I/O. Storage and transport live above it.
//!
//! The design rests on one rule, [`SPEC.md` §3.2]: a signature's `kid` is the
//! RFC 7638 thumbprint of the key that verifies it. Since `kid` is inside the
//! signed protected header, key material submitted in a plain request body
//! cannot be substituted, and no second signed envelope is needed to
//! authenticate a key set.
//!
//! [`SPEC.md` §3.2]: ../../../SPEC.md

pub mod error;
pub mod jwk;
pub mod jws;
pub mod write;

pub use error::{Code, RegistryError, Result};
pub use jwk::{Alg, Jwk};
pub use jws::ProtectedHeader;
pub use write::{AcceptedWrite, AgentState, Outcome, Status, evaluate_withdrawal, evaluate_write};

/// Derive an agent identifier from its genesis key.
///
/// This is just the key's thumbprint, which is why a client can compute its own
/// identifier — and therefore its `jku` — offline, before it ever contacts the
/// registry.
pub fn agent_id_for(genesis: &Jwk) -> &str {
    genesis.thumbprint()
}
