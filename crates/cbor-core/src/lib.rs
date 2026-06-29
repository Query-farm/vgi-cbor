//! `cbor-core` — pure-compute CBOR / MessagePack / COSE / CWT / WebAuthn decoders
//! for the `cbor` VGI worker.
//!
//! This crate carries **no** Arrow or VGI dependency: it operates on
//! `&[u8]` in and Rust values / JSON strings out, so it is independently
//! testable and reusable. The worker crate (`cbor-worker`) maps these results
//! onto DuckDB's Arrow type system.
//!
//! # Design discipline (untrusted input)
//!
//! Every decoder funnels through [`value::parse`] / [`value::parse_strict`],
//! which bound recursion at [`value::MAX_NESTING`] and never panic on malformed
//! bytes. Errors are returned as [`value::DecodeError`] with a `kind()` that
//! lines up with the `well_formed` taxonomy. This is the per-row error-capture
//! contract: a hostile blob fails its own row, it never crashes the scan.
//!
//! # Non-goals
//!
//! No cryptographic verification of COSE/CWT signatures or MACs, no COSE_Encrypt
//! decryption, no CDDL validation. The security modules perform **structural**
//! decode only.

pub mod codec;
pub mod security;
pub mod seq;
pub mod validate;
pub mod value;

/// The crate (and worker) semantic version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
