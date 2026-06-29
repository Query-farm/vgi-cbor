//! Security-payload structural decoders: COSE (RFC 9052), CWT (RFC 8392),
//! COSE_Key, and WebAuthn / FIDO2 / CTAP2. The worker's real value — none of
//! these perform cryptographic verification (structural decode only).

pub mod cose;
pub mod cose_key;
pub mod cwt;
pub mod registry;
pub mod webauthn;
