//! Table (LATERAL fan-out) functions exposed by the cbor worker.

pub mod seq;
pub mod webauthn;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(webauthn::WebauthnAttestation);
    worker.register_table(seq::SeqDecode);
}
