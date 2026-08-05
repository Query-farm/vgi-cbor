//! Table (fan-out) functions exposed by the cbor worker.
//!
//! Both are *blended* table-in-out functions (`input_from_args`): the positional
//! blob argument is a real per-row input column rather than a bind-time
//! constant, so a single registration serves the literal call, the whole-column
//! call, and a correlated `LATERAL` join. Each fans one input row into a varying
//! number of output rows, so both emit `parent_rows` provenance — see
//! `vgi::table_in_out::EmitOptions`.

pub mod seq;
pub mod webauthn;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table_in_out(webauthn::WebauthnAttestation);
    worker.register_table_in_out(seq::SeqDecode);
}
