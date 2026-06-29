//! Byte-level codecs: CBOR ⇄ JSON / diagnostic / canonical encode, the
//! MessagePack mirror, and the semantic-tag walk.

pub mod diagnostic;
pub mod encode;
pub mod json;
pub mod msgpack;
pub mod tags;

use ciborium::value::Value;

/// Compact diagnostic rendering of a single map key (used to form tag paths for
/// non-text keys, e.g. `$[1]`).
pub fn diagnostic_key(key: &Value) -> String {
    let mut s = String::new();
    diagnostic::render(key, &mut s);
    s
}
