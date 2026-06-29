//! RFC 8742 CBOR Sequence decode: a concatenation of zero or more CBOR items,
//! fanned out one row per item. Truncated trailing data stops the sequence
//! cleanly (the consumed items are still returned).

use std::io::Cursor;

use ciborium::value::Value;

use crate::codec::json::to_json_value;
use crate::value::MAX_NESTING;

/// One decoded sequence item.
#[derive(Debug, Clone)]
pub struct SeqItem {
    /// Zero-based position in the sequence.
    pub idx: i64,
    /// The item rendered as JSON.
    pub value_json: String,
}

/// Decode a CBOR sequence into its items. Stops at the first item that fails to
/// decode (e.g. truncated tail), returning everything parsed so far.
pub fn seq_decode(bytes: &[u8]) -> Vec<SeqItem> {
    let mut cur = Cursor::new(bytes);
    let len = bytes.len() as u64;
    let mut out = Vec::new();
    let mut idx = 0i64;
    while cur.position() < len {
        let before = cur.position();
        match ciborium::de::from_reader_with_recursion_limit::<Value, _>(&mut cur, MAX_NESTING) {
            Ok(value) => {
                out.push(SeqItem {
                    idx,
                    value_json: to_json_value(&value).to_string(),
                });
                idx += 1;
                // Guard against a zero-advance loop on a pathological reader.
                if cur.position() == before {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    out
}
