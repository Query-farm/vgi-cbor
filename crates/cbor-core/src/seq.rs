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

/// The outcome of parsing a CBOR sequence into raw values.
#[derive(Debug, Clone, Default)]
pub struct SeqParse {
    /// The items decoded before the sequence ended or went bad.
    pub items: Vec<Value>,
    /// Set when decoding stopped early: the failure that ended the sequence.
    /// `None` means every byte was consumed by a complete item.
    pub error: Option<String>,
}

/// Decode a CBOR sequence into raw [`Value`]s. Stops at the first item that fails
/// to decode (e.g. a truncated tail), returning everything parsed so far plus the
/// error that ended it — the caller decides whether a bad tail is fatal.
pub fn parse_seq(bytes: &[u8]) -> SeqParse {
    let mut cur = Cursor::new(bytes);
    let len = bytes.len() as u64;
    let mut items = Vec::new();
    while cur.position() < len {
        let before = cur.position();
        match ciborium::de::from_reader_with_recursion_limit::<Value, _>(&mut cur, MAX_NESTING) {
            Ok(value) => {
                items.push(value);
                // Guard against a zero-advance loop on a pathological reader.
                if cur.position() == before {
                    return SeqParse {
                        items,
                        error: Some("sequence reader made no progress".to_string()),
                    };
                }
            }
            Err(e) => {
                // Report the classified taxonomy ("input ended before the item
                // was complete"), not ciborium's raw debug form.
                let error = Some(format!(
                    "item {}: {}",
                    items.len(),
                    crate::value::classify(&e)
                ));
                return SeqParse { items, error };
            }
        }
    }
    SeqParse { items, error: None }
}

/// Decode a CBOR sequence into its items. Stops at the first item that fails to
/// decode (e.g. truncated tail), returning everything parsed so far.
pub fn seq_decode(bytes: &[u8]) -> Vec<SeqItem> {
    parse_seq(bytes)
        .items
        .iter()
        .enumerate()
        .map(|(idx, value)| SeqItem {
            idx: idx as i64,
            value_json: to_json_value(value).to_string(),
        })
        .collect()
}
