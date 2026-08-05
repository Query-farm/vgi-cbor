//! RFC 8742 CBOR Sequence decode: a concatenation of zero or more CBOR items,
//! fanned out one row per item. Truncated trailing data stops the sequence
//! cleanly (the consumed items are still returned).

use std::io::{BufRead, Cursor};

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

/// Pull one item at a time from a CBOR Sequence reader.
///
/// `ciborium` decodes a single item per call and leaves the reader positioned
/// after it, so a sequence can be consumed incrementally from any [`BufRead`] —
/// a file, an object-store range reader — without materializing the whole
/// thing.
///
/// [`BufRead`] rather than plain `Read` is load-bearing: the end of a sequence and a
/// *truncated* final item both surface from ciborium as `UnexpectedEof`, so the
/// only way to tell "no more items" from "the last item was cut short" is to
/// check for end-of-input *before* attempting a decode. `fill_buf` does that
/// without consuming anything.
pub struct SeqReader<R: BufRead> {
    reader: R,
    done: bool,
    index: usize,
}

impl<R: BufRead> SeqReader<R> {
    /// Wrap a reader positioned at the start of a CBOR Sequence.
    pub fn new(reader: R) -> Self {
        SeqReader {
            reader,
            done: false,
            index: 0,
        }
    }

    /// The next item: `None` at a clean end of input, `Some(Err(..))` for a
    /// malformed or truncated item (after which the reader stops).
    pub fn next_item(&mut self) -> Option<std::result::Result<Value, String>> {
        if self.done {
            return None;
        }
        // Clean end of input, checked before decoding so a truncated final item
        // is still reported as the error it is.
        match self.reader.fill_buf() {
            Ok([]) => {
                self.done = true;
                return None;
            }
            Ok(_) => {}
            Err(e) => {
                self.done = true;
                return Some(Err(format!("item {}: {e}", self.index)));
            }
        }
        match ciborium::de::from_reader_with_recursion_limit::<Value, _>(
            &mut self.reader,
            MAX_NESTING,
        ) {
            Ok(value) => {
                self.index += 1;
                Some(Ok(value))
            }
            Err(e) => {
                self.done = true;
                Some(Err(format!(
                    "item {}: {}",
                    self.index,
                    crate::value::classify(&e)
                )))
            }
        }
    }
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

#[cfg(test)]
mod reader_tests {
    use super::*;

    fn drain<R: BufRead>(r: R) -> (Vec<Value>, Option<String>) {
        let mut reader = SeqReader::new(r);
        let mut items = Vec::new();
        while let Some(next) = reader.next_item() {
            match next {
                Ok(v) => items.push(v),
                Err(e) => return (items, Some(e)),
            }
        }
        (items, None)
    }

    #[test]
    fn reads_every_item_and_ends_cleanly() {
        // 01 02 03 — three complete top-level items.
        let (items, err) = drain(&[0x01u8, 0x02, 0x03][..]);
        assert_eq!(items.len(), 3);
        assert!(
            err.is_none(),
            "a complete sequence must not report an error"
        );
    }

    #[test]
    fn an_empty_input_is_zero_items_not_an_error() {
        let (items, err) = drain(&[][..]);
        assert!(items.is_empty());
        assert!(err.is_none());
    }

    /// The distinction `fill_buf` exists to preserve: a cut-off final item is an
    /// error, not a clean end. Both surface from ciborium as `UnexpectedEof`.
    #[test]
    fn a_truncated_final_item_is_an_error_not_a_clean_end() {
        // Two complete items, then a map header promising entries that never come.
        let bytes = [0x01u8, 0x02, 0xa1];
        let (items, err) = drain(&bytes[..]);
        assert_eq!(items.len(), 2, "the complete items are still returned");
        let err = err.expect("a truncated tail must be reported");
        assert!(
            err.contains("item 2"),
            "the error names the bad item: {err}"
        );
    }

    /// The incremental reader and the whole-buffer parser must agree.
    #[test]
    fn matches_the_buffered_parser() {
        for bytes in [
            &[0x01u8, 0x02, 0x03][..],
            &[][..],
            &[0x01, 0x02, 0xa1][..],       // truncated tail
            &[0x83, 0x01, 0x02, 0x03][..], // one array item
        ] {
            let (streamed, stream_err) = drain(bytes);
            let buffered = parse_seq(bytes);
            assert_eq!(
                streamed.len(),
                buffered.items.len(),
                "item count differs for {bytes:02x?}"
            );
            assert_eq!(
                stream_err.is_some(),
                buffered.error.is_some(),
                "error disagreement for {bytes:02x?}"
            );
        }
    }
}
