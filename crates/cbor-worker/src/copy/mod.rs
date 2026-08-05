//! `COPY … FROM` / `COPY … TO` formats: bulk import and export of the `cbor` and
//! `msgpack` row-file formats.
//!
//! Where the scalars work one blob at a time, these move whole tables. Each
//! format's file is a bare concatenation of top-level items — one per row (a
//! CBOR Sequence, RFC 8742, or a MessagePack stream) — so a file appends,
//! streams, and needs no container header:
//!
//! ```sql
//! COPY (SELECT * FROM events) TO 'events.cbor' (FORMAT cbor);
//! COPY events FROM 'events.cbor' (FORMAT cbor);
//! ```
//!
//! Reader and writer share the `row_format` option ('map', the default,
//! keys each row by column name; 'array' is positional), so the pair round-trips.

pub mod common;
pub mod from;
pub mod location;
pub mod to;

/// Register both formats' readers and writers on the worker.
pub fn register(w: &mut vgi::Worker) {
    w.register_copy_from(from::CborCopyFrom::cbor());
    w.register_copy_from(from::CborCopyFrom::msgpack());
    w.register_copy_to(to::CborCopyTo::cbor());
    w.register_copy_to(to::CborCopyTo::msgpack());
}
