//! Untrusted-input hardening: the decoders must NEVER panic on arbitrary or
//! truncated bytes. This is the per-row error-capture contract — a hostile blob
//! fails its own row, it never crashes the scan. Property-based with proptest.
//!
//! The recursion-heavy decode paths use `ciborium`'s serde `Value`
//! deserialization, whose **unoptimized debug** stack frames are large. Bounded
//! recursion ([`MAX_NESTING`]) keeps the production worker (release build, ample
//! stack) safe, but a 2 MiB debug **test** thread can still overflow at the depth
//! limit. So these tests run on an explicit large-stack thread — exercising the
//! exact same code, just with headroom the debug build needs.

use cbor_core::codec::{diagnostic::diagnostic, encode, json, msgpack, tags};
use cbor_core::security::{cose, cose_key, cwt, webauthn};
use cbor_core::{seq, validate};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

/// Run every decoder on `bytes`. None may panic; all must return Result/Option.
fn exercise_all(bytes: &[u8]) {
    let _ = json::to_json_string(bytes);
    let _ = diagnostic(bytes);
    let _ = tags::tags(bytes);
    let _ = tags::untag(bytes, 1);
    let _ = encode::canonical(bytes, encode::Canon::Core);
    let _ = encode::canonical(bytes, encode::Canon::Ctap2);
    let _ = validate::is_valid(bytes);
    let _ = validate::well_formed(bytes);
    let _ = msgpack::to_json_string(bytes);
    let _ = msgpack::to_cbor(bytes);
    let _ = cose::cose_decode(bytes);
    let _ = cose::cose_x5t(bytes);
    let _ = cose::cose_x5chain(bytes);
    let _ = cose::cose_payload(bytes);
    let _ = cwt::cwt_claims(bytes);
    let _ = cose_key::cose_key(bytes);
    let _ = webauthn::webauthn_authdata(bytes);
    let _ = webauthn::webauthn_attestation(bytes);
    let _ = seq::seq_decode(bytes);
}

/// Run `f` on a thread with a generous stack and propagate any panic, so the
/// debug-build stack frames of deep recursion don't mask the assertion.
fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn arbitrary_bytes_never_panic() {
    on_big_stack(|| {
        let mut runner = TestRunner::new(Config::with_cases(4000));
        runner
            .run(&proptest::collection::vec(any::<u8>(), 0..512), |bytes| {
                exercise_all(&bytes);
                Ok(())
            })
            .unwrap();
    });
}

#[test]
fn truncations_never_panic() {
    on_big_stack(|| {
        let mut runner = TestRunner::new(Config::with_cases(2000));
        runner
            .run(&proptest::collection::vec(any::<u8>(), 1..256), |bytes| {
                for n in 0..bytes.len() {
                    exercise_all(&bytes[..n]);
                }
                Ok(())
            })
            .unwrap();
    });
}

/// A hostile blob with extreme declared nesting must be rejected
/// (`nesting-limit`), not stack-overflow.
#[test]
fn deeply_nested_is_rejected_not_overflowing() {
    on_big_stack(|| {
        // 2000 nested definite-length 1-element arrays: 0x81 * 2000 then 0x00.
        let mut bytes = vec![0x81u8; 2000];
        bytes.push(0x00);
        let wf = validate::well_formed(&bytes);
        assert!(!wf.ok);
        assert_eq!(wf.kind.as_deref(), Some("nesting-limit"));
        exercise_all(&bytes);
    });
}

/// Indefinite-length nesting (0x9f open) is also bounded.
#[test]
fn indefinite_nesting_is_bounded() {
    on_big_stack(|| {
        let bytes = vec![0x9fu8; 4000];
        assert!(!validate::is_valid(&bytes));
        exercise_all(&bytes);
    });
}
