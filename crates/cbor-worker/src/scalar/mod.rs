//! Scalar functions exposed by the cbor worker.

#[macro_use]
pub mod common;
pub mod codec;
pub mod cose;
pub mod cwt;
pub mod msgpack;
pub mod version;
pub mod webauthn;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::CborVersion);

    // Core CBOR codec.
    worker.register_scalar(codec::ToJson);
    worker.register_scalar(codec::Diagnostic);
    // Two arity overloads each (with / without the optional positional mode):
    // DuckDB binds a const arg as required, so each optional-mode function ships
    // a 1-arg and a 2-arg form.
    worker.register_scalar(codec::Decode { with_mode: false });
    worker.register_scalar(codec::Decode { with_mode: true });
    worker.register_scalar(codec::FromJson);
    worker.register_scalar(codec::Encode { with_mode: false });
    worker.register_scalar(codec::Encode { with_mode: true });
    worker.register_scalar(codec::Canonical { with_mode: false });
    worker.register_scalar(codec::Canonical { with_mode: true });
    worker.register_scalar(codec::IsValid);
    worker.register_scalar(codec::WellFormed);
    worker.register_scalar(codec::Tags);
    worker.register_scalar(codec::Untag);

    // MessagePack mirror.
    worker.register_scalar(msgpack::MsgpackToJson);
    worker.register_scalar(msgpack::MsgpackDecode);
    worker.register_scalar(msgpack::MsgpackToCbor);
    worker.register_scalar(msgpack::MsgpackEncode);

    // COSE / COSE_Key.
    worker.register_scalar(cose::CoseDecodeFn);
    worker.register_scalar(cose::CosePayload);
    worker.register_scalar(cose::CoseHeadersFn);
    worker.register_scalar(cose::CoseX5t);
    worker.register_scalar(cose::CoseX5chain);
    worker.register_scalar(cose::CoseKeyFn);

    // CWT.
    worker.register_scalar(cwt::CwtClaimsFn);

    // WebAuthn.
    worker.register_scalar(webauthn::WebauthnAuthdata);
}
