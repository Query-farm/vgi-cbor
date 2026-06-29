//! Golden-fixture tests over RFC 8949 Appendix A CBOR vectors plus the tag-aware
//! COSE / CWT / COSE_Key / WebAuthn structural-decode cases.

use cbor_core::codec::{diagnostic::diagnostic, encode, json, msgpack, tags};
use cbor_core::security::{cose, cose_key, cwt, webauthn};
use cbor_core::{seq, validate};
use ciborium::value::Value;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// --- RFC 8949 Appendix A: to_json ----------------------------------------

#[test]
fn rfc8949_appendix_a_to_json() {
    let cases: &[(&str, &str)] = &[
        ("00", "0"),
        ("01", "1"),
        ("0a", "10"),
        ("1903e8", "1000"),
        ("20", "-1"),
        ("3903e7", "-1000"),
        ("f4", "false"),
        ("f5", "true"),
        ("f6", "null"),
        ("6161", "\"a\""),
        ("6449455446", "\"IETF\""),
        ("83010203", "[1,2,3]"),
        ("8201820203", "[1,[2,3]]"),
        ("a26161016162820203", "{\"a\":1,\"b\":[2,3]}"),
        ("826161a161626163", "[\"a\",{\"b\":\"c\"}]"),
        // Indefinite-length array [1,2,3].
        ("9f010203ff", "[1,2,3]"),
        // Byte string → base64url.
        ("4401020304", "\"AQIDBA\""),
    ];
    for (hex_in, want) in cases {
        let got = json::to_json_string(&hx(hex_in)).unwrap();
        assert_eq!(&got, want, "to_json({hex_in})");
    }
}

#[test]
fn rfc8949_floats_to_json() {
    // 1.1 as a 64-bit float.
    let got = json::to_json_string(&hx("fb3ff199999999999a")).unwrap();
    assert_eq!(got, "1.1");
    // 1.0 as a 16-bit float widens to 1.0.
    let got = json::to_json_string(&hx("f93c00")).unwrap();
    assert_eq!(got, "1.0");
}

// --- diagnostic notation --------------------------------------------------

#[test]
fn diagnostic_preserves_tags_and_bytes() {
    assert_eq!(diagnostic(&hx("83010203")).unwrap(), "[1, 2, 3]");
    assert_eq!(diagnostic(&hx("4401020304")).unwrap(), "h'01020304'");
    // tag 1 epoch timestamp is preserved (unlike to_json).
    assert_eq!(diagnostic(&hx("c11a514b67b0")).unwrap(), "1(1363896240)");
    assert_eq!(
        diagnostic(&hx("a26161016162820203")).unwrap(),
        "{\"a\": 1, \"b\": [2, 3]}"
    );
}

// --- round-trips & canonical ---------------------------------------------

#[test]
fn from_json_round_trips_through_to_json() {
    for s in [
        "[1,2,3]",
        "{\"a\":1,\"b\":2}",
        "\"hello\"",
        "true",
        "null",
        "42",
    ] {
        let cbor = json::from_json_str(s).unwrap();
        let back = json::to_json_string(&cbor).unwrap();
        assert_eq!(back, s, "round-trip {s}");
    }
}

#[test]
fn canonical_core_sorts_map_keys() {
    // {"b":1,"a":2} → core-canonical sorts keys by encoded bytes → {"a":2,"b":1}.
    // (Asserted on raw bytes — serde_json's object keys are always sorted, so JSON
    // can't observe CBOR map order.)
    let input = hx("a2616201616102");
    let canon = encode::canonical(&input, encode::Canon::Core).unwrap();
    assert_eq!(hex::encode(&canon), "a2616102616201");
    // Idempotent.
    let again = encode::canonical(&canon, encode::Canon::Core).unwrap();
    assert_eq!(canon, again);
}

#[test]
fn canonical_ctap2_orders_length_first() {
    // Keys "aa" (3 encoded bytes) and "b" (2 encoded bytes): CTAP2 puts the
    // shorter-encoded key first regardless of byte value.
    let mut bytes = Vec::new();
    let value = Value::Map(vec![
        (Value::Text("aa".into()), Value::Integer(1.into())),
        (Value::Text("b".into()), Value::Integer(2.into())),
    ]);
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    let canon = encode::canonical(&bytes, encode::Canon::Ctap2).unwrap();
    // a2 | 61 62 02 ("b":2) | 62 61 61 01 ("aa":1).
    assert_eq!(hex::encode(&canon), "a261620262616101");
}

// --- tags / untag ---------------------------------------------------------

#[test]
fn tags_walks_in_document_order() {
    // [1, 1(1363896240)] — one tag at $[1].
    let bytes = hx("82 01 c11a514b67b0".replace(' ', "").as_str());
    let hits = tags::tags(&bytes).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].tag, 1);
    assert_eq!(hits[0].path, "$[1]");
    assert_eq!(hits[0].value_json, "1363896240");

    let untagged = tags::untag(&bytes, 1).unwrap();
    assert_eq!(untagged, "[1363896240]");
}

// --- validation -----------------------------------------------------------

#[test]
fn well_formed_classifies_errors() {
    assert!(validate::is_valid(&hx("83010203")));
    assert!(validate::well_formed(&hx("83010203")).ok);

    // Truncated array (declares 3, supplies 2).
    let wf = validate::well_formed(&hx("830102"));
    assert!(!wf.ok);
    assert_eq!(wf.kind.as_deref(), Some("truncated"));

    // Trailing bytes after a complete item.
    let wf = validate::well_formed(&hx("0101"));
    assert!(!wf.ok);
    assert_eq!(wf.kind.as_deref(), Some("trailing-bytes"));

    // Duplicate map key {1:1, 1:2}.
    let wf = validate::well_formed(&hx("a201010102"));
    assert!(!wf.ok);
    assert_eq!(wf.kind.as_deref(), Some("duplicate-key"));
}

// --- MessagePack ----------------------------------------------------------

#[test]
fn msgpack_decode_and_transcode() {
    // msgpack [1,2,3] = 0x93 01 02 03.
    let mp = hx("93010203");
    assert_eq!(msgpack::to_json_string(&mp).unwrap(), "[1,2,3]");

    // Transcode to CBOR and confirm equal JSON.
    let cbor = msgpack::to_cbor(&mp).unwrap();
    assert_eq!(json::to_json_string(&cbor).unwrap(), "[1,2,3]");

    // msgpack map {"a":1} = 0x81 a1 61 01.
    let mp = hx("81a16101");
    assert_eq!(msgpack::to_json_string(&mp).unwrap(), "{\"a\":1}");
}

#[test]
fn msgpack_timestamp_ext() {
    // fixext4 (0xd6), type -1 (0xff), 4-byte seconds = 1 (0x00000001).
    let mp = hx("d6ff00000001");
    let json = msgpack::to_json_string(&mp).unwrap();
    assert!(json.contains("1970-01-01T00:00:01Z"), "got {json}");
}

// --- COSE -----------------------------------------------------------------

/// A COSE_Sign1 (tag 18) skeleton: protected {1:-7 (ES256)}, empty unprotected,
/// empty payload, a short signature.
fn cose_sign1_skeleton() -> Vec<u8> {
    // d2 (tag 18) 84 (array4) 43 a10126 (protected bstr {1:-7}) a0 (unprot {})
    // 40 (payload "") 44 deadbeef (sig).
    hx("d28443a10126a04044deadbeef")
}

#[test]
fn cose_decode_sign1() {
    let bytes = cose_sign1_skeleton();
    let d = cose::cose_decode(&bytes).unwrap();
    assert_eq!(d.tag, Some(18));
    assert_eq!(d.msg_type, "COSE_Sign1");
    assert_eq!(d.protected.alg.as_deref(), Some("ES256"));
    assert_eq!(d.signature.as_deref(), Some(&hx("deadbeef")[..]));
}

#[test]
fn cose_headers_with_x5t_and_x5chain() {
    // protected {1:-7}, unprotected {33: [der1, der2], 34: [-43, h'abcd']}.
    let der1 = vec![0x30u8, 0x01, 0x00];
    let der2 = vec![0x30u8, 0x02, 0x00, 0x00];
    let unprot = Value::Map(vec![
        (
            Value::Integer(33.into()),
            Value::Array(vec![Value::Bytes(der1.clone()), Value::Bytes(der2.clone())]),
        ),
        (
            Value::Integer(34.into()),
            Value::Array(vec![
                Value::Integer((-43).into()),
                Value::Bytes(vec![0xab, 0xcd]),
            ]),
        ),
    ]);
    let mut prot_inner = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-7).into()),
        )]),
        &mut prot_inner,
    )
    .unwrap();
    let msg = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(prot_inner),
            unprot,
            Value::Bytes(vec![]),
            Value::Bytes(vec![0x00]),
        ])),
    );
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&msg, &mut bytes).unwrap();

    let chain = cose::cose_x5chain(&bytes).unwrap().unwrap();
    assert_eq!(chain, vec![der1, der2]);
    let x5t = cose::cose_x5t(&bytes).unwrap().unwrap();
    assert_eq!(x5t, "abcd");
}

// --- CWT (RFC 8392) -------------------------------------------------------

#[test]
fn cwt_claims_full_set() {
    // RFC 8392 A.1 claim set.
    let claims = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Text("coap://as.example.com".into()),
        ),
        (Value::Integer(2.into()), Value::Text("erikw".into())),
        (
            Value::Integer(3.into()),
            Value::Text("coap://light.example.com".into()),
        ),
        (Value::Integer(4.into()), Value::Integer(1444064944.into())),
        (Value::Integer(5.into()), Value::Integer(1443944944.into())),
        (Value::Integer(6.into()), Value::Integer(1443944944.into())),
        (Value::Integer(7.into()), Value::Bytes(vec![0x0b, 0x71])),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&claims, &mut bytes).unwrap();

    let c = cwt::cwt_claims(&bytes).unwrap();
    assert_eq!(c.iss.as_deref(), Some("coap://as.example.com"));
    assert_eq!(c.sub.as_deref(), Some("erikw"));
    assert_eq!(c.aud.as_deref(), Some("coap://light.example.com"));
    assert_eq!(c.exp, Some(1444064944));
    assert_eq!(c.iat, Some(1443944944));
    assert_eq!(c.cti, Some(vec![0x0b, 0x71]));
}

#[test]
fn cwt_claims_unwraps_cose_envelope() {
    // A CWT claims map wrapped in a tag-61 envelope around a COSE_Sign1.
    let claims = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Text("coap://as".into()),
    )]);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&claims, &mut payload).unwrap();
    let mut prot_inner = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-7).into()),
        )]),
        &mut prot_inner,
    )
    .unwrap();
    let sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(prot_inner),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(vec![0x00]),
        ])),
    );
    let cwt_env = Value::Tag(61, Box::new(sign1));
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&cwt_env, &mut bytes).unwrap();

    let c = cwt::cwt_claims(&bytes).unwrap();
    assert_eq!(c.iss.as_deref(), Some("coap://as"));
}

// --- COSE_Key -------------------------------------------------------------

#[test]
fn cose_key_ec2() {
    // {1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2: x, -3: y}.
    let key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-7).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(vec![0xaa; 32])),
        (Value::Integer((-3).into()), Value::Bytes(vec![0xbb; 32])),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&key, &mut bytes).unwrap();

    let k = cose_key::cose_key(&bytes).unwrap();
    assert_eq!(k.kty.as_deref(), Some("EC2"));
    assert_eq!(k.alg.as_deref(), Some("ES256"));
    assert_eq!(k.crv.as_deref(), Some("P-256"));
    assert_eq!(k.x, Some(vec![0xaa; 32]));
    assert_eq!(k.y, Some(vec![0xbb; 32]));
}

// --- WebAuthn -------------------------------------------------------------

/// Build authenticatorData with an attested EC2 credential public key.
fn authdata_with_cred() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0u8; 32]); // rpIdHash
    out.push(0x41); // flags: UP (0x01) | AT (0x40)
    out.extend_from_slice(&7u32.to_be_bytes()); // signCount = 7
    out.extend_from_slice(&[0x11u8; 16]); // aaguid
    out.extend_from_slice(&3u16.to_be_bytes()); // credIdLen = 3
    out.extend_from_slice(&[0xca, 0xfe, 0x01]); // credentialId
    let key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-7).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(vec![0xaa; 32])),
        (Value::Integer((-3).into()), Value::Bytes(vec![0xbb; 32])),
    ]);
    ciborium::ser::into_writer(&key, &mut out).unwrap();
    out
}

#[test]
fn webauthn_authdata_attested() {
    let auth = webauthn::webauthn_authdata(&authdata_with_cred()).unwrap();
    assert!(auth.up);
    assert!(auth.at);
    assert_eq!(auth.sign_count, 7);
    assert_eq!(
        auth.aaguid.as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(auth.cred_id, Some(vec![0xca, 0xfe, 0x01]));
    let key = auth.cred_public_key.unwrap();
    assert_eq!(key.kty.as_deref(), Some("EC2"));
    assert_eq!(key.crv.as_deref(), Some("P-256"));
}

#[test]
fn webauthn_attestation_packed() {
    let authdata = authdata_with_cred();
    let att = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("packed".into())),
        (
            Value::Text("attStmt".into()),
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7).into())),
                (Value::Text("sig".into()), Value::Bytes(vec![0xde, 0xad])),
                (
                    Value::Text("x5c".into()),
                    Value::Array(vec![Value::Bytes(vec![0x30, 0x01, 0x00])]),
                ),
            ]),
        ),
        (Value::Text("authData".into()), Value::Bytes(authdata)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();

    let row = webauthn::webauthn_attestation(&bytes).unwrap();
    assert_eq!(row.fmt, "packed");
    assert_eq!(row.alg.as_deref(), Some("ES256"));
    assert_eq!(row.sign_count, 7);
    assert_eq!(row.sig, Some(vec![0xde, 0xad]));
    assert_eq!(row.x5c.len(), 1);
    assert_eq!(
        row.aaguid.as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
}

#[test]
fn webauthn_attestation_none() {
    let mut authdata = vec![0u8; 32];
    authdata.push(0x01); // UP only, no attested cred
    authdata.extend_from_slice(&0u32.to_be_bytes());
    let att = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(authdata)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();
    let row = webauthn::webauthn_attestation(&bytes).unwrap();
    assert_eq!(row.fmt, "none");
    assert!(row.alg.is_none());
    assert!(row.x5c.is_empty());
}

// --- CBOR Sequence (RFC 8742) --------------------------------------------

#[test]
fn seq_decode_fans_items() {
    // Three top-level items: 1, 2, 3.
    let items = seq::seq_decode(&hx("010203"));
    assert_eq!(items.len(), 3);
    assert_eq!(items[0].idx, 0);
    assert_eq!(items[2].value_json, "3");

    // A truncated tail stops cleanly after the first complete item.
    let items = seq::seq_decode(&hx("0183"));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].value_json, "1");
}
