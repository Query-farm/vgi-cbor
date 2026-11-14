//! Composed example queries: realistic SQL that combines two or more of this
//! worker's own objects in one statement (a COSE header read beside the CWT
//! claims it signs, msgpack → CBOR → canonical → JSON, a well-formedness
//! screen beside a canonical-form check, a WebAuthn attestation shred joined
//! to the `cose_registry` view).
//!
//! Each SQL is defined exactly once here and referenced from both the
//! schema-level `vgi.example_queries` list and the example list of the object
//! that drives the query (the vgi-lint agent simulator only shows an object's
//! first five examples, never the schema-level list).

/// One described example query.
pub struct Example {
    pub description: &'static str,
    pub sql: &'static str,
}

/// Signed-CWT inventory: algorithm from the COSE header beside the subject and
/// expiry from the claim set the same COSE_Sign1 carries.
pub const SIGNED_CWT_INVENTORY: Example = Example {
    description: "Inventory COSE_Sign1-signed CWTs: the signing algorithm from each token's COSE \
                  header beside the subject and expiry from the claim set it signs, soonest \
                  expiry first.",
    sql: "SELECT (cbor.main.cwt_claims(t.token)).sub AS subject, (cbor.main.cose_headers(t.token)).alg AS alg, (cbor.main.cwt_claims(t.token)).exp AS expires FROM (VALUES (from_hex('d28443a10126a104426b31582aa3017668747470733a2f2f6973737565722e6578616d706c6502696465766963652d3432041a6955b90044deadbeef')), (from_hex('d28443a10127a104426b325828a3017568747470733a2f2f6f746865722e6578616d706c6502686465766963652d37041a6553f10044deadbeef'))) AS t(token) ORDER BY expires",
};

/// Key-order-insensitive dedupe of MessagePack frames: transcode to CBOR,
/// canonicalize, render as JSON, then group.
pub const MSGPACK_CANONICAL_DEDUPE: Example = Example {
    description: "Count logically distinct MessagePack frames when producers emit map keys in \
                  different orders: transcode each frame to CBOR, canonicalize it, and group by \
                  the canonical JSON (the first two frames collapse into one payload).",
    sql: "SELECT cbor.main.to_json(cbor.main.canonical(cbor.main.msgpack_to_cbor(f.frame))) AS payload, count(*) AS frames FROM (VALUES (from_hex('82a16201a16102')), (from_hex('82a16102a16201')), (from_hex('82a16103a16201'))) AS f(frame) GROUP BY payload ORDER BY payload",
};

/// Untrusted-input screen: classify malformed blobs and flag well-formed ones
/// that are not in deterministic (canonical) encoding.
pub const CANONICAL_SCREEN: Example = Example {
    description: "Screen inbound blobs for deterministic encoding: classify malformed ones by \
                  failure kind, and flag well-formed ones whose map keys are not in canonical \
                  order (blob 2 is out of order, blob 3 is truncated).",
    sql: "SELECT b.id, (cbor.main.well_formed(b.blob)).kind AS problem, cbor.main.canonical(b.blob) = b.blob AS is_canonical FROM (VALUES (1, from_hex('a2616101616202')), (2, from_hex('a2616202616101')), (3, from_hex('a2616101'))) AS b(id, blob) ORDER BY b.id",
};

/// WebAuthn enrollment shred under LATERAL, joined to the COSE registry to get
/// the numeric COSEAlgorithmIdentifier a relying-party policy is written in.
pub const WEBAUTHN_ALG_POLICY: Example = Example {
    description: "Shred each enrollment's attestation object and join its algorithm name to the \
                  COSE registry to recover the numeric COSEAlgorithmIdentifier, checked against \
                  a relying-party allow-list of -7 (ES256) and -257 (RS256); the undecodable \
                  enrollment contributes no row.",
    sql: "SELECT e.user_name, w.fmt, w.alg, r.id AS alg_id, r.id IN (-7, -257) AS alg_allowed FROM (VALUES ('alice', from_hex('a363666d74667061636b65646761747453746d74a363616c67266373696742dead637835638143300100686175746844617461588700000000000000000000000000000000000000000000000000000000000000004100000007111111111111111111111111111111110003cafe01a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')), ('bob', from_hex('00'))) AS e(user_name, att_obj), LATERAL cbor.main.webauthn_attestation(e.att_obj) AS w JOIN cbor.main.cose_registry AS r ON r.registry = 'alg' AND r.name = w.alg ORDER BY e.user_name",
};

/// Every composed example, in the order the schema-level list shows them.
pub const COMPOSED: &[&Example] = &[
    &SIGNED_CWT_INVENTORY,
    &MSGPACK_CANONICAL_DEDUPE,
    &CANONICAL_SCREEN,
    &WEBAUTHN_ALG_POLICY,
];

/// Escape a string for a JSON string literal. Example text is plain ASCII SQL
/// and prose, so quotes, backslashes and control characters are all it needs.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One example as a JSON object.
fn to_json(example: &Example) -> String {
    format!(
        "{{\"description\":\"{}\",\"sql\":\"{}\"}}",
        json_escape(example.description),
        json_escape(example.sql)
    )
}

/// Append `extra` examples to an existing `vgi.example_queries` JSON list.
pub fn with(existing: &str, extra: &[&Example]) -> String {
    let body = existing.trim();
    let body = body
        .strip_suffix(']')
        .expect("vgi.example_queries must be a JSON list")
        .trim_end();
    let mut out = body.to_string();
    for example in extra {
        if !out.ends_with('[') {
            out.push(',');
        }
        out.push_str(&to_json(example));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_to_list() {
        let ex = Example {
            description: "say \"hi\"",
            sql: "SELECT 'a\\b' AS x",
        };
        assert_eq!(
            with("[]", &[&ex]),
            r#"[{"description":"say \"hi\"","sql":"SELECT 'a\\b' AS x"}]"#
        );
        assert_eq!(
            with(r#"[{"description":"d","sql":"s"}]"#, &[&ex]),
            r#"[{"description":"d","sql":"s"},{"description":"say \"hi\"","sql":"SELECT 'a\\b' AS x"}]"#
        );
    }

    #[test]
    fn composed_sql_is_single_line_and_qualified() {
        for ex in COMPOSED {
            assert!(!ex.sql.contains('\n'));
            assert!(ex.sql.contains("cbor.main."));
            assert!(ex.sql.contains("ORDER BY"));
        }
    }
}
