//! IANA COSE registry lookups (algorithms, key types, curves) used to render the
//! numeric labels in COSE headers and keys as their standard names.

/// Map a COSE algorithm identifier (RFC 9053 / IANA "COSE Algorithms") to its
/// name. Unknown values fall back to the decimal label string.
pub fn alg_name(id: i64) -> String {
    let name = match id {
        -65535 => "RS1",
        -260 => "WalnutDSA",
        -259 => "RS512",
        -258 => "RS384",
        -257 => "RS256",
        -47 => "ES256K",
        -46 => "HSS-LMS",
        -45 => "SHAKE256",
        -44 => "SHA-512",
        -43 => "SHA-384",
        -39 => "PS512",
        -38 => "PS384",
        -37 => "PS256",
        -36 => "ES512",
        -35 => "ES384",
        -34 => "ECDH-SS+A256KW",
        -33 => "ECDH-SS+A192KW",
        -32 => "ECDH-SS+A128KW",
        -31 => "ECDH-ES+A256KW",
        -30 => "ECDH-ES+A192KW",
        -29 => "ECDH-ES+A128KW",
        -27 => "ECDH-SS+HKDF-512",
        -26 => "ECDH-SS+HKDF-256",
        -25 => "ECDH-ES+HKDF-512",
        -8 => "EdDSA",
        -7 => "ES256",
        -6 => "direct",
        -5 => "A256KW",
        -4 => "A192KW",
        -3 => "A128KW",
        0 => "Reserved",
        1 => "A128GCM",
        2 => "A192GCM",
        3 => "A256GCM",
        4 => "HMAC 256/64",
        5 => "HMAC 256/256",
        6 => "HMAC 384/384",
        7 => "HMAC 512/512",
        10 => "AES-CCM-16-64-128",
        11 => "AES-CCM-16-64-256",
        12 => "AES-CCM-64-64-128",
        13 => "AES-CCM-64-64-256",
        14 => "AES-MAC 128/64",
        15 => "AES-MAC 256/64",
        24 => "ChaCha20/Poly1305",
        25 => "AES-MAC 128/128",
        26 => "AES-MAC 256/128",
        30 => "AES-CCM-16-128-128",
        31 => "AES-CCM-16-128-256",
        32 => "AES-CCM-64-128-128",
        33 => "AES-CCM-64-128-256",
        _ => return id.to_string(),
    };
    name.to_string()
}

/// Map a COSE key type (`kty`) to its name.
pub fn kty_name(id: i64) -> String {
    let name = match id {
        1 => "OKP",
        2 => "EC2",
        3 => "RSA",
        4 => "Symmetric",
        5 => "HSS-LMS",
        6 => "WalnutDSA",
        _ => return id.to_string(),
    };
    name.to_string()
}

/// Map a COSE elliptic curve (`crv`) identifier to its name.
pub fn crv_name(id: i64) -> String {
    let name = match id {
        1 => "P-256",
        2 => "P-384",
        3 => "P-521",
        4 => "X25519",
        5 => "X448",
        6 => "Ed25519",
        7 => "Ed448",
        8 => "secp256k1",
        _ => return id.to_string(),
    };
    name.to_string()
}
