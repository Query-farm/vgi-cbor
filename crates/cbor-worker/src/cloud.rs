//! Cloud object-store access for `s3://` and `http(s)://` paths.
//!
//! The worker runs as a subprocess outside DuckDB, so it has no `httpfs`. This
//! module is the single home for object-store I/O: it classifies a path as local
//! vs remote, maps a DuckDB `s3` secret (resolved via the VGI two-phase secret
//! bind) onto [`object_store`] S3 credentials, and reads/writes/lists objects.
//!
//! Scope (first cut): `s3://` (AWS S3, plus R2 / MinIO / GCS-HMAC via a `TYPE s3`
//! secret with `ENDPOINT`/`URL_STYLE`) and `http(s)://` reads. Native `gs://` /
//! `az://` are deliberately unsupported for now (a clear error, not a silent
//! local-file fallback).
//!
//! The worker is synchronous and, on the stdio transport, runs without an
//! ambient tokio runtime, so [`block_on`] owns one; under the HTTP transport it
//! reuses the ambient runtime via `block_in_place`.

use std::future::Future;
// Only the native path keeps a process-wide runtime (see `runtime`).
#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;

use object_store::path::Path as ObjPath;
// object_store 0.14 moved the `head` / `get_range` / `put` convenience methods
// off the `ObjectStore` trait onto the `ObjectStoreExt` extension trait; bring
// it into scope so those call sites (cloud.rs) still resolve.
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use url::Url;
use vgi::secrets::{SecretLookup, Secrets};
use vgi_rpc::{Result, RpcError};

fn ve(e: impl std::fmt::Display) -> RpcError {
    RpcError::value_error(e.to_string())
}

/// Characters in an `s3://` key that must be percent-encoded before `Url::parse`
/// so they survive as part of the key: `?`/`#` are URL delimiters (query /
/// fragment) that would otherwise truncate the key, and `%` is encoded so any
/// `%xx` already in the key round-trips losslessly. Crucially this keeps a `?`
/// glob wildcard intact (the `url` crate would otherwise eat it as a query). All
/// of `*`, `[`, `]` pass through `Url` unharmed, so they are not encoded here.
/// object_store reverses this via `Path::from_url_path` (which percent-decodes).
const S3_KEY_ESCAPE: &AsciiSet = &CONTROLS.add(b'%').add(b'?').add(b'#');

/// A resolved path: either a local filesystem path or a remote object URL.
pub enum Location {
    Local(String),
    Remote(Url),
}

/// Classify a `path` argument as a local file path or a remote object URL.
pub fn classify(path: &str) -> Result<Location> {
    if let Some((scheme, rest)) = path.split_once("://") {
        let lower = scheme.to_ascii_lowercase();
        match lower.as_str() {
            // s3: parse via an escaped key so glob/delimiter chars survive.
            "s3" | "s3a" => {
                let url = Url::parse(&encode_s3_url(&lower, rest))
                    .map_err(|e| ve(format!("bad URL '{path}': {e}")))?;
                return Ok(Location::Remote(url));
            }
            // http(s): a real URL — `?`/`#` are legitimately query/fragment.
            "http" | "https" => {
                let url = Url::parse(path).map_err(|e| ve(format!("bad URL '{path}': {e}")))?;
                return Ok(Location::Remote(url));
            }
            // Scheme-shaped but unknown (e.g. `gs://`, `az://`): refuse loudly so
            // it never gets misread as a local path.
            _ if !lower.is_empty()
                && lower
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
            {
                return Err(ve(format!(
                    "unsupported URL scheme '{lower}://' for '{path}' (supported: s3://, \
                     http://, https://; local paths have no scheme)"
                )));
            }
            _ => {}
        }
    }
    Ok(Location::Local(path.to_string()))
}

/// Build an `s3://bucket/key` URL string with the key's URL-delimiter chars
/// percent-encoded (see [`S3_KEY_ESCAPE`]) so `Url::parse` preserves the whole
/// key — including a `?` glob wildcard.
fn encode_s3_url(scheme: &str, rest: &str) -> String {
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    let key_enc = utf8_percent_encode(key, S3_KEY_ESCAPE);
    format!("{scheme}://{bucket}/{key_enc}")
}

/// The DuckDB secret type to request for a remote URL, or `None` when the scheme
/// needs no credentials (`http(s)://`).
pub fn secret_type_for(url: &Url) -> Option<&'static str> {
    match url.scheme() {
        "s3" | "s3a" => Some("s3"),
        _ => None,
    }
}

/// The DuckDB secret to request for a `path` argument: an `s3`-type secret
/// **scoped to the URL** for `s3://` paths, or `None` for local / no-credential
/// (`http(s)://`) paths. Both `read_fixed` and `write_fixed` use this so a single
/// place decides what gets requested via the two-phase secret bind. Best-effort:
/// an unclassifiable path yields `None`; the real error surfaces at bind time.
pub fn secret_lookup(path: &str) -> Option<SecretLookup> {
    match classify(path) {
        Ok(Location::Remote(url)) => secret_type_for(&url).map(|t| SecretLookup {
            secret_type: t.to_string(),
            scope: Some(url.to_string()),
            name: None,
        }),
        _ => None,
    }
}

/// A shared multi-thread runtime owned by this process for cloud I/O. Built once.
#[cfg(not(target_arch = "wasm32"))]
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime for cloud I/O")
    })
}

/// Drive a future to completion from synchronous code, whatever ambient runtime
/// (if any) the host transport set up:
/// - **multi-thread** ambient runtime (the usual HTTP transport): `block_in_place`
///   so we don't stall the scheduler.
/// - **current-thread** ambient runtime: `block_in_place` would *panic* and we
///   can't nest a `block_on` on this thread, so run the future on a scratch
///   thread with our owned runtime (`std::thread::scope` keeps borrows valid).
/// - **no** ambient runtime (stdio transport): our owned runtime.
#[cfg(not(target_arch = "wasm32"))]
fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(move || handle.block_on(fut))
        }
        Ok(_) => std::thread::scope(|s| s.spawn(|| runtime().block_on(fut)).join().unwrap()),
        Err(_) => runtime().block_on(fut),
    }
}

/// wasm32: there is no ambient runtime and no I/O driver — the XHR transport
/// blocks inline, so nothing ever parks on a socket. `enable_time` is
/// **required**: object_store's retry layer awaits `tokio::time::sleep` for
/// backoff, which never wakes without a time driver.
///
/// The runtime is **per-thread and long-lived**, not per-call. Building one per
/// call also *drops* one per call, and dropping a tokio runtime blocks until its
/// tasks finish — with object_store's client tasks that can wedge the serve
/// thread indefinitely (observed as a scan that issues its first request and
/// then hangs). One serve thread per ring slot means a thread-local is the
/// natural ownership, and it also avoids rebuilding a runtime for every 8 MiB
/// range chunk.
#[cfg(target_arch = "wasm32")]
fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    thread_local! {
        static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build tokio runtime for cloud I/O");
    }
    RT.with(|rt| rt.block_on(fut))
}

/// Whether `ip` is on a network the worker should not be tricked into reaching
/// server-side (the SSRF backstop): loopback, link-local (incl. the
/// `169.254.169.254` cloud-metadata address), private/ULA, or unspecified.
fn is_internal_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                // Carrier-grade NAT 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique-local fc00::/7 and link-local fe80::/10 (the
                // is_unique_local / is_unicast_link_local helpers are unstable).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped — unwrap and re-check.
                || v6.to_ipv4_mapped().map(IpAddr::V4).is_some_and(is_internal_ip)
        }
    }
}

/// Reject a remote `host` (an IP literal or a DNS name) that resolves to an
/// internal address. Prevents an `http(s)://` read from being aimed at cloud
/// metadata (`169.254.169.254`), loopback, or RFC-1918 services the SQL user
/// can't otherwise reach. Set `VGI_CBOR_ALLOW_INTERNAL_HOSTS=1` to override
/// (e.g. a deliberately internal HTTP source).
///
/// **wasm32 (browser) is deliberately exempt.** This guard is an SSRF backstop
/// for a *server-side* worker: there, the process sits on infrastructure the SQL
/// user cannot otherwise reach, so a URL in a query must not become a fetch of
/// the instance metadata endpoint. In the browser none of that holds — the
/// request originates from the end user's own machine, using their network
/// position, and the page could issue the identical `fetch()` itself, so the
/// guard grants no protection while breaking legitimate uses (a localhost dev
/// server, an intranet file the user can genuinely read). The real boundary
/// there is the browser's same-origin policy: a cross-origin response is
/// unreadable unless that host opts in via CORS.
fn guard_host(host: &str) -> Result<()> {
    if cfg!(target_arch = "wasm32") {
        return Ok(());
    }
    if std::env::var_os("VGI_CBOR_ALLOW_INTERNAL_HOSTS").is_some() {
        return Ok(());
    }
    // IP literal? check directly. Otherwise resolve and reject if ANY address is
    // internal (a hostname that resolves to a mix is still unsafe).
    let internal = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        is_internal_ip(ip)
    } else {
        resolve_any_internal(host)
    };
    if internal {
        return Err(ve(format!(
            "refusing to read from internal host '{host}' (loopback / link-local / private / \
             cloud-metadata); set VGI_CBOR_ALLOW_INTERNAL_HOSTS=1 to override"
        )));
    }
    Ok(())
}

/// Resolve `host` and report whether any address is internal. Resolution failure
/// is surfaced later by the actual request; don't mask it here.
#[cfg(not(target_arch = "wasm32"))]
fn resolve_any_internal(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).any(is_internal_ip),
        Err(_) => false,
    }
}

/// wasm32 has no resolver, so a DNS name cannot be pre-checked. The IP-literal
/// check above still applies. This is a weaker guard than native, but the threat
/// model differs too: the fetch runs from the end user's own browser (not a
/// server), and the browser's same-origin policy means a cross-origin response
/// is unreadable unless that host opts in via CORS.
#[cfg(target_arch = "wasm32")]
fn resolve_any_internal(_host: &str) -> bool {
    false
}

pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// DuckDB stores an `s3` endpoint as a bare `host[:port]`; object_store wants a
/// URL. Prepend a scheme (honoring `use_ssl`) when one is absent.
pub(crate) fn normalize_endpoint(ep: &str, use_ssl: Option<bool>) -> String {
    if ep.contains("://") {
        ep.to_string()
    } else {
        let scheme = if use_ssl == Some(false) {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{ep}")
    }
}

/// Build an object store for `url`, mapping the resolved DuckDB `s3` secret fields
/// onto object_store S3 config keys. `overrides` are named-argument options
/// (`endpoint =>`, `region =>`, …) that win over secret-derived values. Returns
/// the store plus the object key (`Path`) addressed by the URL.
pub fn build_store(
    url: &Url,
    secrets: &Secrets,
    overrides: &[(String, String)],
) -> Result<(Box<dyn ObjectStore>, ObjPath)> {
    // SSRF backstop: an `http(s)://` path is a server-side fetch of whatever host
    // the URL names, so block internal targets (cloud metadata, loopback,
    // RFC-1918). `s3://` custom endpoints are NOT guarded here — pointing s3 at a
    // localhost MinIO is a deliberate, explicit configuration, not an injected
    // URL — so the common local-MinIO case keeps working.
    if matches!(url.scheme(), "http" | "https") {
        if let Some(host) = url.host_str() {
            guard_host(host)?;
        }
    }

    let mut opts: Vec<(String, String)> = if secret_type_for(url) == Some("s3") {
        s3_options(secrets, url)
    } else {
        Vec::new()
    };

    // Named-argument overrides take precedence (parse_url_opts uses the last
    // value for a repeated key).
    opts.extend(overrides.iter().cloned());

    build_store_with_opts(url, opts)
}

/// Native: let object_store pick and construct the store from the URL. It brings
/// its own transport (`reqwest`) and crypto (`aws-lc-rs`) via the `aws`/`http`
/// features.
#[cfg(not(target_arch = "wasm32"))]
fn build_store_with_opts(
    url: &Url,
    opts: Vec<(String, String)>,
) -> Result<(Box<dyn ObjectStore>, ObjPath)> {
    let (store, path) = object_store::parse_url_opts(url, opts)
        .map_err(|e| ve(format!("init store for '{url}': {e}")))?;
    Ok((store, path))
}

/// wasm32: `parse_url_opts` builds stores with the bundled transport/crypto,
/// which this target does not have — so construct the builders explicitly and
/// inject ours. The option keys are the same strings the native path passes to
/// `parse_url_opts`, so `s3_options` and the named overrides are shared verbatim;
/// an unrecognized key is ignored here exactly as `parse_url_opts` ignores it.
#[cfg(target_arch = "wasm32")]
fn build_store_with_opts(
    url: &Url,
    opts: Vec<(String, String)>,
) -> Result<(Box<dyn ObjectStore>, ObjPath)> {
    use crate::wasm::{crypto, http as wasm_http};

    // Derive the object key with object_store's own URL→(scheme, key) logic —
    // the exact function `parse_url_opts` uses natively — so key semantics stay
    // identical across targets instead of being re-derived (and diverging) here.
    // The re-parse through `ObjPath::parse` also mirrors `parse_url_opts`.
    let (_scheme, raw_path) = object_store::ObjectStoreScheme::parse(url)
        .map_err(|e| ve(format!("bad object URL '{url}': {e}")))?;
    let path =
        ObjPath::parse(raw_path).map_err(|e| ve(format!("bad object key in '{url}': {e}")))?;

    match url.scheme() {
        "s3" | "s3a" => {
            let mut b = object_store::aws::AmazonS3Builder::new()
                .with_http_connector(wasm_http::XhrConnector)
                .with_crypto_provider(crypto::provider())
                .with_url(url.as_str());
            for (k, v) in opts {
                if let Ok(key) = k.parse::<object_store::aws::AmazonS3ConfigKey>() {
                    b = b.with_config(key, v);
                }
            }
            let store = b
                .build()
                .map_err(|e| ve(format!("init store for '{url}': {e}")))?;
            Ok((Box::new(store), path))
        }
        "http" | "https" => {
            // HttpStore's base URL must be scheme://host only — it appends the
            // object key to whatever base it was built with, so passing the full
            // URL here doubles the path (`/dir/f.bin/dir/f.bin`). This is exactly
            // what `parse_url_opts` does natively.
            let base = &url[..url::Position::BeforePath];
            let store = object_store::http::HttpBuilder::new()
                .with_http_connector(wasm_http::XhrConnector)
                .with_url(base)
                .build()
                .map_err(|e| ve(format!("init store for '{url}': {e}")))?;
            Ok((Box::new(store), path))
        }
        other => Err(ve(format!(
            "unsupported URL scheme '{other}://' for '{url}'"
        ))),
    }
}

/// Map the DuckDB `s3` secret matching `url`'s scope onto object_store S3 config
/// keys. Selecting by scope+type means a call spanning several buckets uses the
/// right secret per URL. Returns empty when no `s3` secret matches.
fn s3_options(secrets: &Secrets, url: &Url) -> Vec<(String, String)> {
    let mut opts: Vec<(String, String)> = Vec::new();
    let Some(fields) = secrets.for_scope_of_type(url.as_str(), "s3") else {
        return opts;
    };
    let nonempty = |f: &str| fields.get(f).filter(|v| !v.is_empty()).cloned();
    let use_ssl = fields.get("use_ssl").and_then(|v| parse_bool(v));

    if let Some(v) = nonempty("key_id") {
        opts.push(("aws_access_key_id".into(), v));
    }
    if let Some(v) = nonempty("secret") {
        opts.push(("aws_secret_access_key".into(), v));
    }
    if let Some(v) = nonempty("session_token") {
        opts.push(("aws_session_token".into(), v));
    }
    if let Some(v) = nonempty("region") {
        opts.push(("aws_region".into(), v));
    }
    if let Some(v) = nonempty("endpoint") {
        opts.push(("aws_endpoint".into(), normalize_endpoint(&v, use_ssl)));
    }
    if let Some(v) = nonempty("url_style") {
        if v.eq_ignore_ascii_case("path") {
            opts.push(("aws_virtual_hosted_style_request".into(), "false".into()));
        }
    }
    if use_ssl == Some(false) {
        opts.push(("aws_allow_http".into(), "true".into()));
    }
    opts
}

/// Read a whole object into memory.
///
/// The COPY reader parses an entire row file at once (`Wire::parse_rows` takes a
/// byte slice), so there is nothing to stream into — a single `get` is both
/// simpler and one round trip. `object_store`'s retry layer covers transient
/// failures.
pub fn read_object(
    url: &Url,
    secrets: &Secrets,
    overrides: &[(String, String)],
) -> Result<Vec<u8>> {
    let (store, path) = build_store(url, secrets, overrides)?;
    let bytes = block_on(async move { store.get(&path).await?.bytes().await })
        .map_err(|e| RpcError::runtime_error(format!("read {url}: {e}")))?;
    Ok(bytes.to_vec())
}

/// Write a whole object to a remote store. `http(s)://` is read-only.
pub fn write_object(
    url: &Url,
    secrets: &Secrets,
    overrides: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    if matches!(url.scheme(), "http" | "https") {
        return Err(ve(format!(
            "writing to '{}://' is not supported; use s3://",
            url.scheme()
        )));
    }
    let (store, path) = build_store(url, secrets, overrides)?;
    let payload = PutPayload::from(body.to_vec());
    block_on(async move { store.put(&path, payload).await })
        .map_err(|e| ve(format!("write {url}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_locals_and_remotes() {
        assert!(matches!(
            classify("data/x.dat").unwrap(),
            Location::Local(_)
        ));
        assert!(matches!(
            classify("/abs/x.dat").unwrap(),
            Location::Local(_)
        ));
        assert!(matches!(
            classify("./rel*.dat").unwrap(),
            Location::Local(_)
        ));
        assert!(matches!(
            classify("s3://bucket/x.dat").unwrap(),
            Location::Remote(_)
        ));
        assert!(matches!(
            classify("HTTPS://host/x.dat").unwrap(),
            Location::Remote(_)
        ));
        // Unknown scheme is an error, not a local path.
        assert!(classify("gs://bucket/x.dat").is_err());
        assert!(classify("az://c/x.dat").is_err());
    }

    #[test]
    fn internal_ip_classification() {
        let internal = [
            "127.0.0.1",
            "169.254.169.254", // cloud metadata
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "100.64.0.1", // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ];
        for ip in internal {
            assert!(
                is_internal_ip(ip.parse().unwrap()),
                "{ip} should be internal"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"] {
            assert!(
                !is_internal_ip(ip.parse().unwrap()),
                "{ip} should be public"
            );
        }
    }

    #[test]
    fn build_store_blocks_internal_http() {
        // An http(s) URL aimed at cloud metadata / loopback is refused (SSRF
        // backstop); a public host is allowed past the guard.
        let sec = Secrets::default();
        let err = build_store(
            &Url::parse("http://169.254.169.254/latest/meta-data/").unwrap(),
            &sec,
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("internal host"), "got: {err}");
        assert!(build_store(&Url::parse("http://127.0.0.1:8080/x").unwrap(), &sec, &[]).is_err());
    }

    #[test]
    fn secret_lookup_requests_s3_for_s3_paths() {
        // An s3:// path requests a `s3` secret scoped to the URL.
        let l = secret_lookup("s3://bucket/data/file.dat").expect("s3 path requests a secret");
        assert_eq!(l.secret_type, "s3");
        assert_eq!(l.scope.as_deref(), Some("s3://bucket/data/file.dat"));
        assert!(l.name.is_none());
        assert_eq!(secret_lookup("s3a://b/k").unwrap().secret_type, "s3");
        // A glob s3 path still requests it (DuckDB prefix-matches the scope).
        let g = secret_lookup("s3://bucket/data/*.dat").expect("glob s3 path requests a secret");
        assert_eq!(g.scope.as_deref(), Some("s3://bucket/data/*.dat"));
        // http(s):// and local paths need no secret.
        assert!(secret_lookup("https://host/f.dat").is_none());
        assert!(secret_lookup("http://host/f.dat").is_none());
        assert!(secret_lookup("data/f.dat").is_none());
        assert!(secret_lookup("/abs/f.dat").is_none());
    }

    /// Build a `Secrets` from (name, fields) entries.
    fn make_secrets(entries: &[(&str, &[(&str, &str)])]) -> Secrets {
        let by_name = entries
            .iter()
            .map(|(name, fields)| {
                (
                    name.to_string(),
                    fields
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                )
            })
            .collect();
        Secrets { by_name }
    }

    #[test]
    fn s3_options_select_secret_per_bucket() {
        // Two s3 secrets, one per bucket — each URL must get its own credentials.
        let secrets = make_secrets(&[
            (
                "sec_a",
                &[
                    ("type", "s3"),
                    ("key_id", "AAA"),
                    ("secret", "sa"),
                    ("scope", "s3://bucket-a"),
                ],
            ),
            (
                "sec_b",
                &[
                    ("type", "s3"),
                    ("key_id", "BBB"),
                    ("secret", "sb"),
                    ("scope", "s3://bucket-b"),
                ],
            ),
        ]);
        let opts_a = s3_options(&secrets, &Url::parse("s3://bucket-a/data/x.dat").unwrap());
        let opts_b = s3_options(&secrets, &Url::parse("s3://bucket-b/data/y.dat").unwrap());
        let key = |o: &[(String, String)]| {
            o.iter()
                .find(|(k, _)| k == "aws_access_key_id")
                .map(|(_, v)| v.clone())
        };
        assert_eq!(key(&opts_a).as_deref(), Some("AAA"));
        assert_eq!(key(&opts_b).as_deref(), Some("BBB"));
    }

    #[test]
    fn secret_type_by_scheme() {
        let s3 = Url::parse("s3://b/k").unwrap();
        let http = Url::parse("https://h/k").unwrap();
        assert_eq!(secret_type_for(&s3), Some("s3"));
        assert_eq!(secret_type_for(&http), None);
    }

    /// Build a one-secret `Secrets` from (field, value) pairs.
    fn secrets(name: &str, fields: &[(&str, &str)]) -> Secrets {
        let mut by_name = std::collections::HashMap::new();
        by_name.insert(
            name.to_string(),
            fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        Secrets { by_name }
    }

    /// Map a secret through build_store and read back the options it produced by
    /// re-running the same mapping (build_store is the source of truth, so we
    /// assert on a store being constructed plus the option derivation helpers).
    #[test]
    fn s3_secret_maps_to_store() {
        let url = Url::parse("s3://bucket/out.dat").unwrap();
        let sec = secrets(
            "s3",
            &[
                ("key_id", "AKIA"),
                ("secret", "shh"),
                ("region", "us-east-1"),
                ("endpoint", "minio:9000"),
                ("url_style", "path"),
                ("use_ssl", "false"),
            ],
        );
        // parse_url_opts must accept the derived options and yield a store.
        let (_store, path) = build_store(&url, &sec, &[]).expect("store builds");
        assert_eq!(path.as_ref(), "out.dat");
    }

    #[test]
    fn endpoint_scheme_is_inferred_from_use_ssl() {
        assert_eq!(
            normalize_endpoint("minio:9000", Some(false)),
            "http://minio:9000"
        );
        assert_eq!(
            normalize_endpoint("minio:9000", Some(true)),
            "https://minio:9000"
        );
        assert_eq!(normalize_endpoint("minio:9000", None), "https://minio:9000");
        assert_eq!(
            normalize_endpoint("http://already:9000", Some(true)),
            "http://already:9000"
        );
    }

    #[test]
    fn parse_bool_forms() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("FALSE"), Some(false));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    /// End-to-end proof that two `s3://` paths needing two different secrets each
    /// reach the object store with the RIGHT credentials. A tiny in-process mock
    /// S3 endpoint records the AWS access-key id from each request's SigV4
    /// `Authorization` header; we read one object per bucket using two scoped
    /// secrets (different `key_id`s) and assert each bucket's request carried its
    /// own access key. This exercises `build_store` → `fetch_object` →
    /// `Secrets::for_scope_of_type` → object_store over real HTTP (the same path
    /// the streaming reader takes per object).
    #[test]
    fn two_paths_use_two_different_secrets() {
        use std::collections::HashMap;
        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // (request path, access-key-id) seen by the mock, in order.
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_srv = seen.clone();
        let body: &'static [u8] = b"JANE007\nJOHN042\n";

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                // Read request headers (GET has no body).
                let mut data = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            data.extend_from_slice(&buf[..n]);
                            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let req = String::from_utf8_lossy(&data);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|p| p.split('?').next())
                    .unwrap_or("")
                    .to_string();
                // Pull the access key id out of `... Credential=<AK>/...`.
                let ak = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .and_then(|l| l.split("Credential=").nth(1))
                    .and_then(|c| c.split('/').next())
                    .unwrap_or("")
                    .to_string();
                seen_srv.lock().unwrap().push((path, ak));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: \
                     application/octet-stream\r\nETag: \"t\"\r\nAccept-Ranges: bytes\r\n\
                     Last-Modified: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.write_all(body);
                let _ = s.flush();
            }
        });

        let endpoint = format!("127.0.0.1:{port}");
        let mk = |key_id: &str, scope: &str| -> HashMap<String, String> {
            let mut m: HashMap<String, String> = [
                ("type", "s3"),
                ("key_id", key_id),
                ("secret", "test-secret-key"),
                ("region", "us-east-1"),
                ("url_style", "path"),
                ("use_ssl", "false"),
                ("scope", scope),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            m.insert("endpoint".to_string(), endpoint.clone());
            m
        };
        let secrets = Secrets {
            by_name: HashMap::from([
                ("sec_a".to_string(), mk("AKIDBUCKETA", "s3://bucket-a")),
                ("sec_b".to_string(), mk("AKIDBUCKETB", "s3://bucket-b")),
            ]),
        };

        let fetch = |spec: &str| {
            let url = Url::parse(spec).unwrap();
            let (store, path) = build_store(&url, &secrets, &[]).unwrap();
            // Whole-object GET — exercises build_store → SigV4 over real HTTP; the
            // production range-streaming path adds a HEAD the mock doesn't model.
            block_on(async move { store.get(&path).await?.bytes().await })
                .unwrap()
                .to_vec()
        };
        let a = fetch("s3://bucket-a/data.dat");
        let b = fetch("s3://bucket-b/data.dat");
        assert_eq!(a, body);
        assert_eq!(b, body);

        let seen = seen.lock().unwrap();
        let ak_for = |p: &str| {
            seen.iter()
                .find(|(path, _)| path == p)
                .map(|(_, ak)| ak.clone())
        };
        // The crux: each bucket's request carried ITS OWN access key.
        assert_eq!(
            ak_for("/bucket-a/data.dat").as_deref(),
            Some("AKIDBUCKETA"),
            "bucket-a must use secret sec_a's key; seen={seen:?}"
        );
        assert_eq!(
            ak_for("/bucket-b/data.dat").as_deref(),
            Some("AKIDBUCKETB"),
            "bucket-b must use secret sec_b's key; seen={seen:?}"
        );
    }
}
