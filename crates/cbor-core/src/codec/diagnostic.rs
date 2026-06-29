//! RFC 8949 §8 Extended Diagnostic Notation (EDN) renderer — the human-debug
//! surface. Unlike `to_json` it preserves tags (`1(...)`), byte strings (`h'..'`),
//! and the distinction between `null` and `undefined`.

use ciborium::value::Value;

use crate::value::{int_i128, parse_strict, DecodeError};

/// Render the diagnostic notation for a CBOR blob. Always succeeds for
/// well-formed input.
pub fn diagnostic(bytes: &[u8]) -> Result<String, DecodeError> {
    let value = parse_strict(bytes)?;
    let mut out = String::new();
    render(&value, &mut out);
    Ok(out)
}

/// Render a value into the EDN buffer.
pub fn render(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Integer(i) => out.push_str(&int_i128(i).to_string()),
        Value::Float(f) => render_float(*f, out),
        Value::Text(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Bytes(b) => {
            out.push_str("h'");
            out.push_str(&hex::encode(b));
            out.push('\'');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(k, out);
                out.push_str(": ");
                render(v, out);
            }
            out.push('}');
        }
        Value::Tag(tag, inner) => {
            out.push_str(&tag.to_string());
            out.push('(');
            render(inner, out);
            out.push(')');
        }
        _ => out.push_str("undefined"),
    }
}

fn render_float(f: f64, out: &mut String) {
    if f.is_nan() {
        out.push_str("NaN");
    } else if f.is_infinite() {
        out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
    } else if f == f.trunc() && f.abs() < 1e16 {
        // Keep a trailing `.0` so the value reads as a float in EDN.
        out.push_str(&format!("{f:.1}"));
    } else {
        out.push_str(&f.to_string());
    }
}
