//! Rust reference verifier for DF-VERIFY/1 Ed25519-signed responses.
//!
//! Spec: <https://dynamicfeed.ai/standard>. Reproduces the `json-sorted-compact`
//! canonicalization byte-for-byte (keys sorted recursively, compact separators,
//! non-ASCII escaped `\uXXXX` including astral surrogate pairs, top-level
//! `signature` stripped, numbers verbatim) and checks the detached Ed25519
//! signature against the published key. The cardinal rule it enforces:
//! **signed != verified** — a signature proves integrity, not truth.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonicalize a payload to the exact bytes that were signed.
/// Equivalent to Python `json.dumps(payload_without_top_level_signature,
/// sort_keys=True, separators=(",", ":"))` with default `ensure_ascii=True`.
pub fn canonical(env: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    match env {
        // strip the top-level `signature` field only
        Value::Object(map) => {
            out.push(b'{');
            let sorted: BTreeMap<&String, &Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "signature")
                .collect();
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(k, &mut out);
                out.push(b':');
                write_value(v, &mut out);
            }
            out.push(b'}');
        }
        other => write_value(other, &mut out),
    }
    out
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        // arbitrary_precision: the Number serializes back to its exact source text
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(e, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(k, out);
                out.push(b':');
                write_value(val, out);
            }
            out.push(b'}');
        }
    }
}

/// String escaping matching Python's json encoder with `ensure_ascii=True`.
fn write_str(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) >= 0x20 && (c as u32) <= 0x7e => out.push(c as u8),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.extend_from_slice(format!("\\u{:04x}", cp).as_bytes());
                } else {
                    // emit a UTF-16 surrogate pair, like Python's ensure_ascii
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.extend_from_slice(format!("\\u{:04x}\\u{:04x}", hi, lo).as_bytes());
                }
            }
        }
    }
    out.push(b'"');
}

fn b64url(s: &str) -> Result<Vec<u8>, String> {
    // tolerate missing padding, like Python's urlsafe_b64decode after re-padding
    let t = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .map_err(|e| format!("base64: {e}"))
}

/// Verify a signed envelope against a `key_id -> base64url public key` map.
/// Returns Ok(true) only if the detached Ed25519 signature over the canonical
/// bytes checks out. Never panics on malformed input; returns Ok(false)/Err.
pub fn verify(env: &Value, keys: &serde_json::Map<String, Value>) -> Result<bool, String> {
    let sig = env
        .get("signature")
        .and_then(|s| s.as_object())
        .ok_or("no signature object")?;
    let key_id = sig
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("no key_id")?;
    let sig_b64 = sig.get("sig").and_then(|v| v.as_str()).ok_or("no sig")?;
    let pk_b64 = keys
        .get(key_id)
        .and_then(|v| v.as_str())
        .ok_or("unknown key_id")?;

    let pk_bytes = b64url(pk_b64)?;
    let sig_bytes = b64url(sig_b64)?;
    let pk: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key not 32 bytes")?;
    let sg: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature not 64 bytes")?;

    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("bad key: {e}"))?;
    let signature = Signature::from_bytes(&sg);
    Ok(vk.verify(&canonical(env), &signature).is_ok())
}

/// Parse with `arbitrary_precision` so numbers keep their exact source text.
pub fn parse(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("json: {e}"))
}
