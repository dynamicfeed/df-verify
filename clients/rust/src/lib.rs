//! # dynamicfeed-verify — Ed25519 and lifecycle-policy verifier for DF-VERIFY/1
//!
//! Signed [Dynamic Feed](https://dynamicfeed.ai) response profiles use a JSON envelope carrying a
//! top-level `"signature"` block:
//!
//! ```json
//! {
//!   "...payload fields...": "...",
//!   "signature": {
//!     "alg": "Ed25519",
//!     "key_id": "df-ed25519-…",
//!     "canonicalization": "json-sorted-compact",
//!     "sig": "<base64url>"
//!   }
//! }
//! ```
//!
//! The signature covers the **canonical bytes** of the envelope: the JSON object *without* its
//! `"signature"` field, serialized exactly like Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"))` — sorted keys, compact separators,
//! and `ensure_ascii` escaping (every non-ASCII character becomes `\uXXXX`, astral characters
//! become a surrogate pair `\uD8xx\uDCxx`).
//!
//! ## The two canonicalization traps
//!
//! This crate handles the same two traps as the Python and JavaScript clients in this repository:
//!
//! 1. **`ensure_ascii` escaping.** The server canonicalizes with Python's default
//!    `ensure_ascii=True`, but responses travel over the wire as raw UTF-8 (the wire says `"°C"`).
//!    A verifier must re-escape every non-ASCII character back to its ASCII `\uXXXX` form
//!    (`°` becomes `\u00b0`) before checking the signature.
//! 2. **Lossless numbers.** Numbers must round-trip *exactly* as they appear in the source text.
//!    Parsing `-50.0` into an `f64` and re-printing it can change the spelling (`1e-07` vs
//!    `1e-7`, `-50.0` vs `-50`), which flips bytes and breaks the signature. This crate uses its
//!    own small JSON parser that keeps every number **verbatim** as a text slice — the same
//!    approach as `web/verify.js` — so no float formatting is ever involved.
//!
//! ## Quick start (no network)
//!
//! ```no_run
//! let envelope_text = std::fs::read_to_string("envelope.json").unwrap();
//! let pubkey_b64 = "acMWky59eQfoVqCUgmUM3tcl35YioRngL4wVDIQsstg="; // active key from /.well-known/keys
//! let v = dynamicfeed_verify::verify_envelope(&envelope_text, pubkey_b64).unwrap();
//! assert!(v.valid); // Ed25519 mathematics only; lifecycle policy is not evaluated here
//! println!("CRYPTO_VALID — key_id={}", v.key_id);
//! ```
//!
//! With the optional `fetch` feature, [`fetch_keys`] retrieves cryptographic key bytes from
//! `https://dynamicfeed.ai/.well-known/keys` (a flat `{ "<key_id>": "<base64 pubkey>", ... }`
//! map. That endpoint contains key bytes only and cannot establish lifecycle acceptance.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// The published JWKS endpoint for dynamicfeed.ai.
pub const DEFAULT_KEYS_URL: &str = "https://dynamicfeed.ai/.well-known/keys";
/// The lifecycle-policy endpoint used by policy-aware clients.
pub const DEFAULT_LIFECYCLE_URL: &str =
    "https://dynamicfeed.ai/.well-known/signing-key-registry.json";
/// Minimum lifecycle-registry revision this release will accept for live verification.
pub const COMPILED_MIN_REGISTRY_REVISION: u64 = 1;

/// Whether a lifecycle document is being used for a live policy decision or inspected as a
/// deliberately non-actionable historical snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VerificationMode {
    #[default]
    Live,
    HistoricalSnapshot,
}

/// Caller-retained anti-rollback inputs for lifecycle-registry validation.
///
/// A registry's self-declared revision is not an independent anti-rollback mechanism. Callers
/// that authenticate a revision must persist it outside the registry and pass it back through
/// `highest_authenticated_registry_revision` on every later live verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryValidationOptions {
    pub mode: VerificationMode,
    pub minimum_registry_revision: Option<u64>,
    pub highest_authenticated_registry_revision: Option<u64>,
    /// Set only after authenticating caller-supplied/custom-origin registry material. Live signer
    /// acceptance remains false when this is false.
    pub registry_source_authenticated: bool,
}

impl Default for RegistryValidationOptions {
    fn default() -> Self {
        Self {
            mode: VerificationMode::Live,
            minimum_registry_revision: None,
            highest_authenticated_registry_revision: None,
            registry_source_authenticated: false,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

/// Everything that can go wrong while parsing or verifying an envelope.
///
/// Note: a *well-formed* envelope whose signature simply doesn't match is **not** an error —
/// [`verify_envelope`] returns `Ok(Verification { valid: false, .. })` for that case. `Err` means
/// the input was structurally unusable (bad JSON, missing signature block, undecodable key…).
#[derive(Debug)]
pub enum Error {
    /// The input is not valid JSON (position/context in the message).
    Json(String),
    /// The top-level JSON value is not an object.
    NotAnObject,
    /// The envelope has no top-level `"signature"` object.
    NoSignature,
    /// The `"signature"` block is missing a required field or has the wrong type.
    BadSignatureBlock(String),
    /// A base64 / base64url field failed to decode.
    Base64(String),
    /// The public key bytes are not a valid Ed25519 key (or wrong length).
    Key(String),
    /// The envelope's `key_id` was not found in the supplied [`Keys`].
    UnknownKeyId(String),
    /// The signing-key lifecycle registry is missing, malformed, or inconsistent.
    Lifecycle(String),
    /// Network or HTTP failure while fetching keys (only with the `fetch` feature).
    #[cfg(feature = "fetch")]
    Fetch(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(m) => write!(f, "invalid JSON — {m}"),
            Error::NotAnObject => write!(f, "expected a top-level JSON object"),
            Error::NoSignature => write!(f, "no \"signature\" block in this envelope"),
            Error::BadSignatureBlock(m) => write!(f, "bad signature block — {m}"),
            Error::Base64(m) => write!(f, "base64 decode failed — {m}"),
            Error::Key(m) => write!(f, "bad public key — {m}"),
            Error::UnknownKeyId(id) => {
                write!(f, "key_id {id} not in the supplied keys (rotated?)")
            }
            Error::Lifecycle(m) => write!(f, "invalid signing-key lifecycle registry — {m}"),
            #[cfg(feature = "fetch")]
            Error::Fetch(m) => write!(f, "could not fetch keys — {m}"),
        }
    }
}

impl std::error::Error for Error {}

// ------------------------------------------------------------------------------------------------
// Lossless JSON parse (numbers kept VERBATIM, mirroring web/verify.js `lparse`)
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Node {
    /// Key/value pairs in source order (canonicalization sorts them later).
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
    Str(String),
    /// Number kept exactly as it appeared in the source text — never re-formatted.
    Num(String),
    Bool(bool),
    Null,
}

struct Parser {
    chars: Vec<char>,
    i: usize,
}

impl Parser {
    fn new(s: &str) -> Self {
        Parser {
            chars: s.chars().collect(),
            i: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: char) -> Result<(), Error> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(Error::Json(format!(
                "expected '{c}' at char {} (found {:?})",
                self.i,
                self.peek()
            )))
        }
    }

    fn literal(&mut self, lit: &str) -> Result<(), Error> {
        for c in lit.chars() {
            if self.peek() != Some(c) {
                return Err(Error::Json(format!("bad literal at char {}", self.i)));
            }
            self.i += 1;
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Node, Error> {
        self.ws();
        match self.peek() {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(Node::Str(self.string()?)),
            Some('t') => self.literal("true").map(|_| Node::Bool(true)),
            Some('f') => self.literal("false").map(|_| Node::Bool(false)),
            Some('n') => self.literal("null").map(|_| Node::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(Error::Json(format!("unexpected '{c}' at char {}", self.i))),
            None => Err(Error::Json("unexpected end of input".into())),
        }
    }

    fn object(&mut self) -> Result<Node, Error> {
        self.expect('{')?;
        let mut pairs = Vec::new();
        let mut seen = BTreeSet::new();
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(Node::Object(pairs));
        }
        loop {
            self.ws();
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(Error::Json(format!(
                    "duplicate object key '{key}' at char {}",
                    self.i
                )));
            }
            self.ws();
            self.expect(':')?;
            let val = self.value()?;
            pairs.push((key, val));
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                }
                Some('}') => {
                    self.i += 1;
                    break;
                }
                _ => {
                    return Err(Error::Json(format!(
                        "expected ',' or '}}' at char {}",
                        self.i
                    )))
                }
            }
        }
        Ok(Node::Object(pairs))
    }

    fn array(&mut self) -> Result<Node, Error> {
        self.expect('[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(Node::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                }
                Some(']') => {
                    self.i += 1;
                    break;
                }
                _ => {
                    return Err(Error::Json(format!(
                        "expected ',' or ']' at char {}",
                        self.i
                    )))
                }
            }
        }
        Ok(Node::Array(items))
    }

    fn hex4(&mut self) -> Result<u16, Error> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self
                .peek()
                .ok_or_else(|| Error::Json("truncated \\u escape".into()))?;
            let d = c
                .to_digit(16)
                .ok_or_else(|| Error::Json(format!("bad \\u escape at char {}", self.i)))?;
            v = (v << 4) | d as u16;
            self.i += 1;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, Error> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| Error::Json("unterminated string".into()))?;
            self.i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let e = self
                        .peek()
                        .ok_or_else(|| Error::Json("truncated escape".into()))?;
                    self.i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                // high surrogate — must be followed by \uDCxx low surrogate
                                if self.peek() == Some('\\') {
                                    self.i += 1;
                                    if self.peek() == Some('u') {
                                        self.i += 1;
                                        let lo = self.hex4()?;
                                        if (0xDC00..0xE000).contains(&lo) {
                                            let cp = 0x10000
                                                + (((hi as u32) - 0xD800) << 10)
                                                + ((lo as u32) - 0xDC00);
                                            out.push(char::from_u32(cp).ok_or_else(|| {
                                                Error::Json("bad surrogate pair".into())
                                            })?);
                                            continue;
                                        }
                                    }
                                }
                                return Err(Error::Json(format!(
                                    "lone high surrogate \\u{hi:04x} at char {}",
                                    self.i
                                )));
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(Error::Json(format!(
                                    "lone low surrogate \\u{hi:04x} at char {}",
                                    self.i
                                )));
                            }
                            out.push(
                                char::from_u32(hi as u32)
                                    .ok_or_else(|| Error::Json("bad \\u escape".into()))?,
                            );
                        }
                        other => {
                            return Err(Error::Json(format!(
                                "bad escape '\\{other}' at char {}",
                                self.i
                            )))
                        }
                    }
                }
                other if (other as u32) < 0x20 => {
                    return Err(Error::Json(format!(
                        "unescaped control character at char {}",
                        self.i - 1
                    )))
                }
                other => out.push(other),
            }
        }
    }

    fn number(&mut self) -> Result<Node, Error> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        match self.peek() {
            Some('0') => {
                self.i += 1;
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    return Err(Error::Json(format!(
                        "leading zero in number at char {start}"
                    )));
                }
            }
            Some('1'..='9') => {
                self.i += 1;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(Error::Json(format!("expected a number at char {start}"))),
        }
        if self.peek() == Some('.') {
            self.i += 1;
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err(Error::Json(format!(
                    "missing fraction digits at char {}",
                    self.i
                )));
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err(Error::Json(format!(
                    "missing exponent digits at char {}",
                    self.i
                )));
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        Ok(Node::Num(self.chars[start..self.i].iter().collect()))
    }
}

/// Parse the envelope text and return the top-level object's pairs in source order.
fn parse_object(text: &str) -> Result<Vec<(String, Node)>, Error> {
    let mut p = Parser::new(text);
    let root = p.value()?;
    p.ws();
    if p.i != p.chars.len() {
        return Err(Error::Json(format!("trailing data at char {}", p.i)));
    }
    match root {
        Node::Object(pairs) => Ok(pairs),
        _ => Err(Error::NotAnObject),
    }
}

/// Validate a JSON object with the verifier's strict parser without canonicalizing it.
/// Duplicate object names, malformed numbers, raw controls, and trailing bytes fail closed.
pub fn validate_json_strict(json_text: &str) -> Result<(), Error> {
    parse_object(json_text).map(|_| ())
}

// ------------------------------------------------------------------------------------------------
// Canonicalization (json-sorted-compact, Python json.dumps ensure_ascii semantics)
// ------------------------------------------------------------------------------------------------

/// Escape a string exactly like Python `json.dumps(..., ensure_ascii=True)`:
/// `"` `\` and the named control escapes, `\uXXXX` for other control chars and ALL non-ASCII,
/// surrogate-pair `\uD8xx\uDCxx` escapes for astral characters.
fn py_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        let c = ch as u32;
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            _ if c < 0x20 => {
                out.push_str(&format!("\\u{c:04x}"));
            }
            _ if c <= 0x7E => out.push(ch),
            _ if c > 0xFFFF => {
                let x = c - 0x10000;
                out.push_str(&format!(
                    "\\u{:04x}\\u{:04x}",
                    0xD800 + (x >> 10),
                    0xDC00 + (x & 0x3FF)
                ));
            }
            _ => out.push_str(&format!("\\u{c:04x}")),
        }
    }
    out.push('"');
}

fn canon(node: &Node, out: &mut String) {
    match node {
        Node::Object(pairs) => {
            // Sorted keys. The parser has already rejected duplicate object names.
            // Rust &str ordering is byte-wise UTF-8 == Unicode code-point order == Python's sort.
            let mut map: BTreeMap<&str, &Node> = BTreeMap::new();
            for (k, v) in pairs {
                map.insert(k.as_str(), v);
            }
            out.push('{');
            for (n, (k, v)) in map.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                py_string(k, out);
                out.push(':');
                canon(v, out);
            }
            out.push('}');
        }
        Node::Array(items) => {
            out.push('[');
            for (n, v) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                canon(v, out);
            }
            out.push(']');
        }
        Node::Str(s) => py_string(s, out),
        Node::Num(t) => out.push_str(t), // VERBATIM — the whole point
        Node::Bool(true) => out.push_str("true"),
        Node::Bool(false) => out.push_str("false"),
        Node::Null => out.push_str("null"),
    }
}

fn canonical_string_dropping(pairs: &[(String, Node)], drop: &[&str]) -> String {
    let stripped: Vec<(String, Node)> = pairs
        .iter()
        .filter(|(k, _)| !drop.contains(&k.as_str()))
        .cloned()
        .collect();
    let mut out = String::new();
    canon(&Node::Object(stripped), &mut out);
    out
}

fn canonical_string(pairs: &[(String, Node)]) -> String {
    canonical_string_dropping(pairs, &["signature"])
}

/// Compute the canonical bytes of a signed envelope: the JSON object **without** its
/// `"signature"` field, serialized as `json-sorted-compact` with Python `ensure_ascii`
/// escaping and verbatim (never re-formatted) numbers.
///
/// These are exactly the bytes the Ed25519 signature covers, byte-identical with
/// `json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")`.
pub fn canonical_bytes(envelope_json_text: &str) -> Result<Vec<u8>, Error> {
    let pairs = parse_object(envelope_json_text)?;
    Ok(canonical_string(&pairs).into_bytes())
}

// ------------------------------------------------------------------------------------------------
// Base64url (strict padded or unpadded form — matches the Python and JavaScript clients)
// ------------------------------------------------------------------------------------------------

fn b64_decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.is_empty() || s.trim() != s {
        return Err(Error::Base64(
            "base64url must not contain whitespace".into(),
        ));
    }
    let padding = s.len() - s.trim_end_matches('=').len();
    let core = s.trim_end_matches('=');
    if padding > 2
        || (padding > 0 && (s.len() & 3) != 0)
        || core.len() % 4 == 1
        || !core
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Error::Base64("invalid base64url".into()));
    }
    let cleaned: String = core
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    STANDARD_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|e| Error::Base64(e.to_string()))
}

// ------------------------------------------------------------------------------------------------
// Verification
// ------------------------------------------------------------------------------------------------

/// The outcome of low-level cryptographic verification. `valid` does not evaluate key lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// `true` iff Ed25519 mathematics, algorithm metadata, and key-id binding are valid.
    /// This is not signer acceptance; use [`verify_with_registry`] for lifecycle policy.
    pub valid: bool,
    /// The `key_id` declared in the envelope's signature block.
    pub key_id: String,
    /// The declared algorithm (expected `"Ed25519"`).
    pub alg: Option<String>,
    /// The declared canonicalization (expected `"json-sorted-compact"`).
    pub canonicalization: Option<String>,
    /// `Some(true)` when an attached `anchor` was inside the verified signature scope,
    /// `Some(false)` for the frozen legacy convention where it was attached after signing,
    /// and `None` when no anchor is present or no signature form passed.
    pub anchor_authenticated: Option<bool>,
}

fn find<'a>(pairs: &'a [(String, Node)], key: &str) -> Option<&'a Node> {
    // last occurrence wins, matching Python dict semantics
    pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn str_field(pairs: &[(String, Node)], key: &str) -> Option<String> {
    match find(pairs, key) {
        Some(Node::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

struct SigBlock {
    key_id: String,
    sig_b64: String,
    alg: Option<String>,
    canonicalization: Option<String>,
}

fn signature_block(pairs: &[(String, Node)]) -> Result<SigBlock, Error> {
    let sig_node = find(pairs, "signature").ok_or(Error::NoSignature)?;
    let sig_pairs = match sig_node {
        Node::Object(p) => p,
        _ => {
            return Err(Error::BadSignatureBlock(
                "\"signature\" is not an object".into(),
            ))
        }
    };
    let key_id = str_field(sig_pairs, "key_id")
        .ok_or_else(|| Error::BadSignatureBlock("missing key_id".into()))?;
    let sig_b64 = str_field(sig_pairs, "sig")
        .ok_or_else(|| Error::BadSignatureBlock("missing sig".into()))?;
    Ok(SigBlock {
        key_id,
        sig_b64,
        alg: str_field(sig_pairs, "alg"),
        canonicalization: str_field(sig_pairs, "canonicalization"),
    })
}

/// Return the `key_id` declared in an envelope's signature block (without verifying anything).
/// Useful for looking the key up in a [`Keys`] set first.
pub fn signature_key_id(envelope_json_text: &str) -> Result<String, Error> {
    let pairs = parse_object(envelope_json_text)?;
    Ok(signature_block(&pairs)?.key_id)
}

/// Verify a signed Dynamic Feed envelope against an Ed25519 public key
/// (strict base64url, padded or not — as published at `/.well-known/keys`).
///
/// Returns `Ok(Verification { valid: false, .. })` when the envelope is well-formed but the
/// signature does not match (e.g. tampered payload); returns `Err` only for structural problems.
/// Entirely offline — no network access.
pub fn verify_envelope(envelope_json_text: &str, pubkey_b64: &str) -> Result<Verification, Error> {
    let pairs = parse_object(envelope_json_text)?;
    let sig = signature_block(&pairs)?;

    let pk_bytes = b64_decode(pubkey_b64)?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Key(format!("expected 32 bytes, got {}", pk_bytes.len())))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| Error::Key(e.to_string()))?;
    let fingerprint = Sha256::digest(pk_arr);
    let expected_key_id = format!(
        "df-ed25519-{}",
        fingerprint[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    let sig_bytes = b64_decode(&sig.sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::BadSignatureBlock(format!("sig: expected 64 bytes, got {}", sig_bytes.len()))
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    // Two anchor conventions coexist: some receipts sign the body BEFORE a timestamp anchor is
    // attached (an RFC 3161 / DLT anchor is OF the signed hash, so it can only land after signing —
    // e.g. /v1/answer, /v1/receipt), others sign WITH the anchor already inside the bytes (e.g.
    // notary inclusion proofs). Try the strip-signature form first; if it fails and an `anchor` is
    // present, retry with the anchor stripped too. Accepting either canonical form is not a
    // weakening — a forgery still needs a valid Ed25519 signature over one of the two forms.
    let metadata_valid = sig.alg.as_deref() == Some("Ed25519")
        && sig.canonicalization.as_deref() == Some("json-sorted-compact")
        && sig.key_id == expected_key_id;
    let has_anchor = pairs.iter().any(|(k, _)| k == "anchor");
    let mut valid = metadata_valid
        && vk
            .verify(&canonical_string(&pairs).into_bytes(), &signature)
            .is_ok();
    let mut anchor_authenticated = if valid && has_anchor {
        Some(true)
    } else {
        None
    };
    if metadata_valid && !valid && has_anchor {
        let msg = canonical_string_dropping(&pairs, &["signature", "anchor"]).into_bytes();
        valid = vk.verify(&msg, &signature).is_ok();
        if valid {
            anchor_authenticated = Some(false);
        }
    }

    Ok(Verification {
        valid,
        key_id: sig.key_id,
        alg: sig.alg,
        canonicalization: sig.canonicalization,
        anchor_authenticated,
    })
}

// ------------------------------------------------------------------------------------------------
// Keys (the /.well-known/keys JWKS shape)
// ------------------------------------------------------------------------------------------------

/// The published key set from `GET https://dynamicfeed.ai/.well-known/keys`.
///
/// On the wire this is a flat map — `{ "<key_id>": "<base64 pubkey>", "signature": {...} }` —
/// i.e. the keys document is itself a signed envelope. [`Keys::parse`] accepts that live shape
/// (top-level string fields, the `signature` block excluded) as well as the nested
/// `{ "keys": { "<key_id>": "<base64 pubkey>" } }` variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    map: BTreeMap<String, String>,
}

impl Keys {
    /// Parse a keys document (see type-level docs for the accepted shapes).
    pub fn parse(json_text: &str) -> Result<Keys, Error> {
        let pairs = parse_object(json_text)?;
        let source: &[(String, Node)] = match find(&pairs, "keys") {
            Some(Node::Object(inner)) => inner,
            _ => &pairs,
        };
        let mut map = BTreeMap::new();
        for (k, v) in source {
            if k == "signature" {
                continue;
            }
            if let Node::Str(s) = v {
                map.insert(k.clone(), s.clone());
            }
        }
        if map.is_empty() {
            return Err(Error::Key(
                "no public keys found in the keys document".into(),
            ));
        }
        Ok(Keys { map })
    }

    /// Look up a public key (base64) by `key_id`.
    pub fn get(&self, key_id: &str) -> Option<&str> {
        self.map.get(key_id).map(|s| s.as_str())
    }

    /// All known key ids.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(|s| s.as_str())
    }

    /// Number of keys in the set.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the set is empty (never true for a successfully parsed document).
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Fetch and parse the key set from a URL (requires the `fetch` feature).
    #[cfg(feature = "fetch")]
    pub fn fetch(url: &str) -> Result<Keys, Error> {
        let body = ureq::AgentBuilder::new()
            .redirects(0)
            .build()
            .get(url)
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .map_err(|e| Error::Fetch(e.to_string()))?
            .into_string()
            .map_err(|e| Error::Fetch(e.to_string()))?;
        Keys::parse(&body)
    }
}

/// Fetch the published key set (defaults: [`DEFAULT_KEYS_URL`]). Requires the `fetch` feature.
#[cfg(feature = "fetch")]
pub fn fetch_keys(url: &str) -> Result<Keys, Error> {
    Keys::fetch(url)
}

// ------------------------------------------------------------------------------------------------
// Signing-key lifecycle policy
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleStatus {
    Active,
    Retired,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct LifecycleRegistry {
    keys: Keys,
    active_key_id: String,
    statuses: BTreeMap<String, LifecycleStatus>,
    registry_revision: u64,
    effective_registry_floor: u64,
    mode: VerificationMode,
    registry_source_authenticated: bool,
    highest_authenticated_registry_revision: Option<u64>,
}

fn object_field<'a>(pairs: &'a [(String, Node)], key: &str) -> Result<&'a [(String, Node)], Error> {
    match find(pairs, key) {
        Some(Node::Object(inner)) => Ok(inner),
        _ => Err(Error::Lifecycle(format!("{key} must be an object"))),
    }
}

fn bool_field(pairs: &[(String, Node)], key: &str) -> Option<bool> {
    match find(pairs, key) {
        Some(Node::Bool(value)) => Some(*value),
        _ => None,
    }
}

fn positive_u64_field(pairs: &[(String, Node)], key: &str) -> Result<u64, Error> {
    match find(pairs, key) {
        Some(Node::Num(value)) => value
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::Lifecycle(format!("{key} must be a positive integer"))),
        _ => Err(Error::Lifecycle(format!(
            "{key} must be a positive integer"
        ))),
    }
}

fn null_field(pairs: &[(String, Node)], key: &str) -> bool {
    matches!(find(pairs, key), Some(Node::Null))
}

fn utc_timestamp_key(value: &str) -> Option<(u32, u32, u32, u32, u32, u32, u32)> {
    // Registry timestamps are canonical UTC RFC3339. Validate the calendar components rather than
    // accepting normalizing parsers (e.g. February 30 -> March 2).
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().unwrap_or(&0) != b'Z'
    {
        return None;
    }
    let parse = |a: usize, b: usize| value[a..b].parse::<u32>().ok();
    let (year, month, day, hour, minute, second) = match (
        parse(0, 4),
        parse(5, 7),
        parse(8, 10),
        parse(11, 13),
        parse(14, 16),
        parse(17, 19),
    ) {
        (Some(y), Some(m), Some(d), Some(h), Some(min), Some(s)) => (y, m, d, h, min, s),
        _ => return None,
    };
    let suffix = &value[19..value.len() - 1];
    let nanos = if suffix.is_empty() {
        0
    } else {
        let digits = suffix.strip_prefix('.')?;
        if digits.is_empty() || digits.len() > 9 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let value = digits.parse::<u32>().ok()?;
        value * 10u32.pow((9 - digits.len()) as u32)
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((year, month, day, hour, minute, second, nanos))
}

fn valid_utc_timestamp(value: &str) -> bool {
    utc_timestamp_key(value).is_some()
}

impl LifecycleRegistry {
    pub fn parse(json_text: &str) -> Result<Self, Error> {
        Self::parse_with_options(json_text, RegistryValidationOptions::default())
    }

    pub fn parse_with_options(
        json_text: &str,
        options: RegistryValidationOptions,
    ) -> Result<Self, Error> {
        let pairs = parse_object(json_text)?;
        if str_field(&pairs, "schema").as_deref() != Some("df-signing-key-registry/v1")
            || str_field(&pairs, "issuer").as_deref() != Some("dynamicfeed.ai")
        {
            return Err(Error::Lifecycle("unexpected schema or issuer".into()));
        }
        let registry_revision = positive_u64_field(&pairs, "registry_revision")?;
        let effective_registry_floor = match options.mode {
            VerificationMode::HistoricalSnapshot => 0,
            VerificationMode::Live => COMPILED_MIN_REGISTRY_REVISION
                .max(options.minimum_registry_revision.unwrap_or(0))
                .max(options.highest_authenticated_registry_revision.unwrap_or(0)),
        };
        if options.mode == VerificationMode::Live && registry_revision < effective_registry_floor {
            return Err(Error::Lifecycle(format!(
                "registry revision {registry_revision} is below effective floor {effective_registry_floor}"
            )));
        }
        let updated = str_field(&pairs, "updated_at")
            .ok_or_else(|| Error::Lifecycle("missing updated_at".into()))?;
        if !valid_utc_timestamp(&updated) {
            return Err(Error::Lifecycle(
                "updated_at is not a valid UTC timestamp".into(),
            ));
        }
        let active_key_id = str_field(&pairs, "active_key_id")
            .ok_or_else(|| Error::Lifecycle("missing active_key_id".into()))?;
        let public_pairs = object_field(&pairs, "public_keys")?;
        let lifecycle_pairs = object_field(&pairs, "lifecycle")?;
        let mut key_map = BTreeMap::new();
        for (key_id, node) in public_pairs {
            let encoded = match node {
                Node::Str(value) => value.clone(),
                _ => return Err(Error::Lifecycle(format!("public key {key_id} is not text"))),
            };
            let raw = b64_decode(&encoded)?;
            if raw.len() != 32 {
                return Err(Error::Lifecycle(format!(
                    "public key {key_id} is not 32 bytes"
                )));
            }
            let fingerprint = Sha256::digest(&raw);
            let expected = format!(
                "df-ed25519-{}",
                fingerprint[..6]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            if &expected != key_id {
                return Err(Error::Lifecycle(format!(
                    "public key does not derive {key_id}"
                )));
            }
            key_map.insert(key_id.clone(), encoded);
        }
        if key_map.is_empty() || !key_map.contains_key(&active_key_id) {
            return Err(Error::Lifecycle("active key is not published".into()));
        }
        let life_ids: BTreeSet<&str> = lifecycle_pairs.iter().map(|(id, _)| id.as_str()).collect();
        let key_ids: BTreeSet<&str> = key_map.keys().map(|id| id.as_str()).collect();
        if life_ids != key_ids {
            return Err(Error::Lifecycle(
                "every public key needs one lifecycle entry".into(),
            ));
        }
        let mut statuses = BTreeMap::new();
        let mut active_count = 0;
        for (key_id, node) in lifecycle_pairs {
            let meta = match node {
                Node::Object(value) => value,
                _ => {
                    return Err(Error::Lifecycle(format!(
                        "lifecycle {key_id} is not an object"
                    )))
                }
            };
            if str_field(meta, "alg").as_deref() != Some("Ed25519")
                || str_field(meta, "use").as_deref() != Some("receipt-signing")
                || bool_field(meta, "public_key_retained") != Some(true)
            {
                return Err(Error::Lifecycle(format!(
                    "invalid lifecycle metadata for {key_id}"
                )));
            }
            let raw = b64_decode(key_map.get(key_id).unwrap())?;
            let fingerprint = Sha256::digest(&raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if str_field(meta, "fingerprint_sha256").as_deref() != Some(fingerprint.as_str()) {
                return Err(Error::Lifecycle(format!(
                    "fingerprint mismatch for {key_id}"
                )));
            }
            let first_used = str_field(meta, "first_used_at")
                .and_then(|v| utc_timestamp_key(&v))
                .ok_or_else(|| Error::Lifecycle(format!("invalid first_used_at for {key_id}")))?;
            let active_from = str_field(meta, "active_from")
                .and_then(|v| utc_timestamp_key(&v))
                .ok_or_else(|| Error::Lifecycle(format!("invalid active_from for {key_id}")))?;
            if first_used > active_from {
                return Err(Error::Lifecycle(format!(
                    "first_used_at is after active_from for {key_id}"
                )));
            }
            let status = match str_field(meta, "status").as_deref() {
                Some("active") => {
                    active_count += 1;
                    if key_id != &active_key_id
                        || !null_field(meta, "retired_at")
                        || !null_field(meta, "compromised_after")
                    {
                        return Err(Error::Lifecycle("active-key metadata mismatch".into()));
                    }
                    LifecycleStatus::Active
                }
                Some("retired") => {
                    let retired_at =
                        str_field(meta, "retired_at").and_then(|v| utc_timestamp_key(&v));
                    if retired_at.is_none()
                        || active_from > retired_at.unwrap()
                        || !null_field(meta, "compromised_after")
                    {
                        return Err(Error::Lifecycle(format!("invalid retirement for {key_id}")));
                    }
                    LifecycleStatus::Retired
                }
                Some("compromised") => {
                    let retired_at =
                        str_field(meta, "retired_at").and_then(|v| utc_timestamp_key(&v));
                    let compromised_after =
                        str_field(meta, "compromised_after").and_then(|v| utc_timestamp_key(&v));
                    if retired_at.is_none()
                        || compromised_after.is_none()
                        || active_from > retired_at.unwrap()
                        || compromised_after.unwrap() > retired_at.unwrap()
                    {
                        return Err(Error::Lifecycle(format!(
                            "invalid compromise metadata for {key_id}"
                        )));
                    }
                    LifecycleStatus::Compromised
                }
                _ => {
                    return Err(Error::Lifecycle(format!(
                        "unknown lifecycle status for {key_id}"
                    )))
                }
            };
            statuses.insert(key_id.clone(), status);
        }
        if active_count != 1 {
            return Err(Error::Lifecycle(
                "registry must contain exactly one active key".into(),
            ));
        }
        let authority = object_field(&pairs, "authority")?;
        if bool_field(authority, "independent_registry_root") != Some(false) {
            return Err(Error::Lifecycle(
                "authority classification is missing".into(),
            ));
        }
        let policy = object_field(&pairs, "verification_policy")?;
        for name in [
            "cryptographic_validity_separate_from_lifecycle",
            "retired_keys_verify_historical_bytes",
            "compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp",
            "receipt_issued_at_alone_is_not_independent_time_evidence",
        ] {
            if bool_field(policy, name) != Some(true) {
                return Err(Error::Lifecycle("verification policy is incomplete".into()));
            }
        }
        Ok(Self {
            keys: Keys { map: key_map },
            active_key_id,
            statuses,
            registry_revision,
            effective_registry_floor,
            mode: options.mode,
            registry_source_authenticated: options.registry_source_authenticated,
            highest_authenticated_registry_revision: options
                .highest_authenticated_registry_revision,
        })
    }

    pub fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    pub fn effective_registry_floor(&self) -> u64 {
        self.effective_registry_floor
    }

    pub fn mode(&self) -> VerificationMode {
        self.mode
    }

    #[cfg(feature = "fetch")]
    pub fn fetch(url: &str) -> Result<Self, Error> {
        let options = RegistryValidationOptions {
            registry_source_authenticated: url == DEFAULT_LIFECYCLE_URL,
            ..RegistryValidationOptions::default()
        };
        Self::fetch_with_options(url, options)
    }

    #[cfg(feature = "fetch")]
    pub fn fetch_with_options(
        url: &str,
        options: RegistryValidationOptions,
    ) -> Result<Self, Error> {
        let body = ureq::AgentBuilder::new()
            .redirects(0)
            .build()
            .get(url)
            .set("Cache-Control", "no-cache")
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .map_err(|e| Error::Fetch(e.to_string()))?
            .into_string()
            .map_err(|e| Error::Fetch(e.to_string()))?;
        Self::parse_with_options(&body, options)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerification {
    pub accepted: bool,
    pub crypto_valid: bool,
    pub signer_accepted: bool,
    pub policy_as_of_accepted: bool,
    pub lifecycle_status: LifecycleStatus,
    pub key_id: String,
    /// Signature coverage of an attached anchor; see [`Verification::anchor_authenticated`].
    pub anchor_authenticated: Option<bool>,
    pub mode: VerificationMode,
    pub historical_snapshot: bool,
    pub registry_revision: u64,
    pub effective_registry_floor: u64,
    pub registry_source_authenticated: bool,
    pub rollback_protected: bool,
}

pub fn verify_with_registry(
    envelope_json_text: &str,
    registry: &LifecycleRegistry,
) -> Result<PolicyVerification, Error> {
    let key_id = signature_key_id(envelope_json_text)?;
    let pubkey = registry
        .keys
        .get(&key_id)
        .ok_or_else(|| Error::UnknownKeyId(key_id.clone()))?;
    let crypto = verify_envelope(envelope_json_text, pubkey)?;
    let status = registry
        .statuses
        .get(&key_id)
        .cloned()
        .unwrap_or(LifecycleStatus::Unknown);
    let (signer_accepted, policy_as_of_accepted) = match registry.mode {
        VerificationMode::Live => (
            status == LifecycleStatus::Active
                && registry.active_key_id == key_id
                && registry.registry_source_authenticated,
            false,
        ),
        VerificationMode::HistoricalSnapshot => (
            false,
            matches!(status, LifecycleStatus::Active | LifecycleStatus::Retired),
        ),
    };
    let rollback_protected = registry.mode == VerificationMode::Live
        && registry.registry_source_authenticated
        && registry.highest_authenticated_registry_revision.is_some()
        && registry.registry_revision
            >= registry
                .highest_authenticated_registry_revision
                .unwrap_or(u64::MAX);
    Ok(PolicyVerification {
        accepted: crypto.valid && signer_accepted,
        crypto_valid: crypto.valid,
        signer_accepted,
        policy_as_of_accepted,
        lifecycle_status: status,
        key_id,
        anchor_authenticated: crypto.anchor_authenticated,
        mode: registry.mode,
        historical_snapshot: registry.mode == VerificationMode::HistoricalSnapshot,
        registry_revision: registry.registry_revision,
        effective_registry_floor: registry.effective_registry_floor,
        registry_source_authenticated: registry.registry_source_authenticated,
        rollback_protected,
    })
}

#[cfg(feature = "fetch")]
pub fn fetch_lifecycle_registry(url: &str) -> Result<LifecycleRegistry, Error> {
    LifecycleRegistry::fetch(url)
}

/// Verify cryptographic signature mathematics by looking `key_id` up in a flat [`Keys`] set.
/// This does not evaluate lifecycle status; use [`verify_with_registry`] for policy acceptance.
pub fn verify_with_keys(envelope_json_text: &str, keys: &Keys) -> Result<Verification, Error> {
    let key_id = signature_key_id(envelope_json_text)?;
    let pubkey = keys
        .get(&key_id)
        .ok_or_else(|| Error::UnknownKeyId(key_id.clone()))?;
    verify_envelope(envelope_json_text, pubkey)
}

// ------------------------------------------------------------------------------------------------
// Unit tests for the two canonicalization traps
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a JSON `\uXXXX` escape sequence at runtime (backslash + "u" + hex digits).
    fn u(hex: &str) -> String {
        format!("{}u{}", '\\', hex)
    }

    #[test]
    fn ensure_ascii_escaping_matches_python() {
        // python3: json.dumps({"a":"°C – ok","b":True}, sort_keys=True, separators=(",",":"))
        // escapes ° (U+00B0) and – (U+2013) to ASCII \uXXXX sequences — raw UTF-8 in,
        // ensure_ascii escapes out.
        let src = r#"{"b": true, "a": "°C – ok", "signature": {"sig": "x", "key_id": "k"}}"#;
        let got = canonical_bytes(src).unwrap();
        let expected = format!(r#"{{"a":"{}C {} ok","b":true}}"#, u("00b0"), u("2013"));
        assert_eq!(String::from_utf8(got).unwrap(), expected);
    }

    #[test]
    fn astral_chars_become_surrogate_pair_escapes() {
        // python3: json.dumps({"r":"🤖"}) escapes U+1F916 to the surrogate pair d83e/dd16.
        let expected = format!(r#"{{"r":"{}{}"}}"#, u("d83e"), u("dd16"));
        // raw UTF-8 emoji in the source...
        let got = canonical_bytes(r#"{"r":"🤖"}"#).unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), expected);
        // ...and the same when the source already uses the escaped surrogate pair
        let src_escaped = format!(r#"{{"r":"{}{}"}}"#, u("d83e"), u("dd16"));
        let got2 = canonical_bytes(&src_escaped).unwrap();
        assert_eq!(String::from_utf8(got2).unwrap(), expected);
    }

    #[test]
    fn numbers_round_trip_verbatim() {
        // serde_json would re-print 1e-07 as 1e-7 and -50.0 as -50.0/-50 depending on type;
        // we must keep the source spelling EXACTLY (Python repr round-trip).
        let src = r#"{"z": 1e-07, "a": -50.0, "m": 16.7, "n": 100000000000000000000}"#;
        let got = canonical_bytes(src).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            r#"{"a":-50.0,"m":16.7,"n":100000000000000000000,"z":1e-07}"#
        );
    }

    #[test]
    fn signature_field_is_stripped_and_keys_sorted() {
        let src = r#"{"b":2,"signature":{"sig":"s","key_id":"k"},"a":1}"#;
        let got = canonical_bytes(src).unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn nonstandard_numbers_and_raw_controls_fail_closed() {
        for invalid in [r#"{"x":+1}"#, r#"{"x":01}"#, r#"{"x":1.}"#, r#"{"x":1e}"#] {
            assert!(
                canonical_bytes(invalid).is_err(),
                "accepted invalid JSON: {invalid}"
            );
        }
        let raw_control = format!("{{\"x\":\"{}\"}}", '\u{0001}');
        assert!(canonical_bytes(&raw_control).is_err());
    }
}
