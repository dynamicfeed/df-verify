# dynamicfeed-verify (Rust)

Ed25519 verifier for [Dynamic Feed](https://dynamicfeed.ai) signed envelopes (**DF-VERIFY/1**).

Signed Dynamic Feed response profiles carry DF-VERIFY/1 envelopes. This crate lets Rust verify
their signature bytes and lifecycle policy offline, byte-identical with the other implementations
in this repository:

- Python — [`../python`](../python)
- JavaScript — [`../js`](../js)
- Rust — this crate

Spec: https://dynamicfeed.ai/standard

## The envelope

```json
{
  "...payload fields...": "...",
  "signature": {
    "alg": "Ed25519",
    "key_id": "df-ed25519-6ca0de29113b",
    "canonicalization": "json-sorted-compact",
    "sig": "<base64url>"
  }
}
```

The signature covers the **canonical bytes**: the JSON object *without* its `signature` field,
serialized exactly like Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))` —
sorted keys, compact separators, `ensure_ascii` escaping.

## The two canonicalization traps

A naive verifier (parse with any JSON library, re-serialize, verify) breaks on real envelopes.
Two traps, both solved here the same way `web/verify.js` solves them:

1. **Python `ensure_ascii` escaping.** Responses travel over the wire as raw UTF-8 (`"unit":"°C"`),
   but the server signed the ASCII-escaped form (`"unit":"\u00b0C"`). Every non-ASCII character
   must be re-escaped to `\uXXXX` (lowercase hex; astral characters become a UTF-16 surrogate
   pair, e.g. 🤖 → `\ud83e\udd16`) before checking the signature.

2. **Lossless numbers.** Numbers must round-trip **exactly** as they appear in the source text.
   Parsing `-50.0` into a float and re-printing it can change the spelling (`-50`, or `1e-07`
   becoming `1e-7` under serde_json), which flips bytes and invalidates the signature. This crate
   uses its own small JSON parser that keeps every number **verbatim as a text slice** — no float
   formatting is ever involved.

## Library — lifecycle policy mode

```rust
// Offline — no network. Pin the reviewed lifecycle registry outside the receipt channel.
let envelope_text = std::fs::read_to_string("envelope.json")?;
let registry_text = std::fs::read_to_string("signing-key-lifecycle.json")?;
let registry = dynamicfeed_verify::LifecycleRegistry::parse_with_options(
    &registry_text,
    dynamicfeed_verify::RegistryValidationOptions {
        registry_source_authenticated: true,
        ..Default::default()
    },
)?;
let result = dynamicfeed_verify::verify_with_registry(&envelope_text, &registry)?;
assert!(result.accepted); // signature mathematics AND signer lifecycle policy
println!("POLICY_ACCEPTED — key_id={}", result.key_id);

// Canonical bytes (what the signature actually covers):
let bytes = dynamicfeed_verify::canonical_bytes(&envelope_text)?;
```

`verify_envelope` and `verify_with_keys` are deliberately lower-level, **crypto-only** APIs. They
can establish Ed25519 signature mathematics and key-id binding, but a flat key map contains no
retired/compromised status. Never interpret their `valid` field as signer acceptance:

```rust
let keys = dynamicfeed_verify::Keys::parse(&keys_json_text)?;
let crypto_only = dynamicfeed_verify::verify_with_keys(&envelope_text, &keys)?;
assert!(crypto_only.valid); // CRYPTO_VALID; LIFECYCLE_UNCHECKED
```

Their `anchor_authenticated` field also preserves the two frozen receipt conventions: `Some(true)`
means an attached anchor was inside the verified signature scope, `Some(false)` means legacy
post-signature attachment, and `None` means no anchor (or no passing signature form). Signature
validity must never be used to infer authenticity of a legacy attached timestamp artifact.

With the optional **`fetch`** feature (the core stays no-network):

```rust
let registry = dynamicfeed_verify::fetch_lifecycle_registry(
    dynamicfeed_verify::DEFAULT_LIFECYCLE_URL,
)?;
let result = dynamicfeed_verify::verify_with_registry(&envelope_text, &registry)?;
```

The default URL is a current-domain operational disclosure, not an independent trust root. Pin a
reviewed registry out of band when the verifier is a security or evidence policy gate.
Caller-supplied files and custom registry URLs are not accepted as authenticated merely because
they were supplied; set `registry_source_authenticated` only after authenticating that source.
Network fetches reject redirects.

Live verification enforces `COMPILED_MIN_REGISTRY_REVISION` plus any caller-supplied minimum and
the caller's highest previously authenticated revision. The registry's own revision cannot protect
itself from rollback: persist an authenticated highest revision outside the document and pass it
back through `RegistryValidationOptions`. `HistoricalSnapshot` mode must be selected explicitly;
it can report historical signature mathematics and policy-as-of status but never returns
`accepted=true` and must not authorize a live action.

```rust
let options = dynamicfeed_verify::RegistryValidationOptions {
    highest_authenticated_registry_revision: Some(1),
    registry_source_authenticated: true,
    ..Default::default()
};
let registry = dynamicfeed_verify::LifecycleRegistry::parse_with_options(
    &registry_text,
    options,
)?;
```

```toml
[dependencies]
dynamicfeed-verify = { version = "1.0.2", features = ["fetch"] }
```

## CLI

```sh
# offline policy mode, pinned registry
dynamicfeed-verify envelope.json --registry SIGNING_KEY_LIFECYCLE.json \
  --registry-source-authenticated

# enforce a caller-retained authenticated revision floor
dynamicfeed-verify envelope.json --registry SIGNING_KEY_LIFECYCLE.json \
  --highest-authenticated-registry-revision 1 --registry-source-authenticated

# non-actionable historical inspection (always exits non-zero for policy acceptance)
dynamicfeed-verify envelope.json --registry SIGNING_KEY_LIFECYCLE.json --historical-snapshot

# from stdin, same pinned policy
curl -s 'https://dynamicfeed.ai/v1/attest?metric=temperature_c&op=gte&threshold=-50&lat=-33.87&lon=151.21' \
  | dynamicfeed-verify --registry SIGNING_KEY_LIFECYCLE.json

# fetch the current-domain lifecycle registry (requires --features fetch)
dynamicfeed-verify envelope.json

# explicit signature-mathematics diagnostic; no lifecycle acceptance
dynamicfeed-verify envelope.json --key acMWky59eQfoVqCUgmUM3tcl35YioRngL4wVDIQsstg= --crypto-only
```

Policy mode prints `POLICY_ACCEPTED`, `CRYPTO_VALID LIFECYCLE_REJECTED`, or `CRYPTO_INVALID` and
exits `0` only for policy acceptance. Explicit `--crypto-only` prints
`CRYPTO_VALID LIFECYCLE_UNCHECKED` or `CRYPTO_INVALID`.

## Conformance

`tests/conformance.rs` runs against frozen historical awareness and anchored-answer fixtures plus
generated active-key material:

- preserved historical bytes remain cryptographically valid while the compromised signer is
  lifecycle-rejected by the reviewed registry;
- a generated active-key fixture passes signature and lifecycle policy;
- flipping a single payload byte makes it **INVALID**;
- revision rollback below a caller-retained floor fails closed;
- historical snapshot mode never returns live acceptance;
- duplicate JSON keys and rewritten signature metadata fail closed;
- a legacy post-signature anchor reports `anchor_authenticated = Some(false)`.

## License

MIT
