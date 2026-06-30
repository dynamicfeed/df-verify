# dynamicfeed-verify (Rust)

Independently verify [Dynamic Feed](https://dynamicfeed.ai) **DF-VERIFY/1** Ed25519-signed responses in Rust. No account, no runtime trust in Dynamic Feed beyond fetching the public key. You can verify, even against us.

Reference implementation of the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard). Byte-for-byte identical canonicalization to the Python, JavaScript and C# verifiers: it passes the shared conformance vectors in [`tests/vectors`](../../tests/vectors).

## Library

```rust
use dynamicfeed_verify::{parse, verify};

let env = parse(&response_text)?;          // arbitrary_precision: numbers kept verbatim
let ok = verify(&env, &keys_map)?;         // keys: key_id -> base64url public key
```

## CLI

```bash
cargo run -- response.json keys.json       # verify a saved signed response
cargo run -- --canonical response.json     # print the exact canonical bytes
```

Fetch the keys however you like; the verifier has no network dependency:

```bash
curl -s https://dynamicfeed.ai/.well-known/keys > keys.json
```

## How it works

1. Drop the top-level `signature` field; keep the rest as the payload.
2. Canonicalize (`json-sorted-compact`): keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX` (astral characters as UTF-16 surrogate pairs), numbers verbatim, UTF-8.
3. Verify the detached Ed25519 signature over the canonical bytes against the key named in `signature.key_id`. Change one byte and it fails.

The cardinal rule it enforces: **signed is not verified**. A signature proves integrity, not truth.

## Conformance

```bash
cargo test
```

runs the language-agnostic vectors in [`../../tests/vectors`](../../tests/vectors), the same ones the Python and JS harnesses use: every canonicalization vector must match byte-for-byte, the authentic envelope must verify, and the tampered twin must be rejected.

Full specification: **https://dynamicfeed.ai/standard**

## License

MIT.
