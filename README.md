# DF-VERIFY/1 verifier sources

Reference verifier source for Dynamic Feed signed envelopes and signing-key lifecycle policy.
The security boundary is deliberately split:

- `crypto_valid` means the Ed25519 signature, exact metadata, canonical bytes, and key-ID binding
  passed;
- `ok` / policy acceptance additionally requires an acceptable signer in a validated lifecycle
  registry whose source the verifier authenticated;
- a signature proves integrity under that key, not objective truth, safety, or legal compliance.

## Security notice — 2026-07-11

Earlier published verifiers accepted a flat public-key map and had no retired/compromised signer
policy. The former signing key `df-ed25519-4cb32e72f333` is now classified **compromised** using the
conservative boundary `2026-07-11T00:00:00Z`. Its public bytes are retained so historical signature
mathematics remain inspectable, but that key must never produce a live policy-accepted result.

The hardened versions in this repository are release targets, not evidence that package registries
have already been updated:

| Ecosystem | Affected published version(s) | Hardened source target | Published by this PR? |
|---|---:|---:|---|
| PyPI `dynamicfeed-verify` | `<= 1.0.2` | `1.0.3` | No |
| npm `@dynamicfeed/verify` | `<= 1.0.1` | `1.0.2` | No |
| crates.io `dynamicfeed-verify` | `1.0.0` (and affected prior source `1.0.1`) | `1.0.2` | No |
| C# sample | all current source | quarantined, transport-only | Not a package |

Do not announce a clean package rotation until the target artifacts are built from the reviewed
commit, published through their normal release controls, installed from each registry into a clean
environment, and the advisory is updated with artifact digests and provenance.

See [SECURITY.md](SECURITY.md) for the full advisory.

## Trust material

- [`SIGNING_KEY_LIFECYCLE.json`](SIGNING_KEY_LIFECYCLE.json) is the reviewed
  `df-signing-key-registry/v1` snapshot. It retains active and historical public bytes with explicit
  lifecycle status and `registry_revision`.
- [`KNOWN_KEYS.json`](KNOWN_KEYS.json) is a deprecated compatibility archive. It is intentionally
  not a flat map and cannot honestly authorize the compromised key.
- The service compatibility endpoint `/.well-known/keys` is required to become active-key-only as
  part of the corresponding service deployment. Historical key bytes belong in the lifecycle
  registry. Verify the live endpoint after deployment; this source PR does not deploy it.

The current-domain registry is an operational disclosure, not an independent trust root. A
security-sensitive verifier should pin a reviewed registry out of band, authenticate updates, and
persist the highest authenticated `registry_revision` outside the document.

## What policy-aware verification does

1. Strictly parse JSON and reject duplicate object names, malformed numbers, raw controls, and
   trailing bytes.
2. Require exactly `Ed25519` and `json-sorted-compact` signature metadata.
3. Preserve both frozen receipt conventions: verify without `signature` first, then (only when
   needed) without both `signature` and a legacy post-signature `anchor`.
4. Derive `key_id` from the SHA-256 fingerprint of the raw public key.
5. Validate the lifecycle registry, its key/fingerprint relationships, chronology, policy fields,
   active-key uniqueness, and revision floor.
6. Accept only the current active key in live mode. Retired keys are non-live historical material;
   compromised keys are never policy accepted.
7. Keep historical snapshot inspection explicit and non-actionable: it can report signature
   mathematics and policy-as-of state but never returns an overall live acceptance.

`anchor_authenticated=true` means an attached anchor was inside the signed bytes.
`anchor_authenticated=false` means the frozen legacy post-signature attachment was outside them.
Neither state independently validates an RFC 3161 or OpenTimestamps proof; these libraries do not
claim full timestamp-proof verification.

## Repository map

| Path | Status |
|---|---|
| [`clients/python`](clients/python) | Python lifecycle-aware verifier, target `1.0.3` |
| [`clients/js`](clients/js) | JavaScript/TypeScript lifecycle-aware verifier, target `1.0.2` |
| [`clients/rust`](clients/rust) | Rust crate `dynamicfeed-verify`, lifecycle-aware target `1.0.2` |
| [`clients/csharp`](clients/csharp) | Quarantined transport-only sample; no reference-verifier claim |
| [`examples/verified-agent`](examples/verified-agent) | Verify-before-use example; never an actuator |
| [`tests/vectors`](tests/vectors) | Shared canonicalization and frozen receipt fixtures |
| [`reliability`](reliability) | Separate non-cryptographic reliability vocabulary and validators |

### Rust package provenance

This repository's [`clients/rust`](clients/rust) is the source for the crate named
`dynamicfeed-verify`. The distinct monorepo crate named `df-verify` (`0.1.2` target) is maintained at
`Dynamic-Feed/packages/df-verify-rs`; it is not source-identical or package-identical. Its Cargo
`repository` metadata must point to its actual source location (or that exact source must be added
here under an unambiguous path) before publication.

## Verify from source

Python:

```bash
python -m pip install -e clients/python pytest
python -m pytest clients/python/tests
python tests/verify_vectors.py
```

JavaScript:

```bash
npm install --prefix clients/js
npm test --prefix clients/js
node tests/verify_vectors.mjs
```

Rust:

```bash
cd clients/rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Rotation guardrail:

```bash
python scripts/check_rotation_policy.py
```

## Minimal policy-aware use

Python:

```python
import json
from dynamicfeed_verify import verify

registry = json.load(open("SIGNING_KEY_LIFECYCLE.json"))
result = verify(
    envelope,
    lifecycle_registry=registry,
    registry_source_authenticated=True,  # caller authenticated this pinned file
)
if not result["ok"]:
    raise RuntimeError(result["error"])
```

JavaScript:

```js
import { verify } from '@dynamicfeed/verify';

const result = await verify(rawEnvelopeText, {
  lifecycleRegistry: pinnedRegistry,
  registrySourceAuthenticated: true,
});
if (!result.ok) throw new Error(result.error);
```

Rust:

```rust
let registry = dynamicfeed_verify::LifecycleRegistry::parse_with_options(
    &registry_text,
    dynamicfeed_verify::RegistryValidationOptions {
        registry_source_authenticated: true,
        ..Default::default()
    },
)?;
let result = dynamicfeed_verify::verify_with_registry(&raw_envelope, &registry)?;
assert!(result.accepted);
```

## Links

- Specification surface: https://dynamicfeed.ai/standard
- Browser verifier: https://dynamicfeed.ai/proof
- Lifecycle registry endpoint: https://dynamicfeed.ai/.well-known/signing-key-registry.json
- Active-key compatibility endpoint: https://dynamicfeed.ai/.well-known/keys

## License

MIT.
