# Contributing

Thanks for your interest. The goal of this repository is one thing done well: independently check
DF-VERIFY/1 signature bytes and apply caller-authenticated signer-lifecycle policy consistently
across languages, while keeping the separate reliability object honest.

## The bar

Every supported reference verifier must agree on signature mathematics and lifecycle policy. The C#
sample is quarantined until it reaches that bar. Agreement is defined by the language-agnostic
vectors and lifecycle regressions, not by any one implementation:

- **Canonicalization** must match the expected bytes exactly (keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX` including astral surrogate pairs, numbers verbatim, top-level `signature` stripped).
- Authentic historical bytes may be cryptographically valid while lifecycle-rejected. Tampered
  signed bytes must be cryptographically rejected. Compromised signers must never pass live policy.
- Registry revision floors, explicit historical mode, and active-only live acceptance must match.
- For the reliability object, the cases in [`reliability/conformance-vectors.json`](reliability/conformance-vectors.json) must pass (the honesty rules, including `signed != verified`).

CI runs all of this on every push and pull request. A change is mergeable when CI is green.

## Adding or porting a verifier

1. Put it under `clients/<language>/`.
2. Reproduce strict canonicalization, Ed25519, key-ID binding, lifecycle validation, and caller-held
   revision floors; do not invent a new format.
3. Add a test (or harness) that runs the vectors in `tests/vectors`, and wire it into [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
4. Open a PR. Keep it dependency-light and offline-capable. A flat public key is crypto-only;
   policy-aware offline use requires a reviewed lifecycle registry.

## Running the checks locally

```bash
python3 tests/verify_vectors.py                 # Python harness
node    tests/verify_vectors.mjs                # JS harness (npm install --prefix clients/js first)
cargo test --manifest-path clients/rust/Cargo.toml
python3 reliability/verify_reliability.py --selftest
node    reliability/verify_reliability.js --selftest
```

## Scope

Verification and the reliability object only. This stays advisory evidence a consumer recomputes for itself, never a trust score the library arbitrates, and never a safety certification.

By contributing you agree your work is licensed under the repo's [MIT License](LICENSE).
