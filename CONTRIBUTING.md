# Contributing

Thanks for your interest. The goal of this repo is one thing done well: **independently verifying DF-VERIFY/1 signed responses, byte-for-byte, in any language**, plus the reliability object that grades how much to believe a datapoint.

## The bar

Every verifier, in every language, must agree. That agreement is defined by the language-agnostic vectors in [`tests/vectors`](tests/vectors), not by any one implementation:

- **Canonicalization** must match the expected bytes exactly (keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX` including astral surrogate pairs, numbers verbatim, top-level `signature` stripped).
- The **authentic** signed envelope must verify; the **tampered** twin must be rejected.
- For the reliability object, the cases in [`reliability/conformance-vectors.json`](reliability/conformance-vectors.json) must pass (the honesty rules, including `signed != verified`).

CI runs all of this on every push and pull request. A change is mergeable when CI is green.

## Adding or porting a verifier

1. Put it under `clients/<language>/`.
2. Reproduce the canonicalization and the Ed25519 check; do not invent a new format.
3. Add a test (or harness) that runs the vectors in `tests/vectors`, and wire it into [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
4. Open a PR. Keep it dependency-light and offline-capable: a verifier should need nothing from the issuer at runtime beyond fetching the public key.

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
