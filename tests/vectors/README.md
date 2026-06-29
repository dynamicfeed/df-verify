# DF-VERIFY/1 conformance vectors

Language-agnostic test vectors for the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard). Use them to prove a verifier, in any language, is byte-for-byte correct.

- **`canonicalization.json`**: payloads + their expected canonical output (`json-sorted-compact`: keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX` incl. astral surrogate pairs, top-level `signature` stripped). For each vector, `canonicalize(payload)` must equal `canonical`.
- **`signed-awareness.json`**: a real signed verdict (exact response bytes in `envelope_text`), its verifying public key, and a tampered twin. Verify the **raw text**, because re-serializing a parsed object can change number formatting (e.g. `14.0` → `14`) and break the signature. The `authentic` envelope **must** verify; the `tampered` one **must** be rejected.

## Check an implementation

```bash
python3 tests/verify_vectors.py     # Python reference harness  → "✓ ALL 10 VECTORS PASS"
node   tests/verify_vectors.mjs     # JavaScript harness (run `npm install --prefix clients/js` first)
```

Both reference verifiers (Python and JavaScript) reproduce every vector exactly (same canonical bytes, same signature verdicts). Port a harness to confirm a Go/Rust/etc. verifier.

Spec: **https://dynamicfeed.ai/standard**
