# DF-VERIFY/1 conformance vectors

Language-agnostic test vectors for the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard). Use them to prove a verifier, in any language, is byte-for-byte correct.

- **`canonicalization.json`**: payloads + their expected canonical output (`json-sorted-compact`: keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX` incl. astral surrogate pairs, top-level `signature` stripped). For each vector, `canonicalize(payload)` must equal `canonical`.
- **`signed-awareness.json`**: a real historical signed verdict (exact response bytes in
  `envelope_text`), its verifying public key, and a tampered twin. The authentic bytes must be
  cryptographically valid, but their now-compromised signer must be lifecycle-rejected. The
  tampered twin must be cryptographically rejected.
- **`signed-answer-anchored.json`**: the frozen legacy post-signature anchor convention. Signature
  mathematics remains valid when that unsigned anchor changes, and `anchor_authenticated` must be
  false; a signed-body change must fail.

## Check an implementation

```bash
python3 tests/verify_vectors.py     # Python reference harness
node   tests/verify_vectors.mjs     # JavaScript harness (run `npm install --prefix clients/js` first)
```

The harnesses distinguish signature mathematics from lifecycle acceptance. Do not copy the
fixture's flat key map into a live trust policy.

Spec: **https://dynamicfeed.ai/standard**
