# @dynamicfeed/verify

Verify [Dynamic Feed](https://dynamicfeed.ai) **DF-VERIFY/1** signed bytes and signing-key lifecycle policy in any JavaScript runtime (Node ≥18, Deno, Bun, browsers). The default fetch is current-domain policy; origin-independent verification requires an out-of-band pinned lifecycle registry.

Reference implementation of the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard). Byte-for-byte identical canonicalization to the Python (`dynamicfeed-verify`) and in-browser verifiers.

## Install

`1.0.2` is the hardened source target in this branch. Until the security advisory records that it
has been published and clean-install tested, install from the reviewed source commit rather than
assuming npm is current:

```bash
npm install --prefix clients/js
```

## Use

```js
import { verify, verifyLive } from '@dynamicfeed/verify';

// 1) fetch a fresh signed awareness verdict and verify it
const { text, result } = await verifyLive();
console.log(result);   // { ok: true, keyId: 'df-ed25519-…', verdict: 'caution', ... }

// 2) verify any signed response you hold — pass the RAW text for byte-fidelity
const result2 = await verify(rawResponseText);
if (!result2.ok) throw new Error(`unverified: ${result2.error}`);

// 3) verify fully offline with an out-of-band pinned df-signing-key-registry/v1 document
const result3 = await verify(rawResponseText, {
  lifecycleRegistry: pinnedRegistry,
  registrySourceAuthenticated: true,
});

// A legacy flat key map reports signature mathematics only: cryptoValid may be true, but ok stays false.
const cryptoOnly = await verify(rawResponseText, { jwks: { 'df-ed25519-…': '<base64url key>' } });
```

## CLI

```bash
npx @dynamicfeed/verify                      # fetch a live verdict + verify
npx @dynamicfeed/verify - < response.json    # verify a saved signed response
```

## How it works

A signed response carries a `signature` block (`alg`, `key_id`, `canonicalization`, `sig`). Verification:

1. Require the exact `Ed25519` / `json-sorted-compact` signature metadata.
2. Preserve both frozen anchor conventions: try the document without `signature` first, then (only
   if needed) without both `signature` and `anchor`. `anchorAuthenticated` reports `true`, `false`,
   or `null`; signature validity never authenticates a legacy post-signature anchor.
3. Canonicalize — JSON, keys sorted recursively, compact separators (`,` `:`), non-ASCII escaped `\uXXXX`, UTF-8. (Numbers are preserved verbatim via a lossless parse, so it matches the signer byte-for-byte.)
4. Resolve the key bytes and lifecycle state from `/.well-known/signing-key-registry.json` (or a pinned copy).
5. Verify the Ed25519 signature over the canonical bytes and bind the public key to `key_id`.
6. Return `ok: true` only when cryptography and lifecycle policy both pass. Compromised keys remain available for reporting historical `cryptoValid`, but never turn green from `issued_at` or bundle metadata.

Live mode enforces the compiled revision floor plus `minimumRegistryRevision` and the caller's
persisted `highestAuthenticatedRegistryRevision`. A registry's self-declared revision is not
anti-rollback. Caller-supplied registries and custom network origins require
`registrySourceAuthenticated: true`; otherwise signature mathematics may pass but `ok` remains
false. Redirects fail closed. `historical_snapshot` is explicit and always non-actionable.

Full specification: **https://dynamicfeed.ai/standard**

## License

MIT.
