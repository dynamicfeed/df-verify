# @dynamicfeed/verify

Independently verify [Dynamic Feed](https://dynamicfeed.ai) **DF-VERIFY/1** Ed25519-signed responses in any JavaScript runtime (Node ≥18, Deno, Bun, browsers). No account, no runtime trust in Dynamic Feed beyond fetching the public key. You can verify, even against us.

Reference implementation of the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard). Byte-for-byte identical canonicalization to the Python (`dynamicfeed-verify`) and in-browser verifiers.

## Install

```bash
npm install @dynamicfeed/verify
```

## Use

```js
import { verify, verifyLive } from '@dynamicfeed/verify';

// 1) fetch a fresh signed awareness verdict and verify it
const { text, result } = await verifyLive();
console.log(result);   // { ok: true, keyId: 'df-ed25519-…', verdict: 'caution', ... }

// 2) verify any signed response you hold (pass the RAW text for byte-fidelity)
const result2 = await verify(rawResponseText);
if (!result2.ok) throw new Error(`unverified: ${result2.error}`);

// 3) verify fully offline if you already have the JWKS
const result3 = await verify(rawResponseText, { jwks: { 'df-ed25519-…': '<base64url public key>' } });
```

## CLI

```bash
npx @dynamicfeed/verify                      # fetch a live verdict + verify
npx @dynamicfeed/verify - < response.json    # verify a saved signed response
```

## How it works

A signed response carries a `signature` block (`alg`, `key_id`, `canonicalization`, `sig`). Verification:

1. Drop the `signature` field; keep the rest as the payload.
2. Canonicalize: JSON, keys sorted recursively, compact separators (`,` `:`), non-ASCII escaped `\uXXXX`, UTF-8. (Numbers are preserved verbatim via a lossless parse, so it matches the signer byte-for-byte.)
3. Fetch the public key from `/.well-known/keys` and look up `signature.key_id`.
4. Verify the Ed25519 signature over the canonical bytes. Change one byte → it fails.

Full specification: **https://dynamicfeed.ai/standard**

## License

MIT.
