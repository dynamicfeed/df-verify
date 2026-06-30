# DF-VERIFY/1: verifiable grounding for AI that acts

Reference implementation of **[DF-VERIFY/1](https://dynamicfeed.ai/standard)**, an open, vendor-neutral standard for cryptographically signing, publishing, and **independently verifying exactly what an AI system was told the moment it acted**.

When an AI *acts* (it moves a robot, places a trade, files a claim), "trust me" is not an audit trail. DF-VERIFY attaches an Ed25519 signature to any JSON response, publishes the verifying key openly, and lets anyone check it with **no account and no dependency on the issuer**. You can verify, even against the issuer.

[![DF-VERIFY/1](https://dynamicfeed.ai/badge.svg)](https://dynamicfeed.ai/standard)

## What's here

| Path | What |
|---|---|
| [`clients/python`](clients/python) | `dynamicfeed-verify`: Python reference verifier (library + CLI) |
| [`clients/js`](clients/js) | `@dynamicfeed/verify`: JavaScript/TypeScript verifier (Node, Deno, Bun, browser) |
| [`clients/csharp`](clients/csharp) | C# reference verifier |
| [`clients/rust`](clients/rust) | `dynamicfeed-verify`: Rust reference verifier (library + CLI), passes the shared vectors |
| [`examples/verified-agent`](examples/verified-agent) | a runnable agent that verifies a signature **before it acts** |
| [`tests/vectors`](tests/vectors) | language-agnostic conformance vectors + Python & JS harnesses |

## Verify in 30 seconds

**Python**
```bash
git clone https://github.com/dynamicfeed/df-verify && cd df-verify
pip install cryptography
python examples/verified-agent/agent.py            # verify a live verdict, then act
python examples/verified-agent/agent.py --tamper   # altered after signing → the agent refuses to act
```

**JavaScript**
```js
import { verifyLive } from '@dynamicfeed/verify';
const { result } = await verifyLive();
if (!result.ok) throw new Error(`unverified world-state: ${result.error}`);
```

## How it works

1. Drop the `signature` block; keep the rest as the payload.
2. Canonicalize: JSON, keys sorted recursively, compact separators, non-ASCII escaped `\uXXXX`, UTF-8.
3. Fetch the public key from `https://dynamicfeed.ai/.well-known/keys`, look up `signature.key_id`.
4. Verify the Ed25519 signature over the canonical bytes. Change one byte → it fails.

## Conformance

```bash
python3 tests/verify_vectors.py     # Python harness  → "✓ ALL 10 VECTORS PASS"
node    tests/verify_vectors.mjs    # JS harness (run: npm install --prefix clients/js  first)
```

Both reference verifiers reproduce every vector (same canonical bytes, same signature verdicts), so you can confirm a new implementation in any language byte-for-byte.

## Links

- **Spec:** https://dynamicfeed.ai/standard
- **Verify in your browser:** https://dynamicfeed.ai/proof
- **Public keys (a key_id to Ed25519 public-key map):** https://dynamicfeed.ai/.well-known/keys
- **Discovery manifest:** https://dynamicfeed.ai/.well-known/df-verify.json

## License

MIT.

## Reliability axis

Beyond signing *what* was said, the [`reliability/`](reliability) toolkit grades *how much to believe it*: the OKF reliability object (schema + zero-dep Python & JS validators), enforcing `signed != verified`. See [reliability/README.md](reliability/README.md).
