# dynamicfeed-verify

Verify [Dynamic Feed](https://dynamicfeed.ai) **DF-VERIFY/1** Ed25519-signed responses independently, in one line. No account, no dependency on Dynamic Feed at runtime beyond fetching the public key. You can verify, even against us.

Reference implementation of the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard).

## Install

```bash
pip install dynamicfeed-verify
```

## Use

```python
from dynamicfeed_verify import verify, verify_live

# 1) fetch a fresh signed awareness verdict and verify it
env, result = verify_live()
print(result)        # {'ok': True, 'key_id': 'df-ed25519-…', 'verdict': 'caution', ...}

# 2) verify any signed response you already hold
result = verify(signed_response)
if not result["ok"]:
    raise RuntimeError(result["error"])

# 3) verify fully offline if you already have the JWKS
result = verify(signed_response, jwks={"df-ed25519-…": "<base64url public key>"})
```

## CLI

```bash
dynamicfeed-verify                       # fetch a live verdict + verify
dynamicfeed-verify - < response.json     # verify a saved signed response
```

## How it works

A signed response carries a `signature` block (`alg`, `key_id`, `canonicalization`, `sig`). Verification:

1. Drop the `signature` field; keep the rest as the payload.
2. Canonicalize: JSON, keys sorted recursively, compact separators (`,` `:`), UTF-8. Equivalent to `json.dumps(payload, sort_keys=True, separators=(",", ":"))`.
3. Fetch the public key from `https://dynamicfeed.ai/.well-known/keys` and look up `signature.key_id`.
4. Verify the Ed25519 signature over the canonical bytes. Change one byte → it fails.

Full specification: **https://dynamicfeed.ai/standard**

## License

MIT.
