# dynamicfeed-verify

Verify [Dynamic Feed](https://dynamicfeed.ai) **DF-VERIFY/1** signed bytes and signing-key lifecycle policy in one line. The default policy is fetched from the current HTTPS domain; origin-independent verification requires an out-of-band pinned registry.

Reference implementation of the [DF-VERIFY/1 standard](https://dynamicfeed.ai/standard).

## Install

`1.0.3` is the hardened source target in this branch. Until the security advisory records that it
has been published and clean-install tested, install from the reviewed source commit rather than
assuming the package index is current:

```bash
python -m pip install -e clients/python
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

# 3) verify fully offline using an out-of-band pinned df-signing-key-registry/v1 document
result = verify(
    signed_response,
    lifecycle_registry=pinned_registry,
    registry_source_authenticated=True,
)

# A legacy flat key map reports crypto_valid only and deliberately leaves ok=False.
crypto_only = verify(signed_response, jwks={"df-ed25519-…": "<base64url key>"})
```

## CLI

```bash
dynamicfeed-verify                       # fetch a live verdict + verify
dynamicfeed-verify - < response.json     # verify a saved signed response
```

## How it works

A signed response carries a `signature` block (`alg`, `key_id`, `canonicalization`, `sig`). Verification:

1. Require the exact `Ed25519` / `json-sorted-compact` signature metadata.
2. Preserve both frozen anchor conventions: try the document without `signature` first, then (only
   if needed) without both `signature` and `anchor`. The result reports
   `anchor_authenticated=True`, `False`, or `None`; a legacy attached anchor is not authenticated by
   signature validity.
3. Canonicalize — JSON, keys sorted recursively, compact separators (`,` `:`), UTF-8. Equivalent to `json.dumps(payload, sort_keys=True, separators=(",", ":"))`.
4. Resolve the key and lifecycle state from `/.well-known/signing-key-registry.json` or a pinned copy.
5. Verify Ed25519 signature mathematics and bind the public key bytes to `key_id`.
6. Return `ok=True` only when cryptography and lifecycle policy pass. Compromised-key bytes remain inspectable through `crypto_valid`, but never turn green from signed `issued_at` or bundle metadata.

Live mode enforces the compiled revision floor plus `minimum_registry_revision` and the caller's
persisted `highest_authenticated_registry_revision`. A registry's self-declared revision is not
anti-rollback. Caller-supplied registries and custom network origins require the caller to set
`registry_source_authenticated=True`; otherwise signature mathematics may pass but `ok` remains
false. Redirects fail closed. `historical_snapshot` is explicit and always non-actionable.

Full specification: **https://dynamicfeed.ai/standard**

## License

MIT.
