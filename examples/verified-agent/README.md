# verified-agent — verify advisory evidence before policy review

This runnable example fetches a live `awareness/v1` advisory and checks four separate properties:

1. the signature declares exactly `Ed25519` and `json-sorted-compact`;
2. the public key derives the declared `signature.key_id`;
3. the Ed25519 signature matches the canonical record bytes; and
4. the signer is accepted by a validated `df-signing-key-registry/v1` lifecycle policy.

It deliberately does **not** actuate. A valid signature proves integrity under a selected key, not objective truth, safety, authorization, or that a machine used the record. A passing check only makes the advisory eligible for caller-owned policy, independent safety checks, and authorization.

## Run it

```bash
pip install cryptography
python agent.py
python agent.py --tamper
```

Expected shape:

```text
ACCEPTED AS ADVISORY EVIDENCE (key df-ed25519-<derived-id>, lifecycle active) · verdict='caution'
NO ACTION EXECUTED — caller-owned policy, independent safety checks, and authorization remain required.

tamper mode: rewrote the verdict after signing
REJECTED — advisory record not accepted: signature invalid
```

## What the verifier does

The example strictly parses downloaded JSON, rejecting duplicate keys, invalid constants, malformed input, and oversized responses. It then:

1. removes the top-level `signature` block;
2. canonicalizes the remaining record with recursively sorted keys, compact separators, ASCII escaping, and UTF-8;
3. validates the lifecycle registry and its public-key fingerprints;
4. derives `key_id` from the selected public key;
5. verifies the detached Ed25519 signature; and
6. rejects compromised keys. A fresh real-time advisory must use the registry's active key.

Two historical anchor conventions exist. If a legacy receipt appended `anchor` after signing, the signature can still validate but the result reports `anchor_authenticated: false`. That anchor must not be treated as covered by the envelope signature.

The default registry is fetched from [`/.well-known/signing-key-registry.json`](https://dynamicfeed.ai/.well-known/signing-key-registry.json). Because it comes from the same current HTTPS domain as the record, it is operational disclosure—not an independent trust root. High-assurance consumers should pin the registry or its expected key identities through an out-of-band channel and explicitly record whether that source was authenticated. Merely passing a caller-supplied object does not make it independent. The flat [`/.well-known/keys`](https://dynamicfeed.ai/.well-known/keys) map contains cryptographic bytes only and cannot produce an overall accepted lifecycle result.

Live mode requires the active key and `registry_revision >= 1`. A caller may raise that floor or retain the highest authenticated revision durably; rollback protection is reported only when both authenticated source state and a retained revision are supplied. `historical_snapshot` mode is explicit and non-actionable, and cannot make the live `ok` result pass.

For production, use a lifecycle-aware verifier release that exposes separate cryptographic, key-binding, lifecycle, and anchor-scope results. Do not assume an older package release is lifecycle-aware merely because it accepts the signature mathematics.

- **Profile:** https://dynamicfeed.ai/standard
- **Browser verifier:** https://dynamicfeed.ai/verify.js
- **Lifecycle registry:** https://dynamicfeed.ai/.well-known/signing-key-registry.json

## License

MIT.
