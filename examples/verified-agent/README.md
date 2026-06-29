# verified-agent: an AI agent that verifies before it acts

A ~90-line, runnable example of the **DF-VERIFY/1** pattern: *an autonomous agent must not act on world-state it cannot cryptographically verify.*

The agent asks [Dynamic Feed](https://dynamicfeed.ai) for a signed go / caution / no-go verdict about a location, verifies the **Ed25519 signature** against the issuer's published key, and only proceeds if the data is **authentic, unaltered, and permits the action**. Tamper with the verdict after it was signed and the agent refuses to act.

## Run it (< 5 min)

```bash
pip install cryptography
python agent.py            # fetch a live signed verdict, verify it, then act
python agent.py --tamper   # alter the verdict after signing → verification fails → agent refuses
```

Expected:

```
$ python agent.py
✅  VERIFIED (signed by df-ed25519-4cb32e72f333) · verdict='caution', proceeding with the action.

$ python agent.py --tamper
⚠   tamper mode: flipped the verdict to 'go' after it was signed
⛔  REFUSING TO ACT. Unverifiable world-state: signature invalid: ...
    An agent must never act on data it cannot prove is authentic and unaltered.
```

## Why this matters

When an AI *acts* (it moves a robot, places a trade, files a claim, dispatches a crew), the data it acted on becomes a liability question: *can you prove what the agent was told, and that no one altered it?* DF-VERIFY answers that with a portable signature anyone can check, with no account and no trust in the vendor. You can verify even against us.

The whole verifier is the ~12 lines under `# DF-VERIFY/1` in `agent.py`. Three steps:

1. Drop the `signature` block; keep the rest as the payload.
2. Canonicalize: JSON, keys sorted recursively, compact separators, UTF-8.
3. Fetch the public key from `/.well-known/keys`, look up `signature.key_id`, verify the Ed25519 signature over the canonical bytes. One changed byte → it fails.

## In production

This file inlines the verifier so it runs with zero install beyond `cryptography`. For real use, install the packaged reference verifier:

```bash
pip install dynamicfeed-verify
```

```python
from dynamicfeed_verify import verify_live
env, result = verify_live()
if not result["ok"]:
    raise RuntimeError(f"unverified world-state: {result['error']}")
```

- **Spec:** https://dynamicfeed.ai/standard
- **Verify in the browser:** https://dynamicfeed.ai/proof
- **Public keys (a key_id to Ed25519 public-key map):** https://dynamicfeed.ai/.well-known/keys

## License

MIT.
