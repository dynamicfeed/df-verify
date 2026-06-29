# Reliability object: how much to believe a claim

The **reliability axis** is the fourth trust question, distinct from integrity (is it unaltered), authority (who attests), and citation (is it grounded): **how much should a consumer believe the claim itself**. Proposed in the Open Knowledge Format ([knowledge-catalog#151](https://github.com/GoogleCloudPlatform/knowledge-catalog/issues/151), [PR #159](https://github.com/GoogleCloudPlatform/knowledge-catalog/pull/159)) and as an in-toto predicate ([in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554)).

The cardinal rule: **`signed != verified`**. A signature proves integrity, not truth; `verified` is earned only by independent corroboration.

A second rung, refined in [in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554): **`verified != observed-independently`**. Corroboration is not independence, because multiple sources can all sit on the producer's side. So an optional `vantage` field records the observational basis: `independent` (recorded independently of the producer) or `producer-reported` (the producer attesting its own observation). A signed, corroborated, fresh reading can still be `producer-reported`. The full honesty ladder is **signed != verified != observed-independently**, and a consumer that needs independent observation should require `vantage: independent` rather than read a signature or a high score as independence.

| File | What |
|---|---|
| [`okf-reliability-v1.schema.json`](okf-reliability-v1.schema.json) | JSON Schema (draft 2020-12) for the reliability object. Canonical copy at https://dynamicfeed.ai/schemas/okf-reliability-v1.json |
| [`verify_reliability.py`](verify_reliability.py) | Zero-dependency Python reference validator (stdlib only) |
| [`verify_reliability.js`](verify_reliability.js) | Zero-dependency JavaScript validator (node + browser) |
| [`conformance-vectors.json`](conformance-vectors.json) | Portable pass/fail vectors (`{label, expect, reliability}`) covering all five honesty rules. Run them against any validator to confirm an independent implementation agrees. |
| [`examples/`](examples) | Worked example bundle (live single-source, corroborated, conflict, floor, and both vantages) |

## Run it

```bash
python3 verify_reliability.py --selftest          # built-in good/bad cases
python3 verify_reliability.py path/to/fact.json   # validate a reliability object, a fact, or a /v1/facts response
node     verify_reliability.js --selftest
```

Both enforce the same honesty invariants: ordinal `confidence` band; `verified:true` requires `>=2 sources`; `UNVERIFIED` cannot be verified or carry a high score; `HIGH` cannot ride a near-zero score; a disputed `conflict` must retain both positions plus a resolution; a redundant `signals.conflict` must agree with `conflict.disputed`; and `vantage`, when present, must be `independent` or `producer-reported`.

## The object

```yaml
reliability:
  confidence: MEDIUM          # HIGH | MEDIUM | LOW | UNVERIFIED  (the interoperable surface)
  basis: live-source          # live-source | partner-attested | vendor-doc | forecast | computed | inferred
  score: 0.8                  # optional 0..1, present only when computed; recomputable from signals
  sources: 1
  verified: false             # true only with independent corroboration, never from a signature alone
  vantage: producer-reported  # independent | producer-reported  (observation basis; corroboration is not independence)
  freshness: { as_of: 2026-06-29T00:00:00Z, state: fresh }
  signals: { signed: true, corroborated: false, fresh: true }
```

Live reference implementation: `GET https://dynamicfeed.ai/v1/facts` emits this object on every fact.
