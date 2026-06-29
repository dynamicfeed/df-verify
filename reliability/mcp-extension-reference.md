# Reliability metadata for MCP tool results: a reference packet

Reference material for a possible MCP extension that lets tool results carry verification metadata, prompted by [modelcontextprotocol/modelcontextprotocol discussion #2964](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2964). This is **not** the SEP. It is the reference object, a ready-made conformance suite, and the cross-ecosystem evidence, assembled so whoever authors the SEP has a bulletproof, low-scope starting point. Dynamic Feed is the reference implementation, not the proposal owner; a SEP is strongest authored by an implementer with a production server network as evidence.

## The model: three orthogonal axes, not one `verification` blob

A single `verification` object conflates three things a consumer must keep separate:

1. **Integrity**: were the bytes unaltered, and who produced them? `serverId`, `serverVersion`, `producedAt`, optional output hash, optional signature. Binary and cheap. This is the thread's phase-1 minimum and the right first step.
2. **Reliability**: how good is the underlying data? Freshness, corroboration, source count, basis. Graded, not binary. This is the axis that actually decides whether an agent should act on a result.
3. **Vantage**: did the producer observe this independently, or relay a self-report? Corroboration is not independence: N servers echoing one upstream is one vantage point, not N.

The load-bearing rule across all three: **signed is not verified.** A server can sign a stale, single-source, self-reported value and the envelope is still cryptographically perfect. If a `verification` object only carries producer plus timestamp plus hash plus signature, every consumer reads "signed" as "trustworthy" and the conflation gets baked into the ecosystem.

## Scope-safe design (answers the caution already on the thread)

- **Optional and additive.** A server emits it or omits it; absence is always valid. Never core-mandated.
- **Advisory and recomputable.** A witness signal the client re-checks for itself, never a trust score the protocol arbitrates, and never a safety certification.
- **Leave a typed slot now.** Ship integrity (`serverId` / `serverVersion` / `producedAt`) first, as the thread proposes, but reserve a typed `reliability` slot so the graded axis is additive in V2 rather than a second breaking change.
- **Carrier.** MCP `_meta` on the tool result is the natural home. Result-level metadata was triaged to Server Card V2, so a typed slot in V1 stays forward-compatible with it.

## The reference object (`reliability`)

Floor is two fields (`confidence` + `basis`); everything else is opt-in (a maturity ladder, not a gate). Full schema: <https://dynamicfeed.ai/schemas/okf-reliability-v1.json>

| field | meaning |
|---|---|
| `confidence` | ordinal band `HIGH \| MEDIUM \| LOW \| UNVERIFIED` (the interoperable surface a consumer filters on) |
| `basis` | how the claim was obtained: `live-source \| partner-attested \| vendor-doc \| forecast \| computed \| inferred` (an `authored` value for human-authored knowledge is under cross-shape discussion on knowledge-catalog#159) |
| `score` | optional 0..1 computed companion to the band, recomputable from `signals` |
| `sources` | count of independent sources behind the reading |
| `verified` | true only with 2+ independent sources (and fresh); never coupled to a signature |
| `vantage` | `independent` vs `producer-reported` |
| `freshness` | measurement recency `{ state, as_of }` |
| `conflict` | first-class disagreement state when sources disagree (both positions + a resolution) |

The honesty rules the schema enforces, which are the point of the object:

1. signed is not verified (`signals.signed` is never coupled to `verified`);
2. `verified: true` requires `sources >= 2`;
3. an `UNVERIFIED` band or a disputed conflict cannot be `verified`;
4. a present `score` must be ordinally coherent with the band;
5. a disputed conflict caps the band at `MEDIUM` (`HIGH` excluded).

## A concrete MCP tool result

```json
{
  "content": [{ "type": "text", "text": "US CPI (YoY): 3.1%" }],
  "_meta": {
    "io.modelcontextprotocol/integrity": {
      "serverId": "dynamicfeed.ai",
      "serverVersion": "0.8.0",
      "producedAt": "2026-06-30T00:00:00Z",
      "outputSha256": "..."
    },
    "reliability": {
      "type": "okf-reliability-v1",
      "confidence": "MEDIUM",
      "basis": "live-source",
      "score": 0.8,
      "sources": 1,
      "verified": false,
      "vantage": "producer-reported",
      "freshness": { "state": "fresh" },
      "signals": { "signed": true, "corroborated": false, "fresh": true }
    }
  }
}
```

Integrity says the bytes are intact and which server produced them. Reliability says how much to believe the value (here: signed and fresh but single-source, so honestly `MEDIUM` and not `verified`). Vantage says the producer is reporting its own observation, not an independent one. A consumer requiring independence reads `vantage`, not the signature. The exact `_meta` key is for the SEP to fix; the shape is what matters.

## Ready-made conformance suite

A SEP needs a way to prove implementations agree. These already exist, MIT-licensed:

- [`conformance-vectors.json`](conformance-vectors.json): 12 portable `{label, expect, reliability}` vectors covering all five honesty rules, verified to match their expects against both the JSON Schema and the reference validators.
- [`a2a-artifact-vectors.json`](a2a-artifact-vectors.json): envelope-level vectors (the same object as a sibling in a carrier's metadata).
- Reference validators in [Python and JavaScript](.), zero-dependency.

Any implementation runs these to confirm it agrees. They can serve directly as the SEP's conformance suite.

## Cross-ecosystem evidence: standardizing an agreed object, not inventing one

The same object is being independently validated and co-designed across ecosystems, so an MCP SEP would be adopting a shape that already has multi-implementation agreement:

| ecosystem | venue | independent implementation | status |
|---|---|---|---|
| Open Knowledge Format (Google) | knowledge-catalog#159 | multi-version corpus; human-authored KB | both validate green (ajv + independent validator); co-designing the `basis` vocabulary |
| in-toto (CNCF) | attestation#554 | agent-decision predicate | the vantage axis was refined here |
| A2A | A2A#2011 | a server network with Bitcoin-anchored provenance | ran the suite green (third implementation); object rides as a sibling in `Artifact.metadata` |
| MCP (Anthropic) | discussion#2964 | a multi-server production network | emits a close shape today; this packet supports the SEP |
| Dynamic Feed | live | live-data layer | producer at `/v1/facts`; hosts the reference validators + conformance suite |

## Boundary

Advisory witness evidence a consumer recomputes for itself. Never a trust score the protocol arbitrates, never a safety certification, never on the money path.
