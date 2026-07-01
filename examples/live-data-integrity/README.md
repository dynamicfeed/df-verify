# Live-Data Integrity Report

A reproducible measurement anyone can re-run. For a set of live-data domains an AI agent might call, it
fetches the datapoint from Dynamic Feed, independently verifies its Ed25519 signature with the open-source
`dynamicfeed-verify` package (no trust in Dynamic Feed beyond the public key), and records three honest,
hard-to-game facts:

- **verifiable** — does the datapoint cryptographically verify against a published key? (yes/no)
- **provenance** — does it name its source and observation time?
- **freshness** — how old is the newest datapoint, from its own timestamp?

The point is structural, not a dig at any source: the same public data, fetched raw from the underlying
source an agent would otherwise call, carries no signature and no provenance. You cannot later prove what it
said, or when. Dynamic Feed returns it signed and provenance-stamped, and this script proves that by verifying
every datapoint itself.

## Reproduce it

```bash
pip install dynamicfeed-verify
python report.py     # prints the table + headline, writes results.json
```

Run it any day, against live sources, and reproduce the number yourself. Sample run:

```
domain                 verifiable reliability freshness  source
Weather (Sydney)       YES        MEDIUM      13m        Open-Meteo
Earthquakes            YES        MEDIUM      0m         USGS Earthquake Hazards Program
US Treasury yields     YES        MEDIUM      33.5h      U.S. Department of the Treasury
...
6/6 verified against the published Ed25519 key with the open-source verifier.
```

Evidence and reproducible measurement, not a certification. Tamper-evident, not tamper-proof.
