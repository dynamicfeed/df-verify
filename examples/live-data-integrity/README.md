# Live-Data Integrity Report

A reproducible measurement anyone can re-run. For a set of live-data domains an AI agent might call, it
fetches the datapoint from Dynamic Feed, checks its Ed25519 signature and signer lifecycle against the
reviewed registry snapshot in this repository, and records separate integrity and evidence fields:

- **policy accepted** — do signature mathematics and the pinned signer-lifecycle policy both pass?
- **provenance** — does it name its source and observation time?
- **freshness** — how old is the newest datapoint, from its own timestamp?

The report checks the fields each returned object actually contains. It does not assume an upstream
source lacks provenance, and signer-policy acceptance does not establish objective truth.

## Reproduce it

```bash
python -m pip install -e ../../clients/python
python report.py     # prints the table + headline, writes results.json
```

Run it any day, against live sources, and reproduce the number yourself. Sample run:

```
domain                 accepted   reliability freshness  source
Weather (Sydney)       YES        MEDIUM      13m        Open-Meteo
Earthquakes            YES        MEDIUM      0m         USGS Earthquake Hazards Program
US Treasury yields     YES        MEDIUM      33.5h      U.S. Department of the Treasury
...
6/6 passed signature mathematics and the pinned signer-lifecycle policy.
```

The checked-out registry is a reviewed out-of-band input; its current-domain counterpart is not an
independent trust root. Evidence and reproducible measurement, not truth, safety, or certification.
