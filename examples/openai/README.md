# Grounding an OpenAI agent on verifiable live data

A runnable recipe: before an OpenAI agent acts on a live datapoint, it verifies the Ed25519 signature (integrity) and reads a portable reliability object (`confidence`, `verified`, `vantage`), then gates its action on that. The rule it teaches: **signed is not verified**.

- [`grounding_on_verifiable_live_data.ipynb`](grounding_on_verifiable_live_data.ipynb)

## Run it

```bash
pip install openai cryptography requests
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4.1        # set to whichever current model you use
```

The data source ([Dynamic Feed](https://dynamicfeed.ai)) is keyless, so the verification half runs with no account: fetch a fact, re-canonicalize it (`json-sorted-compact`), check the detached signature against the published key, and read the reliability object. The agent half uses the OpenAI Responses API with a function tool. The pattern is vendor-neutral; any source emitting the same object works.

The reliability object, its JSON Schema, and zero-dependency reference validators are in [`../../reliability`](../../reliability) (MIT).
