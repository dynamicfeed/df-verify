# Grounding an OpenAI agent on verifiable live data

A runnable recipe that separates Ed25519 mathematics, signer-lifecycle acceptance, and a portable
reliability object (`confidence`, `verified`, `vantage`). It produces advisory output; it is not an
actuator. The rule it teaches: **signed is not verified**.

- [`grounding_on_verifiable_live_data.ipynb`](grounding_on_verifiable_live_data.ipynb)

## Run it

```bash
cd examples/openai
pip install openai requests -e ../../clients/python
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4.1        # set to whichever current model you use
```

The data source is keyless, but signer policy still needs trust material. The notebook uses the
reviewed [`SIGNING_KEY_LIFECYCLE.json`](../../SIGNING_KEY_LIFECYCLE.json) snapshot and a caller-held
revision floor. The agent half uses the OpenAI Responses API with a function tool. No signature or
model output should directly authorize a consequential action.

The reliability object, its JSON Schema, and zero-dependency reference validators are in [`../../reliability`](../../reliability) (MIT).
