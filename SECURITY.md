# Security policy

## Advisory DFF-2026-07-11-01 — signer lifecycle bypass

Status: production service cutover completed 2026-07-11; hardened source merged; Rust
`dynamicfeed-verify` `1.0.2` published and registry-verified; Python and npm publications remain
incomplete.

Earlier Python, JavaScript, and Rust verifiers could treat successful Ed25519 mathematics against a
flat key map as an overall accepted result. Flat key bytes contain no lifecycle status. After a key
is retired or compromised, a lifecycle-unaware verifier can therefore accept newly forged bytes as
if the signer were still authorized.

The former key `df-ed25519-4cb32e72f333` is classified compromised using the conservative boundary
`2026-07-11T00:00:00Z`. Its public key remains available for historical analysis. A caller-reported
`issued_at`, a bundle-embedded key, a self-declared registry revision, or an unverified timestamp
artifact cannot rehabilitate it.

### Affected and target versions

| Package/source | Affected | Hardened version | Release status |
|---|---:|---:|---|
| PyPI `dynamicfeed-verify` | `<= 1.0.2` | `1.0.3` | Pending; publishing credentials unavailable |
| npm `@dynamicfeed/verify` | `<= 1.0.1` | `1.0.2` | Pending; publishing credentials unavailable |
| crates.io `dynamicfeed-verify` | published `1.0.0`; prior repository source `1.0.1` | `1.0.2` | Published and registry-verified 2026-07-11 |
| C# sample | all current source | quarantined pending a conformant implementation | Not a package |

The Rust row is a release attestation backed by the evidence recorded below. The Python and npm
version numbers describe source targets only; check their package registries and this advisory
before depending on them.

### Corrected behavior

- signature mathematics is reported separately from signer acceptance;
- exact algorithm and canonicalization metadata are enforced;
- public key bytes must derive the declared key ID;
- duplicate JSON names and malformed JSON fail closed;
- both frozen anchor signature scopes remain compatible, with explicit anchor-authentication state;
- lifecycle registries require complete key/status/fingerprint/chronology/policy relationships;
- live mode accepts only the registry's active key;
- caller-supplied registries and custom network origins require an explicit authenticated-source
  assertion before live policy can pass, and network redirects fail closed;
- retired material is historical and non-live;
- compromised keys are never policy accepted;
- `historical_snapshot` mode is explicit and never actionable;
- live registry revisions enforce the compiled, caller-supplied, and caller-retained floors;
- rollback protection is claimed only when the caller supplies authenticated retained state.

### Trust-boundary warning

`SIGNING_KEY_LIFECYCLE.json` is a reviewed out-of-band snapshot in this source repository. The same
document served by `dynamicfeed.ai` is domain-authenticated operational disclosure, not an
independent lifecycle authority. Security gates should pin trust material outside the receipt
channel and authenticate registry updates.

`KNOWN_KEYS.json` is deprecated and deliberately non-flat. It preserves both public keys and marks
the former key compromised. It must not be converted back into an additive list of accepted keys.

### C# status

The C# sample is not a reference verifier. It lacks conformance-tested canonicalization, lifecycle,
and anti-rollback logic. Its network response is explicitly unverified; compatibility methods that
could return an actionable verdict throw `NotSupportedException`.

### Rust `1.0.2` release evidence

The crates.io package was built from source commit
`95e033efd252e9e97029c0ef97a3ccddad9b6351`, which is also the commit tagged `rust-v1.0.2`.
crates.io records `published_at` as `2026-07-11T16:14:45.939696Z` and the crate size as `29597`
bytes. The crates.io artifact and GitHub release asset have the identical SHA-256 digest
`798bc660b4e9abe25c7f62bcd8007cf1897ca0d8607d975d8b9ba0b8d841d019`.

A clean environment installed `dynamicfeed-verify` `1.0.2` from the crates.io registry. Verification
returned `POLICY_ACCEPTED` for the active signer and `CRYPTO_VALID` with `LIFECYCLE_REJECTED` for
the former compromised signer. These checks attest to the Rust registry artifact only. PyPI
`dynamicfeed-verify` `1.0.3` and npm `@dynamicfeed/verify` `1.0.2` remain pending because publishing
credentials were unavailable, so the overall package rotation is not complete.

This release evidence does not establish full RFC 3161 or OpenTimestamps proof verification. The
libraries continue to distinguish signed anchor attachment from independent timestamp-proof
validation.

### Service cutover and package-release criteria

The production service cutover is complete: `/.well-known/keys` exposes only the active key, while
the lifecycle registry retains the former public key with `compromised` status. Live endpoints,
logs, and rollback were verified as part of that deployment. Those service facts do not publish or
attest to any package-registry artifact.

Do not call the multi-ecosystem verifier **package** rotation complete until all of the following
are recorded for every package:

1. the reviewed source commit and passing CI;
2. package builds from that exact commit;
3. registry publication through normal release controls;
4. clean-environment installation and compromised-key rejection tests for every package;
5. artifact hashes and source provenance;
6. advisory update naming the released versions and completion time.

Merging source in this repository does not publish packages. The Rust `1.0.2` publication and
clean-install checks are recorded above; the Python `1.0.3` and npm `1.0.2` targets remain
unreleased until their registry publications and clean-install checks are recorded.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- GitHub: use **Security > Report a vulnerability** on this repository; or
- email: **hello@dynamicfeed.ai**.

Include the affected implementation, version/commit, minimal reproduction, trust material used,
and expected versus actual `crypto_valid` and policy result. A fixture based on
[`tests/vectors`](tests/vectors) is ideal.

## Scope

In scope:

- false cryptographic acceptance or rejection;
- signer lifecycle or registry anti-rollback bypass;
- canonicalization divergence;
- key-ID/fingerprint confusion;
- duplicate-key parsing differences;
- anchor-scope confusion;
- a sample or CLI that turns crypto-only or unverified data into an actionable policy result.

Endpoint availability is outside this verifier repository's scope, but unsafe fallback from an
unavailable lifecycle registry is in scope.
