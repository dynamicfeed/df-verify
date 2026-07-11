// Offline regression tests for the anchor-convention fix (@dynamicfeed/verify).
//
// A /v1/answer receipt carries a top-level `anchor` block attached AFTER signing (an RFC 3161 / DLT
// anchor is a timestamp OF the signed hash, so it can only land post-signing). A verifier that
// strips only `signature` recomputes the wrong bytes and wrongly reports INVALID. These fixtures
// were captured live from dynamicfeed.ai (2026-07-09); the key df-ed25519-… is persistent. No net.
//
// Run:  node clients/js/tests/anchor.test.js
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const verifierEntry = process.env.DF_VERIFY_PACKAGE_ENTRY;
const verifierModule = verifierEntry
  ? await import(pathToFileURL(resolve(verifierEntry)).href)
  : await import('../index.js');
const { validateLifecycleRegistry, verify } = verifierModule;

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const lifecycleRegistry = JSON.parse(readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../../../SIGNING_KEY_LIFECYCLE.json'), 'utf8'
));
const read = (n) => readFileSync(join(FIX, n), 'utf8');
const jwks = (pkFile, kid) => ({ [kid]: read(pkFile).trim() });
const kidOf = (text) => JSON.parse(text).signature.key_id;
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function mutateUnusedBits(encoded, unusedBits) {
  const padding = (encoded.match(/=+$/) || [''])[0];
  const unpadded = encoded.slice(0, encoded.length - padding.length);
  const lastIndex = B64URL.indexOf(unpadded.at(-1));
  assert.ok(lastIndex >= 0, 'test input must end in base64url data');
  assert.strictEqual(lastIndex & ((1 << unusedBits) - 1), 0,
    'test input must use a canonical final character');
  return unpadded.slice(0, -1) + B64URL[lastIndex + 1] + padding;
}

function replaceSignatureText(rawEnvelope, replacement) {
  const original = JSON.parse(rawEnvelope).signature.sig;
  const needle = `"sig":"${original}"`;
  assert.strictEqual(rawEnvelope.split(needle).length, 2,
    'fixture must contain exactly one signature value');
  return rawEnvelope.replace(needle, `"sig":"${replacement}"`);
}

async function run() {
  // 1) anchored /v1/answer must verify VALID (the previously-broken case)
  const ans = read('answer_anchored.json');
  assert.ok(ans.includes('"anchor"'), 'fixture must carry an anchor block');
  const r1 = await verify(ans, { lifecycleRegistry });
  assert.ok(r1.cryptoValid, 'anchored /v1/answer signature math must verify: ' + JSON.stringify(r1));
  assert.ok(!r1.ok && r1.lifecycleStatus === 'compromised',
    'historical compromised-key fixture must fail overall lifecycle policy');
  assert.strictEqual(r1.anchorAuthenticated, false,
    'legacy post-signature anchor must be surfaced as unauthenticated');

  // 2) no-anchor awareness must still verify VALID (no regression)
  const aw = read('awareness_noanchor.json');
  assert.ok(!aw.includes('"anchor"'), 'fixture must have no anchor block');
  const r2 = await verify(aw, { lifecycleRegistry });
  assert.ok(r2.cryptoValid, 'no-anchor awareness signature math must verify: ' + JSON.stringify(r2));
  assert.ok(!r2.ok && r2.lifecycleStatus === 'compromised');
  assert.strictEqual(r2.anchorAuthenticated, null);

  // 3) body tamper (flip a digit before the signature block) must verify INVALID
  const bad = ans.replace(/(\d)(?=[\s\S]*"signature")/, (d) => (d === '9' ? '8' : String(+d + 1)));
  assert.notStrictEqual(bad, ans, 'tamper must change the text');
  const r3 = await verify(bad, { lifecycleRegistry });
  assert.ok(!r3.cryptoValid && !r3.ok, 'a tampered body must fail cryptographic verification');

  // 4) live registry revisions are monotonic caller state, never a bundle/self-supplied floor.
  for (const value of [undefined, false, 0, 1.5]) {
    const badRegistry = structuredClone(lifecycleRegistry);
    if (value === undefined) delete badRegistry.registry_revision;
    else badRegistry.registry_revision = value;
    await assert.rejects(() => validateLifecycleRegistry(badRegistry), /registry_revision/);
  }
  await validateLifecycleRegistry(lifecycleRegistry, { minimumRegistryRevision: 1 });
  await assert.rejects(() => validateLifecycleRegistry(lifecycleRegistry, {
    minimumRegistryRevision: 2,
  }), /below effective floor/);

  const malformedKey = structuredClone(lifecycleRegistry);
  malformedKey.public_keys[malformedKey.active_key_id] = '!!!!';
  await assert.rejects(() => validateLifecycleRegistry(malformedKey), /base64url/);
  const malformedPadding = structuredClone(lifecycleRegistry);
  malformedPadding.public_keys[malformedPadding.active_key_id] = 'AA=';
  await assert.rejects(() => validateLifecycleRegistry(malformedPadding), /base64url/);
  const invalidCalendar = structuredClone(lifecycleRegistry);
  invalidCalendar.updated_at = '2026-02-30T10:00:00Z';
  await assert.rejects(() => validateLifecycleRegistry(invalidCalendar), /invalid/);
  const malformedSignature = JSON.parse(aw);
  malformedSignature.signature.sig = '!!!!';
  const malformedResult = await verify(malformedSignature, {
    lifecycleRegistry, registrySourceAuthenticated: true,
  });
  assert.strictEqual(malformedResult.ok, false);
  assert.strictEqual(malformedResult.cryptoValid, false);
  assert.match(malformedResult.error, /encoding/);

  // The signature block is outside the signed payload. A 64-byte value has four unused bits in
  // its final base64url character, so a permissive decoder can accept 15 alternate spellings for
  // exactly the same Ed25519 bytes. Preserve the raw fixture bytes and mutate only that spelling.
  const signatureText = JSON.parse(aw).signature.sig;
  const malleableSignatureText = mutateUnusedBits(signatureText, 4);
  assert.deepStrictEqual(Buffer.from(malleableSignatureText, 'base64url'),
    Buffer.from(signatureText, 'base64url'), 'mutation must preserve decoded signature bytes');
  const malleableSignature = await verify(
    replaceSignatureText(aw, malleableSignatureText),
    { lifecycleRegistry, registrySourceAuthenticated: true },
  );
  assert.strictEqual(malleableSignature.ok, false);
  assert.strictEqual(malleableSignature.cryptoValid, false);
  assert.match(malleableSignature.error, /non-canonical base64url encoding/);

  // A 32-byte public key has two unused bits in its final base64url character. The lifecycle
  // registry must reject an alternate spelling even though it decodes to the same key bytes.
  const publicKeyText = lifecycleRegistry.public_keys[kidOf(aw)];
  const malleablePublicKeyText = mutateUnusedBits(publicKeyText, 2);
  assert.deepStrictEqual(Buffer.from(malleablePublicKeyText, 'base64url'),
    Buffer.from(publicKeyText, 'base64url'), 'mutation must preserve decoded public-key bytes');
  const malleablePublicKey = structuredClone(lifecycleRegistry);
  malleablePublicKey.public_keys[kidOf(aw)] = malleablePublicKeyText;
  await assert.rejects(() => validateLifecycleRegistry(malleablePublicKey),
    /non-canonical base64url encoding/);

  const shortSignature = replaceSignatureText(aw, 'AA');
  const shortSignatureResult = await verify(shortSignature, {
    lifecycleRegistry, registrySourceAuthenticated: true,
  });
  assert.strictEqual(shortSignatureResult.ok, false);
  assert.strictEqual(shortSignatureResult.cryptoValid, false);
  assert.match(shortSignatureResult.error, /exactly 64 bytes/);
  const shortPublicKey = structuredClone(lifecycleRegistry);
  shortPublicKey.public_keys[kidOf(aw)] = 'AA';
  await assert.rejects(() => validateLifecycleRegistry(shortPublicKey), /exactly 32 bytes/);

  const unpaddedRegistry = structuredClone(lifecycleRegistry);
  unpaddedRegistry.public_keys[kidOf(aw)] = publicKeyText.replace(/=+$/, '');
  await validateLifecycleRegistry(unpaddedRegistry);

  // 5) historical inspection is explicit and can never turn the overall result green.
  const historical = await verify(aw, { lifecycleRegistry, verificationMode: 'historical_snapshot',
    minimumRegistryRevision: 2, registrySourceAuthenticated: true });
  assert.strictEqual(historical.ok, false);
  assert.strictEqual(historical.historicalSnapshot, true);
  assert.strictEqual(historical.registryRevision, 1);
  assert.strictEqual(historical.effectiveRegistryFloor, 0);
  assert.strictEqual(historical.rollbackProtected, false);

  assert.strictEqual(r2.registryRevision, 1);
  assert.strictEqual(r2.effectiveRegistryFloor, 1);
  assert.strictEqual(r2.rollbackProtected, false,
    'no caller-retained authenticated revision state means future rollback protection is not claimed');

  const previousFetch = globalThis.fetch;
  try {
    const keyId = JSON.parse(aw).signature.key_id;
    const activeRegistry = structuredClone(lifecycleRegistry);
    activeRegistry.active_key_id = keyId;
    activeRegistry.public_keys = { [keyId]: lifecycleRegistry.public_keys[keyId] };
    const activeMetadata = activeRegistry.lifecycle[keyId];
    Object.assign(activeMetadata, { status: 'active', retired_at: null, compromised_after: null });
    activeRegistry.lifecycle = { [keyId]: activeMetadata };
    const supplied = await verify(aw, { lifecycleRegistry: activeRegistry });
    assert.strictEqual(supplied.cryptoValid, true);
    assert.strictEqual(supplied.ok, false);
    assert.match(supplied.error, /not explicitly authenticated/);
    const suppliedAuthenticated = await verify(aw, { lifecycleRegistry: activeRegistry,
      registrySourceAuthenticated: true });
    assert.strictEqual(suppliedAuthenticated.ok, true);

    globalThis.fetch = async () => ({ ok: true, text: async () => JSON.stringify(activeRegistry) });
    const custom = await verify(aw, { base: 'https://mirror.example',
      highestAuthenticatedRegistryRevision: 1 });
    assert.strictEqual(custom.trustBasis, 'caller-configured-network-origin');
    assert.strictEqual(custom.registrySourceAuthenticated, false);
    assert.strictEqual(custom.rollbackProtected, false);
    assert.strictEqual(custom.ok, false);
    const explicit = await verify(aw, { base: 'https://mirror.example',
      highestAuthenticatedRegistryRevision: 1, registrySourceAuthenticated: true });
    assert.strictEqual(explicit.registrySourceAuthenticated, true);
    assert.strictEqual(explicit.rollbackProtected, true);
    assert.strictEqual(explicit.ok, true);
  } finally {
    globalThis.fetch = previousFetch;
  }

  console.log('PASS — lifecycle, canonical base64url, exact lengths, signature math, and tamper checks');
}

run().catch((e) => {
  console.error('FAIL —', e.message);
  process.exit(1);
});
