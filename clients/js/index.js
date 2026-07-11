// @dynamicfeed/verify — independently verify Dynamic Feed (DF-VERIFY/1) Ed25519-signed responses.
//
// Runtime-agnostic ESM (Node >=18, Deno, Bun, browsers/bundlers). Reproduces the server's
// canonicalization BYTE-FOR-BYTE — json-sorted-compact, Python `ensure_ascii` escaping, the
// `signature` field stripped, numbers preserved verbatim via a lossless parse — then verifies the
// detached Ed25519 signature against the published JWKS using @noble/ed25519. Proven identical to
// the Python (scripts/verify_awareness.py) and in-browser (web/verify.js) reference verifiers.
//
// Spec: https://dynamicfeed.ai/standard
import * as ed from '@noble/ed25519';

export const DEFAULT_BASE = 'https://dynamicfeed.ai';
export const COMPILED_MIN_REGISTRY_REVISION = 1;

function b64u(s) {
  const padding = typeof s === 'string' ? ((s.match(/=+$/) || [''])[0].length) : 0;
  const coreLength = typeof s === 'string' ? s.length - padding : 0;
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(s) || coreLength % 4 === 1
      || (padding && s.length % 4 !== 0))
    throw new Error('invalid base64url');
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

// lossless JSON parse — numbers kept VERBATIM so re-canonicalization matches Python's repr exactly
function lparse(s) {
  if (typeof s !== 'string') throw new Error('input must be text');
  let i = 0;
  function fail(msg) { throw new Error(msg + ' @' + i); }
  function ws() { while (i < s.length) { const c = s[i]; if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++; else break; } }
  function val() { ws(); const c = s[i];
    if (c === '{') return obj(); if (c === '[') return arr(); if (c === '"') return { t: 's', v: str() };
    if (s.slice(i, i + 4) === 'true') { i += 4; return { t: 'b', v: true }; }
    if (s.slice(i, i + 5) === 'false') { i += 5; return { t: 'b', v: false }; }
    if (s.slice(i, i + 4) === 'null') { i += 4; return { t: 'z' }; }
    if (c === '-' || /[0-9]/.test(c || '')) return num(); fail('unexpected token'); }
  function obj() { i++; const p = [], seen = new Set(); ws(); if (s[i] === '}') { i++; return { t: 'o', v: p }; }
    for (;;) { ws(); const k = str(); ws(); if (s[i++] !== ':') fail('expected colon');
      if (seen.has(k)) fail('duplicate object key'); seen.add(k); const v = val(); p.push([k, v]); ws();
      if (s[i] === ',') { i++; continue; } if (s[i] === '}') { i++; break; } fail('expected comma or object end'); } return { t: 'o', v: p }; }
  function arr() { i++; const a = []; ws(); if (s[i] === ']') { i++; return { t: 'a', v: a }; }
    for (;;) { a.push(val()); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === ']') { i++; break; } fail('expected comma or array end'); } return { t: 'a', v: a }; }
  function str() { if (s[i] !== '"') fail('expected string'); let r = ''; i++;
    while (i < s.length) { const ch = s[i++]; if (ch === '"') return r;
      if (ch === '\\') { if (i >= s.length) fail('unterminated escape'); const e = s[i++];
        if (e === 'u') { const hex = s.slice(i, i + 4); if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail('invalid unicode escape'); r += String.fromCharCode(parseInt(hex, 16)); i += 4; }
        else { const escapes = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
          if (!Object.prototype.hasOwnProperty.call(escapes, e)) fail('invalid escape'); r += escapes[e]; } }
      else { if (ch.charCodeAt(0) < 0x20) fail('unescaped control character'); r += ch; } } fail('unterminated string'); }
  function num() { const a = i; if (s[i] === '-') i++; if (s[i] === '0') i++;
    else if (/[1-9]/.test(s[i] || '')) while (/[0-9]/.test(s[i] || '')) i++; else fail('invalid number');
    if (s[i] === '.') { i++; if (!/[0-9]/.test(s[i] || '')) fail('invalid fraction'); while (/[0-9]/.test(s[i] || '')) i++; }
    if (s[i] === 'e' || s[i] === 'E') { i++; if (s[i] === '+' || s[i] === '-') i++;
      if (!/[0-9]/.test(s[i] || '')) fail('invalid exponent'); while (/[0-9]/.test(s[i] || '')) i++; }
    return { t: 'n', v: s.slice(a, i) }; }
  const root = val(); ws(); if (i !== s.length) fail('trailing data'); return root;
}

// Python json.dumps string escaping with ensure_ascii=True
function pys(str) { let o = '"'; for (const ch of str) { const c = ch.codePointAt(0);
    if (ch === '"') o += '\\"'; else if (ch === '\\') o += '\\\\';
    else if (ch === '\n') o += '\\n'; else if (ch === '\r') o += '\\r'; else if (ch === '\t') o += '\\t';
    else if (ch === '\b') o += '\\b'; else if (ch === '\f') o += '\\f';
    else if (c < 0x20) o += '\\u' + c.toString(16).padStart(4, '0');
    else if (c <= 0x7e) o += ch;
    else if (c > 0xffff) { const x = c - 0x10000; o += '\\u' + (0xd800 + (x >> 10)).toString(16).padStart(4, '0') + '\\u' + (0xdc00 + (x & 0x3ff)).toString(16).padStart(4, '0'); }
    else o += '\\u' + c.toString(16).padStart(4, '0'); }
  return o + '"'; }

function pyKeyCmp(a, b) { const aa = Array.from(a, ch => ch.codePointAt(0)), bb = Array.from(b, ch => ch.codePointAt(0));
  const n = Math.min(aa.length, bb.length); for (let i = 0; i < n; i++) if (aa[i] !== bb[i]) return aa[i] - bb[i]; return aa.length - bb.length; }
function canon(n) { if (n.t === 'o') { const keys = n.v.map(p => p[0]).sort(pyKeyCmp); const m = {}; n.v.forEach(p => m[p[0]] = p[1]);
    return '{' + keys.map(k => pys(k) + ':' + canon(m[k])).join(',') + '}'; }
  if (n.t === 'a') return '[' + n.v.map(canon).join(',') + ']';
  if (n.t === 's') return pys(n.v); if (n.t === 'n') return n.v;
  if (n.t === 'b') return n.v ? 'true' : 'false'; return 'null'; }

function field(node, key) { if (!node || node.t !== 'o') return null; for (const [k, v] of node.v) if (k === key) return v; return null; }

async function keyIdFor(pub) { const h = new Uint8Array(await crypto.subtle.digest('SHA-256', pub));
  return 'df-ed25519-' + [...h.slice(0, 6)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function utcMillis(value, name) { const m = typeof value === 'string' && value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/);
  if (!m) throw new Error(name + ' must be RFC3339 UTC'); const n = Date.parse(value), d = new Date(n), p = m.slice(1, 7).map(Number);
  if (!Number.isFinite(n) || d.getUTCFullYear() !== p[0] || d.getUTCMonth() + 1 !== p[1] || d.getUTCDate() !== p[2]
      || d.getUTCHours() !== p[3] || d.getUTCMinutes() !== p[4] || d.getUTCSeconds() !== p[5]) throw new Error(name + ' is invalid'); return n; }
function revisionContext(raw, opts = {}) { const mode = opts.verificationMode || 'live';
  if (mode !== 'live' && mode !== 'historical_snapshot') throw new Error('verificationMode must be live or historical_snapshot');
  const revision = raw && raw.registry_revision;
  if (!Number.isInteger(revision) || revision < 1) throw new Error('registry_revision must be a positive integer');
  for (const [name, value] of [['minimumRegistryRevision', opts.minimumRegistryRevision],
    ['highestAuthenticatedRegistryRevision', opts.highestAuthenticatedRegistryRevision]]) {
    if (value !== undefined && value !== null && (!Number.isInteger(value) || value < 1))
      throw new Error(name + ' must be a positive integer');
  }
  const floor = mode === 'historical_snapshot' ? 0 : Math.max(COMPILED_MIN_REGISTRY_REVISION,
    opts.minimumRegistryRevision || COMPILED_MIN_REGISTRY_REVISION,
    opts.highestAuthenticatedRegistryRevision || 0);
  if (mode === 'live' && revision < floor) throw new Error('registry revision ' + revision + ' is below effective floor ' + floor);
  return { mode, registryRevision: revision, effectiveRegistryFloor: floor,
    historicalSnapshot: mode === 'historical_snapshot' }; }
export async function validateLifecycleRegistry(raw, opts = {}) { if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || raw.schema !== 'df-signing-key-registry/v1' || raw.issuer !== 'dynamicfeed.ai') throw new Error('invalid lifecycle registry identity');
  revisionContext(raw, opts); utcMillis(raw.updated_at, 'updated_at'); const keys = raw.public_keys, life = raw.lifecycle, activeId = raw.active_key_id;
  if (!keys || !life || typeof keys !== 'object' || typeof life !== 'object' || Array.isArray(keys) || Array.isArray(life)) throw new Error('invalid lifecycle registry maps');
  const ids = Object.keys(keys).sort(), lids = Object.keys(life).sort(); if (!ids.length || ids.length !== lids.length || ids.some((x, i) => x !== lids[i])) throw new Error('incomplete lifecycle registry');
  let active = 0; for (const id of ids) { const pub = b64u(keys[id]); if (pub.length !== 32 || await keyIdFor(pub) !== id) throw new Error('key id binding mismatch');
    const meta = life[id]; if (!meta || meta.alg !== 'Ed25519' || meta.use !== 'receipt-signing' || !['active', 'retired', 'compromised'].includes(meta.status)) throw new Error('invalid lifecycle entry');
    const fingerprint = [...new Uint8Array(await crypto.subtle.digest('SHA-256', pub))].map(b => b.toString(16).padStart(2, '0')).join('');
    if (meta.fingerprint_sha256 !== fingerprint || meta.public_key_retained !== true) throw new Error('lifecycle fingerprint/retention mismatch');
    const first = utcMillis(meta.first_used_at, id + '.first_used_at'), from = utcMillis(meta.active_from, id + '.active_from'); if (first > from) throw new Error('invalid lifecycle interval');
    if (meta.status === 'active') { active++; if (id !== activeId || meta.retired_at !== null || meta.compromised_after !== null) throw new Error('active lifecycle mismatch'); }
    else { const retired = utcMillis(meta.retired_at, id + '.retired_at'); if (from > retired) throw new Error('invalid retirement interval');
      if (meta.status === 'compromised') { if (utcMillis(meta.compromised_after, id + '.compromised_after') > retired) throw new Error('invalid compromise boundary'); }
      else if (meta.compromised_after !== null) throw new Error('retired key carries compromise metadata'); }
  }
  if (active !== 1 || !Object.prototype.hasOwnProperty.call(keys, activeId) || !raw.authority || raw.authority.independent_registry_root !== false) throw new Error('invalid registry authority/active key');
  const policy = raw.verification_policy || {}; for (const n of ['cryptographic_validity_separate_from_lifecycle', 'retired_keys_verify_historical_bytes',
    'compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp', 'receipt_issued_at_alone_is_not_independent_time_evidence']) if (policy[n] !== true) throw new Error('incomplete registry verification policy');
  return raw; }
function lifecyclePolicy(registry, keyId, mode = 'live') { const meta = registry && registry.lifecycle && registry.lifecycle[keyId];
  if (!meta) return { status: 'unknown', accepted: false, reason: 'key absent from lifecycle registry' };
  if (mode === 'historical_snapshot') return meta.status === 'compromised'
    ? { status: 'compromised', accepted: false, policyAsOfAccepted: false,
      reason: 'compromised key; no verified signature-inclusive pre-boundary commitment', compromisedAfter: meta.compromised_after }
    : { status: meta.status, accepted: false, policyAsOfAccepted: true,
      reason: 'historical snapshot is non-live and non-actionable; policy-as-of is reported separately' };
  if (meta.status === 'active') return { status: 'active', accepted: registry.active_key_id === keyId, reason: 'active lifecycle key' };
  if (meta.status === 'retired') return { status: 'retired', accepted: false, reason: 'retired key is not accepted for live verification' };
  return { status: 'compromised', accepted: false, reason: 'compromised key; no verified signature-inclusive pre-boundary commitment', compromisedAfter: meta.compromised_after }; }
async function fetchRegistry(base, opts) { const r = await fetch(base + '/.well-known/signing-key-registry.json', { cache: 'no-store', redirect: 'error' });
  if (!r.ok) throw new Error('HTTP ' + r.status); const text = await r.text(); lparse(text.trim()); return validateLifecycleRegistry(JSON.parse(text), opts); }

/**
 * The exact bytes that were signed: the response minus its `signature` field, json-sorted-compact.
 * Pass the RAW response text for guaranteed byte-fidelity (numbers are preserved verbatim).
 * @param {string|object} input
 * @returns {string}
 */
export function canonical(input) {
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  const root = lparse(text.trim());
  const stripped = root.t === 'o' ? { t: 'o', v: root.v.filter(p => p[0] !== 'signature') } : root;
  return canon(stripped);
}

/**
 * Verify a DF-VERIFY/1 signed response.
 * @param {string|object} input  Raw response text (preferred) or a parsed object.
 * Caller-supplied registries and custom network origins require
 * registrySourceAuthenticated=true before live policy can pass. Redirects fail closed.
 * @param {{base?:string, jwks?:Record<string,string>, lifecycleRegistry?:object, verificationMode?:'live'|'historical_snapshot', minimumRegistryRevision?:number, highestAuthenticatedRegistryRevision?:number, registrySourceAuthenticated?:boolean}} [opts]
 * @returns {Promise<{ok:boolean, cryptoValid?:boolean, signerAccepted?:boolean, lifecycleStatus?:string, error?:string, keyId?:string}>}
 */
export async function verify(input, opts = {}) {
  const base = (opts.base || DEFAULT_BASE).replace(/\/$/, '');
  const mode = opts.verificationMode || 'live';
  if (mode !== 'live' && mode !== 'historical_snapshot') return { ok: false, error: 'verificationMode must be live or historical_snapshot' };
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  let root;
  try { root = lparse(text.trim()); } catch (e) { return { ok: false, error: 'invalid JSON — ' + e.message }; }
  if (root.t !== 'o') return { ok: false, error: 'expected a JSON object' };
  const sig = field(root, 'signature');
  if (!sig) return { ok: false, error: 'no "signature" block in this response' };
  const keyId = (field(sig, 'key_id') || {}).v, sigB64 = (field(sig, 'sig') || {}).v;
  const alg = (field(sig, 'alg') || {}).v, canonName = (field(sig, 'canonicalization') || {}).v, ephN = field(sig, 'ephemeral_key');
  if (!keyId || !sigB64) return { ok: false, error: 'signature block missing key_id or sig' };
  if (alg !== 'Ed25519' || canonName !== 'json-sorted-compact') return {
    ok: false, cryptoValid: false, signerAccepted: false, lifecycleStatus: 'unknown',
    error: 'unsupported signature metadata', keyId,
  };
  let registry = null, registryError = null, registrySource = 'key-bytes-only', sourceAuthenticated = false;
  if (opts.lifecycleRegistry) {
    try { registry = await validateLifecycleRegistry(opts.lifecycleRegistry, opts);
      registrySource = 'out-of-band'; sourceAuthenticated = opts.registrySourceAuthenticated === true;
    } catch (e) { registryError = e; }
  } else if (!Object.prototype.hasOwnProperty.call(opts, 'jwks')) {
    try { if (mode === 'historical_snapshot') throw new Error('historical_snapshot requires an explicitly supplied pinned registry');
      registry = await fetchRegistry(base, opts);
      const isDefaultOrigin = base === DEFAULT_BASE;
      registrySource = isDefaultOrigin ? 'current-domain-https' : 'caller-configured-network-origin';
      sourceAuthenticated = opts.registrySourceAuthenticated === true || isDefaultOrigin;
    } catch (e) { registryError = e; }
  }
  const ks = registry ? registry.public_keys : (opts.jwks || {});
  if (!(keyId in ks)) return { ok: false, cryptoValid: false, signerAccepted: false,
    lifecycleStatus: 'unknown', error: registryError ? 'could not validate the signing-key lifecycle registry'
      : 'key_id ' + keyId + ' not in supplied key bytes', keyId };
  // Two anchor conventions coexist: some receipts sign the body BEFORE a timestamp anchor is
  // attached (an RFC 3161 / DLT anchor is OF the signed hash, so it can only land after signing —
  // e.g. /v1/answer, /v1/receipt), others sign WITH the anchor already inside the bytes (e.g. notary
  // inclusion proofs). Try the strip-signature form first; if it fails and an `anchor` is present,
  // retry with the anchor stripped too. Accepting either canonical form is not a weakening — a
  // forgery still needs a valid Ed25519 signature over one of the two forms.
  const drops = [['signature']];
  if (root.v.some(p => p[0] === 'anchor')) drops.push(['signature', 'anchor']);
  let sigBytes, pk;
  try { sigBytes = b64u(sigB64); pk = b64u(ks[keyId]); }
  catch (e) { return { ok: false, cryptoValid: false, signerAccepted: false,
    lifecycleStatus: 'unknown', error: 'invalid signature or public-key encoding — ' + e.message, keyId }; }
  if (sigBytes.length !== 64) return { ok: false, cryptoValid: false, signerAccepted: false,
    lifecycleStatus: 'unknown', error: 'signature must decode to 64 bytes', keyId };
  const keyBindingValid = pk.length === 32 && await keyIdFor(pk) === keyId;
  if (!keyBindingValid) return { ok: false, cryptoValid: false, keyBindingValid: false,
    signerAccepted: false, lifecycleStatus: 'unknown', error: 'public key does not derive key_id ' + keyId, keyId };
  let cryptoValid = false, lastErr = null, anchorAuthenticated = null;
  for (const drop of drops) {
    const msg = new TextEncoder().encode(canon({ t: 'o', v: root.v.filter(p => !drop.includes(p[0])) }));
    try { if (await ed.verifyAsync(sigBytes, msg, pk)) {
      cryptoValid = true; anchorAuthenticated = root.v.some(p => p[0] === 'anchor') ? !drop.includes('anchor') : null; break;
    } }
    catch (e) { lastErr = e; }
  }
  const policy = registry ? lifecyclePolicy(registry, keyId, mode) : {
    status: 'unknown', accepted: false, reason: 'flat key bytes carry no lifecycle policy',
  };
  const signerAccepted = !!policy.accepted && sourceAuthenticated, ok = cryptoValid && signerAccepted;
  if (!cryptoValid && lastErr) return { ok: false, cryptoValid: false, keyBindingValid,
    signerAccepted, lifecycleStatus: policy.status, lifecycle: policy,
    error: 'verify error — ' + lastErr.message, keyId };
  const vNode = field(root, 'verdict');
  // verdict is a {status:...} object on awareness verdicts but a plain string (the answer) on
  // /v1/answer receipts — surface whichever is present.
  const verdict = vNode ? (vNode.t === 's' ? vNode.v : (field(vNode, 'status') || {}).v) : null;
  const revision = registry ? revisionContext(registry, opts) : {
    mode, registryRevision: null, effectiveRegistryFloor: mode === 'live' ? COMPILED_MIN_REGISTRY_REVISION : 0,
    historicalSnapshot: mode === 'historical_snapshot',
  };
  const rollbackProtected = mode === 'live' && sourceAuthenticated
    && Number.isInteger(opts.highestAuthenticatedRegistryRevision) && !!registry
    && registry.registry_revision >= opts.highestAuthenticatedRegistryRevision;
  return { ok, cryptoValid, keyBindingValid, signerAccepted, lifecycleStatus: policy.status,
           policyAsOfAccepted: !!policy.policyAsOfAccepted,
           lifecycle: policy, trustBasis: registry ? (opts.lifecycleRegistry ? 'out-of-band'
             : (registrySource === 'current-domain-https' ? 'current-domain' : 'caller-configured-network-origin'))
             : 'key-bytes-only',
           registrySource, registrySourceAuthenticated: sourceAuthenticated, rollbackProtected, ...revision,
           error: ok ? undefined : (!cryptoValid ? 'signature INVALID'
             : (policy.accepted && !sourceAuthenticated
               ? 'lifecycle registry source was not explicitly authenticated' : policy.reason)),
           anchorAuthenticated, keyId, alg, canon: canonName, ephemeral: !!(ephN && ephN.v),
           verdict, snapshot: (field(root, 'snapshot_id') || {}).v };
}

/**
 * Fetch a fresh keyless signed awareness verdict and verify it.
 * @returns {Promise<{text:string, result:Awaited<ReturnType<typeof verify>>}>}
 */
export async function verifyLive(base = DEFAULT_BASE, body = { robot: { class: 'aerial' }, location: { lat: 51.5, lon: -0.12 } }) {
  const b = base.replace(/\/$/, '');
  const r = await fetch(b + '/v1/awareness', { method: 'POST', redirect: 'error',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) return { text: '', result: { ok: false, error: 'awareness HTTP ' + r.status } };
  const text = await r.text();
  const result = await verify(text, { base: b });
  return { text, result };
}
