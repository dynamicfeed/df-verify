// @dynamicfeed/verify — independently verify Dynamic Feed (DF-VERIFY/1) Ed25519-signed responses.
//
// Runtime-agnostic ESM (Node >=18, Deno, Bun, browsers/bundlers). Reproduces the server's
// canonicalization BYTE-FOR-BYTE — json-sorted-compact, Python `ensure_ascii` escaping, the
// `signature` field stripped, numbers preserved verbatim via a lossless parse — then verifies the
// detached Ed25519 signature against the published key set using @noble/ed25519. Proven byte-identical
// to the Python reference verifier (clients/python) over the shared conformance vectors (tests/vectors).
//
// Spec: https://dynamicfeed.ai/standard
import * as ed from '@noble/ed25519';

export const DEFAULT_BASE = 'https://dynamicfeed.ai';

function b64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

// lossless JSON parse — numbers kept VERBATIM so re-canonicalization matches Python's repr exactly
function lparse(s) {
  let i = 0;
  function ws() { while (i < s.length) { const c = s[i]; if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++; else break; } }
  function val() { ws(); const c = s[i];
    if (c === '{') return obj(); if (c === '[') return arr(); if (c === '"') return { t: 's', v: str() };
    if (c === 't') { i += 4; return { t: 'b', v: true }; } if (c === 'f') { i += 5; return { t: 'b', v: false }; }
    if (c === 'n') { i += 4; return { t: 'z' }; } return num(); }
  function obj() { i++; const p = []; ws(); if (s[i] === '}') { i++; return { t: 'o', v: p }; }
    for (;;) { ws(); const k = str(); ws(); i++; const v = val(); p.push([k, v]); ws();
      if (s[i] === ',') { i++; continue; } if (s[i] === '}') { i++; break; } throw new Error('object @' + i); } return { t: 'o', v: p }; }
  function arr() { i++; const a = []; ws(); if (s[i] === ']') { i++; return { t: 'a', v: a }; }
    for (;;) { a.push(val()); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === ']') { i++; break; } throw new Error('array @' + i); } return { t: 'a', v: a }; }
  function str() { let r = ''; i++; while (s[i] !== '"') { if (s[i] === '\\') { const e = s[i + 1];
        if (e === 'u') { r += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16)); i += 6; }
        else { r += ({ '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' })[e]; i += 2; } }
      else { r += s[i]; i++; } } i++; return r; }
  function num() { const a = i; while (i < s.length && '-+0123456789.eE'.indexOf(s[i]) >= 0) i++; return { t: 'n', v: s.slice(a, i) }; }
  return val();
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

function canon(n) { if (n.t === 'o') { const keys = n.v.map(p => p[0]).sort(); const m = {}; n.v.forEach(p => m[p[0]] = p[1]);
    return '{' + keys.map(k => pys(k) + ':' + canon(m[k])).join(',') + '}'; }
  if (n.t === 'a') return '[' + n.v.map(canon).join(',') + ']';
  if (n.t === 's') return pys(n.v); if (n.t === 'n') return n.v;
  if (n.t === 'b') return n.v ? 'true' : 'false'; return 'null'; }

function field(node, key) { if (!node || node.t !== 'o') return null; for (const [k, v] of node.v) if (k === key) return v; return null; }

async function fetchJwks(base) { const r = await fetch(base + '/.well-known/keys'); if (!r.ok) throw new Error('HTTP ' + r.status); return await r.json(); }

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
 * @param {{base?:string, jwks?:Record<string,string>}} [opts]  base URL for key fetch; or supply jwks to verify offline.
 * @returns {Promise<{ok:boolean, error?:string, keyId?:string, alg?:string, canon?:string, ephemeral?:boolean, verdict?:string|null, snapshot?:string}>}
 */
export async function verify(input, opts = {}) {
  const base = (opts.base || DEFAULT_BASE).replace(/\/$/, '');
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  let root;
  try { root = lparse(text.trim()); } catch (e) { return { ok: false, error: 'invalid JSON — ' + e.message }; }
  if (root.t !== 'o') return { ok: false, error: 'expected a JSON object' };
  const sig = field(root, 'signature');
  if (!sig) return { ok: false, error: 'no "signature" block in this response' };
  const keyId = (field(sig, 'key_id') || {}).v, sigB64 = (field(sig, 'sig') || {}).v;
  const alg = (field(sig, 'alg') || {}).v, canonName = (field(sig, 'canonicalization') || {}).v, ephN = field(sig, 'ephemeral_key');
  if (!keyId || !sigB64) return { ok: false, error: 'signature block missing key_id or sig' };
  let ks = opts.jwks;
  if (!ks) { try { ks = await fetchJwks(base); } catch (e) { return { ok: false, error: 'could not fetch the public key set' }; } }
  if (!(keyId in ks)) return { ok: false, error: 'key_id ' + keyId + ' not in published JWKS (rotated?)', keyId };
  const stripped = { t: 'o', v: root.v.filter(p => p[0] !== 'signature') };
  const msg = new TextEncoder().encode(canon(stripped));
  let ok = false;
  try { ok = await ed.verifyAsync(b64u(sigB64), msg, b64u(ks[keyId])); }
  catch (e) { return { ok: false, error: 'verify error — ' + e.message, keyId }; }
  const vNode = field(root, 'verdict');
  return { ok, keyId, alg, canon: canonName, ephemeral: !!(ephN && ephN.v),
           verdict: vNode ? (field(vNode, 'status') || {}).v : null, snapshot: (field(root, 'snapshot_id') || {}).v };
}

/**
 * Fetch a fresh keyless signed awareness verdict and verify it.
 * @returns {Promise<{text:string, result:Awaited<ReturnType<typeof verify>>}>}
 */
export async function verifyLive(base = DEFAULT_BASE, body = { robot: { class: 'aerial' }, location: { lat: 51.5, lon: -0.12 } }) {
  const b = base.replace(/\/$/, '');
  const r = await fetch(b + '/v1/awareness', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const text = await r.text();
  const result = await verify(text, { base: b });
  return { text, result };
}
