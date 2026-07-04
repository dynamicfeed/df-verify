// DF-VERIFY/1 conformance harness (JavaScript) — mirror of tests/verify_vectors.py.
//
//   node tests/verify_vectors.mjs
//
// Uses the @dynamicfeed/verify reference verifier (clients/js) against the shared, language-agnostic
// vectors in tests/vectors/. Proves a JS verifier reproduces the canonical bytes and the signature
// verdicts exactly. (Requires clients/js deps: `npm install --prefix clients/js`.)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify, canonical } from '../clients/js/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const VEC = path.join(here, 'vectors');
let fails = 0;

const cv = JSON.parse(fs.readFileSync(path.join(VEC, 'canonicalization.json'), 'utf8'));
for (const v of cv.vectors) {
  const got = canonical(JSON.stringify(v.payload));
  const ok = got === v.canonical;
  fails += !ok;
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] canon · ${v.name}`);
  if (!ok) console.log(`         expected ${JSON.stringify(v.canonical)}\n         got      ${JSON.stringify(got)}`);
}

const sv = JSON.parse(fs.readFileSync(path.join(VEC, 'signed-awareness.json'), 'utf8'));
const a = await verify(sv.authentic.envelope_text, { jwks: sv.public_keys });  // RAW text — byte-fidelity
const t = await verify(sv.tampered.envelope_text, { jwks: sv.public_keys });
fails += (!a.ok) + (t.ok === true);
console.log(`  [${a.ok ? 'PASS' : 'FAIL'}] signature · authentic envelope verifies`);
console.log(`  [${!t.ok ? 'PASS' : 'FAIL'}] signature · tampered envelope rejected`);

const av = JSON.parse(fs.readFileSync(path.join(VEC, 'signed-answer-anchored.json'), 'utf8'));
const aa = await verify(av.authentic.envelope_text, { jwks: av.public_keys });
const am = await verify(av.anchor_modified.envelope_text, { jwks: av.public_keys });
const at = await verify(av.tampered.envelope_text, { jwks: av.public_keys });
fails += (!aa.ok) + (!am.ok) + (at.ok === true);
console.log(`  [${aa.ok ? 'PASS' : 'FAIL'}] anchored answer · authentic verifies (anchor stripped)`);
console.log(`  [${am.ok ? 'PASS' : 'FAIL'}] anchored answer · anchor-modified STILL verifies (anchor is unsigned)`);
console.log(`  [${!at.ok ? 'PASS' : 'FAIL'}] anchored answer · tampered signed field rejected`);

const n = cv.vectors.length + 5;
console.log(`\n${fails ? '✗ ' + fails + ' FAILED' : '✓ ALL ' + n + ' VECTORS PASS'}`);
process.exit(fails ? 1 : 0);
