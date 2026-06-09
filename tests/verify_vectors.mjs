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

const n = cv.vectors.length + 2;
console.log(`\n${fails ? '✗ ' + fails + ' FAILED' : '✓ ALL ' + n + ' VECTORS PASS'}`);
process.exit(fails ? 1 : 0);
