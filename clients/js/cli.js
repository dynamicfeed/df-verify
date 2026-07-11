#!/usr/bin/env node
// CLI: `dynamicfeed-verify` — fetch a live signed verdict and verify it, or verify a saved response.
import { verifyLive, verify, DEFAULT_BASE } from './index.js';

function report(res) {
  if (res.ok) {
    let extra = '';
    if (res.verdict) extra += ` · verdict=${res.verdict}`;
    if (res.snapshot) extra += ` · snapshot=${res.snapshot}`;
    if (res.ephemeral) extra += ' · EPHEMERAL key';
    console.log(`✅ POLICY ACCEPTED — signature valid · lifecycle=${res.lifecycleStatus} · key=${res.keyId}${extra}`);
    process.exit(0);
  }
  if (res.cryptoValid) {
    console.log(`△ CRYPTOGRAPHICALLY VALID, LIFECYCLE REJECTED — key=${res.keyId} · ` +
      `status=${res.lifecycleStatus || 'unknown'} · ${res.error || 'not accepted'}`);
    process.exit(1);
  }
  console.log(`✗ INVALID — ${res.error}`);
  process.exit(1);
}

const a = process.argv.slice(2);
if (a[0] === '-h' || a[0] === '--help') {
  console.log('usage:\n' +
    '  dynamicfeed-verify [BASE_URL]          fetch a live signed verdict and verify it\n' +
    '  dynamicfeed-verify - [BASE_URL] < response.json   verify saved bytes using current-domain lifecycle policy\n' +
    `  default BASE_URL = ${DEFAULT_BASE}   ·   spec: ${DEFAULT_BASE}/standard`);
  process.exit(0);
}
if (a[0] === '-') {
  let s = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) s += chunk;
  report(await verify(s, { base: a[1] || DEFAULT_BASE }));
} else {
  const base = a[0] || DEFAULT_BASE;
  console.log(`requesting a live signed verdict from ${base}/v1/awareness ...`);
  const { result } = await verifyLive(base);
  report(result);
}
