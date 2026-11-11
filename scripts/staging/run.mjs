// Runs the staging checks against a deployed Worker and writes docs/staging-report.md.
//   STAGING_URL               base URL of the deployed Vectr Website SN Worker (required for real results)
//   FIXTURES_URL              base URL of the deployed fixtures Worker (scripts/staging/fixtures-worker.js)
//   STAGING_PRIVATE_DNS_HOST  optional hostname you control that resolves to 10.0.0.1
// Without STAGING_URL every check is written as "not verified".
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderStagingReport } from './report.mjs';
import { decodeMeta } from '../../src/worker/headers.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const STAGING = process.env.STAGING_URL?.replace(/\/$/, '');
const FIXTURES = process.env.FIXTURES_URL?.replace(/\/$/, '');
const PRIVATE_DNS = process.env.STAGING_PRIVATE_DNS_HOST;

async function call(url, kind = 'page', ip = '198.51.100.250') {
  const started = Date.now();
  const res = await fetch(`${STAGING}/api/fetch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: STAGING, 'cf-connecting-ip': ip },
    body: JSON.stringify({ url, kind }),
  });
  const ms = Date.now() - started;
  const metaHeader = res.headers.get('x-audit-meta');
  const meta = metaHeader ? decodeMeta(metaHeader) : null;
  const body = res.ok ? null : await res.json().catch(() => null);
  if (res.ok) await res.arrayBuffer();
  return { status: res.status, error: body?.error, meta, ms, setCookie: res.headers.get('set-cookie') };
}

const expectError = (r, status, error) => (r.status === status && r.error === error ? 'pass' : 'fail');
const show = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''} in ${r.ms} ms`;

async function main() {
  const results = [];
  const add = (id, status, observed) => results.push({ id, status, observed });

  if (!STAGING || !FIXTURES) {
    const why = !STAGING ? 'STAGING_URL not set' : 'FIXTURES_URL not set';
    console.log(`${why}: writing a report with every check marked "not verified".`);
  } else {
    const f = (p) => `${FIXTURES}${p}`;
    let r = await call(f('/redirect-private'));
    add('redirect-private', expectError(r, 403, 'blocked_target'), show(r));
    r = await call(f('/redirect-metadata'));
    add('redirect-metadata', expectError(r, 403, 'blocked_target'), show(r));
    r = await call(f('/loop-a'));
    add('loop', expectError(r, 502, 'too_many_redirects'), show(r));
    r = await call(f('/chain/6'));
    add('chain-6', expectError(r, 502, 'too_many_redirects'), show(r));
    r = await call(f('/slow-drip'));
    add('slow-drip', expectError(r, 504, 'timeout'), show(r));
    r = await call(f('/big-lying'));
    add('big-lying', r.status === 200 && r.meta?.truncated === true && r.meta?.bytesRead === 1048576 ? 'pass' : 'fail', `${show(r)}; truncated ${r.meta?.truncated}, bytesRead ${r.meta?.bytesRead}`);
    const first = await call(f('/set-cookie'));
    const second = await call(f('/set-cookie'));
    const leaked = JSON.stringify(first.meta ?? {}).includes('STAGING-SECRET') || Boolean(first.setCookie);
    add('set-cookie', !leaked && second.meta?.cache === 'miss' ? 'pass' : 'fail', `first ${show(first)}; second cache ${second.meta?.cache}; cookie leaked ${leaked}`);

    if (PRIVATE_DNS) {
      r = await call(`https://${PRIVATE_DNS}/`);
      add('private-dns', expectError(r, 403, 'blocked_target'), show(r));
    } else add('private-dns', 'not verified', 'STAGING_PRIVATE_DNS_HOST not set');

    const burst = [];
    for (let i = 0; i < 40; i++) burst.push(call(f('/final'), 'page', '198.51.100.251'));
    const codes = (await Promise.all(burst)).map((x) => x.status);
    const limited = codes.filter((c) => c === 429).length;
    const unavailable = codes.filter((c) => c === 503).length;
    add('rate-limit', limited > 0 && unavailable === 0 ? 'pass' : 'not verified', `40 requests from one key: ${limited} x 429, ${unavailable} x 503${limited === 0 ? ' (no limiting observed; cannot conclude the binding works)' : ''}`);

    const repeats = [];
    for (let i = 0; i < 5; i++) repeats.push((await call(f('/final'), 'page', `198.51.100.${10 + i}`)).meta?.cache);
    add('cache-locality', 'info', `5 repeated requests: ${repeats.join(', ')}`);
    add('subrequests', 'not verified', 'the Worker logs the count; read it with wrangler tail (not observable over HTTP)');
    r = await call(f('/final'));
    add('cpu', 'not verified', `wall time for a small page ${r.ms} ms; CPU time at 1 MiB must be read from the Cloudflare dashboard`);
  }

  const date = new Date().toISOString().slice(0, 10);
  writeFileSync(join(root, 'docs', 'staging-report.md'), renderStagingReport(results, { stagingUrl: STAGING, date }));
  console.log('wrote docs/staging-report.md');
}

main().catch((err) => { console.error(err); process.exit(1); });
