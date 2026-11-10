// Shared helpers for the quality gates: scan a fixture through the real engine with a fake client.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scan } from '../../src/engine/scan.js';
import { analyzer, htmlDoc, fakeClient } from './fakeScan.js';

export const readJson = (p) => JSON.parse(readFileSync(resolve(process.cwd(), p), 'utf8'));
export const readFixture = (dir, file) => readFileSync(resolve(process.cwd(), 'tests/fixtures', dir, file), 'utf8');

/** Scan an HTML string as if it were fetched from `url` (followed URLs are unrouted, so they fail as coverage). */
export function scanHtml(html, { url = 'https://x.com/', finalUrl = url, headers, chain } = {}) {
  const extra = {};
  if (headers) extra.headers = headers;
  if (chain) extra.chain = chain;
  const client = fakeClient({ [url]: htmlDoc(finalUrl, html, extra) });
  return scan(url, { client, analyzer });
}
