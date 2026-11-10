// Browser end-to-end safety checks. /api/fetch is route-intercepted with canned
// responses, so no real site is contacted; the rest (static assets, the real
// _headers CSP, the real Web Worker) is served by `wrangler dev`.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { encodeMeta } from '../../src/worker/headers.js';

const fixture = (dir, name) => readFileSync(new URL(`../fixtures/${dir}/${name}`, import.meta.url));

function fulfillPage(route, url, bytes) {
  return route.fulfill({
    status: 200,
    headers: {
      'content-type': 'application/octet-stream',
      'x-audit-meta': encodeMeta({ finalUrl: url, chain: [{ url, status: 200 }], status: 200, contentType: 'text/html; charset=utf-8', bytesRead: bytes.length, truncated: false, cache: 'miss', fetchedAt: new Date().toISOString(), headers: {} }),
    },
    body: bytes,
  });
}

async function instrument(page, pages) {
  const seen = { csp: [], errors: [], dialogs: [], requests: [] };
  page.on('dialog', (d) => { seen.dialogs.push(d.message()); d.dismiss(); });
  page.on('console', (m) => { if (m.type() === 'error') seen.errors.push(m.text()); });
  page.on('pageerror', (e) => seen.errors.push(String(e)));
  page.on('request', (r) => seen.requests.push(r.url()));
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => { (window.__csp ||= []).push(`${e.violatedDirective} ${e.blockedURI}`); });
  });
  await page.route('**/api/fetch', async (route) => {
    const { url } = JSON.parse(route.request().postData() ?? '{}');
    const bytes = pages[url];
    if (!bytes) return route.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({ error: 'upstream_error', detail: 'not in fixtures' }) });
    return fulfillPage(route, url, bytes);
  });
  return seen;
}

async function scanAndWait(page, address) {
  await page.goto('/');
  await page.getByLabel('Web address to scan').fill(address);
  await page.getByRole('button', { name: 'Scan' }).click();
  await expect(page.locator('#results')).toContainText('Scan overview', { timeout: 30_000 });
}

async function assertClean(page, seen, origin) {
  seen.csp.push(...(await page.evaluate(() => window.__csp ?? [])));
  expect(seen.csp, 'CSP violations').toEqual([]);
  expect(seen.errors, 'console errors').toEqual([]);
  expect(seen.dialogs, 'dialogs').toEqual([]);
  for (const u of seen.requests) {
    expect(new URL(u).origin === origin || u.startsWith('data:') || u.startsWith('blob:'), `cross-origin request: ${u}`).toBe(true);
  }
}

test('an obfuscated inline script is found by the real Web Worker, with no CSP violations', async ({ page, baseURL }) => {
  const url = 'https://scan-target.example.net/';
  const seen = await instrument(page, { [url]: fixture('recall', 'obfuscation.html') });
  await scanAndWait(page, url);
  await expect(page.locator('#results')).toContainText('hidden by obfuscation');
  await expect(page.locator('#results')).toContainText('obfuscation.decoded-payload-url');
  await expect(page.locator('#results')).toContainText('hxxps://dl[.]example[.]net/a.exe');
  await assertClean(page, seen, new URL(baseURL).origin);
  // The scanned host is only ever data; the browser never contacted it.
  expect(seen.requests.some((u) => u.includes('scan-target.example.net') || u.includes('dl.example.net'))).toBe(false);
});

test('hostile markup in filenames renders as inert text', async ({ page, baseURL }) => {
  const url = 'https://hostile.example.net/';
  const seen = await instrument(page, { [url]: fixture('hostile', 'page.html') });
  await scanAndWait(page, url);
  await expect(page.locator('#results')).toContainText('Executable-looking link');
  expect(await page.locator('#results').locator('script, img, svg, iframe, a[href], [onerror], [onload]').count()).toBe(0);
  await assertClean(page, seen, new URL(baseURL).origin);
});

test('the static page is served with the CSP and a Worker script that loads', async ({ page, request }) => {
  const res = await request.get('/');
  expect(res.headers()['content-security-policy']).toContain("default-src 'self'");
  expect(res.headers()['x-frame-options']).toBe('DENY');
  expect((await request.get('/js-worker.js')).ok()).toBe(true);
  await page.goto('/');
  await expect(page.getByLabel('Web address to scan')).toBeVisible();
});
