// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import axe from 'axe-core';
import { renderReport, renderProgress, reportToSummaryText, exportReportJson, DISCLAIMER } from '../../src/ui/render.js';
import { startApp } from '../../src/ui/start.js';

const HOSTILE = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)'];

function baseReport(over = {}) {
  return {
    v: 1, engineVersion: '0.1.0', detectorVersions: {}, scannedAt: '2026-11-08T00:00:00.000Z', durationMs: 5,
    target: 'https://x.com/', finalUrl: 'https://x.com/',
    pagesScanned: [{ url: 'https://x.com/', status: 200, contentType: 'text/html', bytesRead: 10, truncated: false, redirectChain: [] }],
    findings: [], coverage: [], fetchStats: { attempted: 1, successful: 1, cached: 0, failed: 0 }, headers: {}, ...over,
  };
}

function finding(over = {}) {
  return {
    id: 'payload.link.executable:abc', fingerprint: 'f', detector: 'payload-links', ruleId: 'payload.link.executable', category: 'payload',
    severity: 'low', confidence: 'medium', title: 'Executable-looking link',
    observations: [{ evidence: { snippet: '<a href="/a.exe">', sourceUrl: 'https://x.com/', matchedValue: '/a.exe', normalizedValue: 'https://evil.example.net/a.exe', context: 'Download', location: { type: 'html_attribute', tag: 'a', attribute: 'href', line: 3, column: 5 } } }],
    observationCount: 1, ...over,
  };
}

function hostileReport() {
  const bad = `${HOSTILE.join(' | ')} \u202Egpj.exe \ud800`;
  const f = finding({ title: bad });
  f.observations[0].evidence = { ...f.observations[0].evidence, snippet: bad, matchedValue: bad, sourceUrl: bad, normalizedValue: bad, context: bad };
  return baseReport({ findings: [f], coverage: [{ check: bad, page: bad, state: 'unknown', reason: bad }] });
}

let root;
beforeEach(() => {
  document.documentElement.lang = 'en';
  document.title = 'FMHY Safety Auditor';
  document.body.innerHTML = '<main><h1>Test</h1><div id="root"></div></main>';
  root = document.getElementById('root');
});

describe('renderReport safety', () => {
  it('renders hostile strings as inert text with no active elements', () => {
    renderReport(hostileReport(), root);
    expect(root.querySelectorAll('script, img, iframe, a[href], [onerror], object, embed, link, style').length).toBe(0);
    for (const h of HOSTILE) expect(root.textContent).toContain(h.replace(/https?:\/\/\S+/, (m) => m));
    expect(root.textContent).toContain('\\u202e'); // override character is shown escaped, never applied
    expect(root.textContent).not.toMatch(/\u202e/);
    expect(root.textContent).not.toMatch(/[\ud800-\udfff]/); // lone surrogate replaced
    for (const n of root.querySelectorAll('*')) {
      for (const a of n.attributes) {
        expect(/^on/i.test(a.name), a.name).toBe(false);
        expect(['href', 'src', 'style', 'srcdoc'].includes(a.name), a.name).toBe(false);
      }
    }
  });

  it('defangs payload URLs and never wraps them in anchors', () => {
    renderReport(baseReport({ findings: [finding()] }), root);
    expect(root.textContent).toContain('hxxps://evil[.]example[.]net/a.exe');
    expect(root.textContent).not.toContain('https://evil.example.net');
    expect(root.querySelectorAll('a').length).toBe(0);
  });

  it('shows findings count and scan coverage as separate items', () => {
    renderReport(baseReport({ findings: [finding(), finding({ ruleId: 'x.y', id: 'x:y' })] }), root);
    const terms = [...root.querySelectorAll('dt')].map((d) => d.textContent);
    expect(terms).toContain('Findings');
    expect(terms).toContain('Scan coverage');
    const dd = (label) => [...root.querySelectorAll('dt')].find((d) => d.textContent === label).nextElementSibling.textContent;
    expect(dd('Findings')).toMatch(/^2 /);
    expect(dd('Scan coverage')).toMatch(/Complete/);
  });

  it('shows severity, confidence, category, rule, source page and element/attribute as text', () => {
    renderReport(baseReport({ findings: [finding()] }), root);
    const card = root.querySelector('details');
    const text = card.textContent;
    for (const s of ['Low', 'medium', 'payload', 'payload.link.executable', 'hxxps://x[.]com/', '<a> href line 3, column 5']) expect(text, s).toContain(s);
    expect(card.querySelector('summary').textContent).toContain('Low');
  });

  it('shows the exact disclaimer with zero findings and with findings', () => {
    renderReport(baseReport(), root);
    expect(root.textContent).toContain(DISCLAIMER);
    expect(root.textContent).toContain('No findings were detected in the scanned scope.');
    renderReport(baseReport({ findings: [finding()] }), root);
    expect(root.textContent).toContain(DISCLAIMER);
    expect(DISCLAIMER).toBe('No detected findings does not establish that a website is safe. This scanner performs static analysis only; it cannot observe all runtime behavior or determine whether a downloaded file is malicious. An incomplete scan is shown as incomplete, not clean.');
  });

  it('shows the coverage panel and the word "incomplete" for an incomplete scan, and not for a complete one', () => {
    renderReport(baseReport({ coverage: [{ check: 'binary-content', page: 'https://x.com/a.zip', state: 'skipped', reason: 'binary_not_inspected' }] }), root);
    const panel = root.querySelector('#coverage-heading').parentElement;
    expect(panel.textContent).toMatch(/incomplete/i);
    expect(panel.textContent).toContain('binary_not_inspected');
    expect(panel.textContent).toContain('hxxps://x[.]com/a.zip');
    renderReport(baseReport(), root);
    expect(root.querySelector('#coverage-heading')).toBeNull();
    const overview = root.querySelector('#overview-heading').parentElement.textContent;
    expect(overview).not.toMatch(/incomplete/i);
  });

  it('treats a failed root fetch as incomplete', () => {
    renderReport(baseReport({ finalUrl: null, pagesScanned: [] }), root);
    expect(root.textContent).toMatch(/could not be fetched/);
    expect(root.textContent).toMatch(/incomplete/i);
  });

  it('never presents "safe" as a verdict outside the disclaimer', () => {
    renderReport(baseReport({ findings: [finding()] }), root);
    const offenders = [...root.querySelectorAll('*')].filter((n) => n.id !== 'disclaimer' && [...n.childNodes].some((c) => c.nodeType === 3 && /\bsafe\b/i.test(c.textContent)));
    expect(offenders).toEqual([]);
  });

  it('has no accessibility violations (axe, color-contrast disabled for jsdom)', async () => {
    renderReport(hostileReport(), root);
    const results = await axe.run(document, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' ')}`)).toEqual([]);
    renderReport(baseReport({ coverage: [{ check: 'c', state: 'unknown', reason: 'r' }], findings: [finding()] }), root);
    const again = await axe.run(document, { rules: { 'color-contrast': { enabled: false } } });
    expect(again.violations).toEqual([]);
  });
});

describe('secrets never appear', () => {
  const S = 'SECRET123';
  const secretReport = () => {
    const u = `https://x.com/a.exe?token=${S}&k=1`;
    const f = finding();
    f.observations[0].evidence = { snippet: `<a href="${u}">`, sourceUrl: u, matchedValue: u, normalizedValue: u, context: `see ${u}`, location: { type: 'html_attribute', tag: 'a', attribute: 'href' } };
    return baseReport({ target: u, finalUrl: u, pagesScanned: [{ url: u, status: 200, contentType: 'text/html', bytesRead: 1, truncated: false, redirectChain: [{ url: u, status: 302, location: u }] }], findings: [f], coverage: [{ check: 'c', page: u, state: 'unknown' }] });
  };
  it('is absent from the DOM text, summary text and JSON export', () => {
    renderReport(secretReport(), root);
    expect(root.textContent).not.toContain(S);
    expect(root.textContent).toContain('token=REDACTED');
    expect(reportToSummaryText(secretReport())).not.toContain(S);
    expect(exportReportJson(secretReport())).not.toContain(S);
    expect(exportReportJson(secretReport())).toContain('k=1');
  });
});

describe('exports', () => {
  it('exportReportJson parses and includes v and coverage', () => {
    const parsed = JSON.parse(exportReportJson(baseReport({ coverage: [{ check: 'c', state: 'ok' }] })));
    expect(parsed.v).toBe(1);
    expect(parsed.coverage).toEqual([{ check: 'c', state: 'ok' }]);
  });
  it('reportToSummaryText states incompleteness and includes the disclaimer', () => {
    const text = reportToSummaryText(baseReport({ findings: [finding()], coverage: [{ check: 'c', state: 'skipped', reason: 'binary_not_inspected' }] }));
    expect(text).toContain('INCOMPLETE');
    expect(text).toContain('[Low] Executable-looking link');
    expect(text).toContain('binary_not_inspected');
    expect(text).toContain(DISCLAIMER);
    expect(text).not.toContain('https://evil.example.net');
  });
});

describe('renderProgress', () => {
  it('writes the phase into the live region as text', () => {
    document.body.innerHTML = '<div id="p" aria-live="polite"></div>';
    const p = document.getElementById('p');
    renderProgress({ phase: 'following' }, p);
    expect(p.textContent).toBe('Checking linked pages…');
    renderProgress({ phase: 'done' }, p);
    expect(p.textContent).toBe('Scan finished.');
  });
});

describe('startApp', () => {
  function page() {
    const html = readFileSync(resolve(process.cwd(), 'src/ui/index.html'), 'utf8');
    document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(html)[1].replace(/<script[\s\S]*?<\/script>/g, '');
  }
  const submit = (value) => {
    const input = document.getElementById('url-input');
    input.value = value;
    document.getElementById('scan-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  };
  const tick = () => new Promise((r) => setTimeout(r, 0));

  it('shows friendly errors for bad input and does not scan', async () => {
    page();
    const scan = vi.fn();
    startApp(document, { scan, analyzer: { analyze: vi.fn(), dispose: vi.fn() }, client: {} });
    submit('ftp://x.com/a');
    expect(document.getElementById('error').textContent).toBe('Only http and https addresses can be scanned.');
    submit('   ');
    expect(document.getElementById('error').textContent).toBe('Enter a web address to scan.');
    expect(scan).not.toHaveBeenCalled();
  });

  it('normalizes input, scans, renders the report and offers actions', async () => {
    page();
    const scan = vi.fn(async (url, deps) => { deps.onProgress({ phase: 'fetching' }); return baseReport({ target: url, findings: [finding()] }); });
    startApp(document, { scan, analyzer: { analyze: vi.fn(), dispose: vi.fn() }, client: {} });
    submit(' example.com/a ');
    await tick(); await tick();
    expect(scan.mock.calls[0][0]).toBe('https://example.com/a');
    expect(document.getElementById('results').textContent).toContain('Executable-looking link');
    expect([...document.querySelectorAll('#actions button')].map((b) => b.textContent)).toEqual(['Copy summary', 'Download JSON']);
    expect(document.getElementById('scan-button').disabled).toBe(false);
    expect(document.getElementById('error').textContent).toBe('');
  });

  it('shows a friendly error when the scan throws and re-enables the button', async () => {
    page();
    startApp(document, { scan: async () => { throw new Error('boom'); }, analyzer: { analyze: vi.fn(), dispose: vi.fn() }, client: {} });
    submit('example.com');
    await tick(); await tick();
    expect(document.getElementById('error').textContent).toMatch(/could not be completed/);
    expect(document.getElementById('scan-button').disabled).toBe(false);
  });

  it('the page itself has a labelled input, a live region and no accessibility violations', async () => {
    page();
    document.documentElement.lang = 'en';
    document.title = 'FMHY Safety Auditor';
    expect(document.querySelector('label[for="url-input"]')).not.toBeNull();
    expect(document.getElementById('progress').getAttribute('aria-live')).toBe('polite');
    const results = await axe.run(document, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });
});

describe('summary text layout', () => {
  it('keeps real line breaks and escapes control characters inside lines', () => {
    const text = reportToSummaryText(baseReport({ findings: [finding({ title: 'a\u202Eb' })] }));
    expect(text.split('\n').length).toBeGreaterThan(5);
    expect(text).toContain('a\\u202eb');
    expect(text).not.toMatch(/\u202e/);
  });
});
