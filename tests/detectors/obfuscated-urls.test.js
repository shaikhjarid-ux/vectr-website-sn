import { describe, it, expect } from 'vitest';
import { obfuscatedUrls } from '../../src/detectors/obfuscated-urls.js';
import { analyzeScript } from '../../src/analysis/fold.js';
import { makeCtx } from '../helpers/ctx.js';

const script = (src, extra = {}) => ({ ...analyzeScript(src), source: 'inline', ...extra });
const run = (html, scripts = []) => obfuscatedUrls.run(makeCtx(html, { scripts }));

describe('obfuscatedUrls over folded script URLs', () => {
  it('has id and version', () => {
    expect(obfuscatedUrls.id).toBe('obfuscated-urls');
    expect(typeof obfuscatedUrls.version).toBe('string');
  });
  it('flags a payload url built from concatenated literals', () => {
    const { findings } = run('<p>x</p>', [script("location='ht'+'tp://x.com/a.exe'")]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ detector: 'obfuscated-urls', ruleId: 'obfuscation.decoded-payload-url', category: 'obfuscation', proposedSeverity: 'medium', confidence: 'medium', target: 'http://x.com/a.exe' });
    expect(findings[0].evidence).toMatchObject({ location: { type: 'script_range' }, normalizedValue: 'http://x.com/a.exe', sourceUrl: 'https://x.com/page/' });
    expect(findings[0].evidence.snippet).toContain('concat');
  });
  it('flags unescape-decoded urls (info when not a payload)', () => {
    const enc = [...'https://x.com/landing'].map((c) => `%${c.charCodeAt(0).toString(16)}`).join('');
    const { findings } = run('', [script(`var u = unescape('${enc}');`)]);
    expect(findings).toEqual([expect.objectContaining({ ruleId: 'obfuscation.decoded-url', proposedSeverity: 'info', target: 'https://x.com/landing' })]);
  });
  it('flags atob-decoded payload urls and attributes the external script url', () => {
    const { findings } = run('', [script("location.href = atob('aHR0cHM6Ly94LmNvbS9hLmV4ZQ==');", { source: 'external', url: 'https://x.com/s.js' })]);
    expect(findings[0]).toMatchObject({ ruleId: 'obfuscation.decoded-payload-url' });
    expect(findings[0].evidence.sourceUrl).toBe('https://x.com/s.js');
  });
  it('reports nothing for benign concatenation, plain literal urls and non-url strings', () => {
    expect(run('', [script("var s = 'a' + 'b'; var u = 'https://cdn.x.com/' + 'lib.js'; var v = 'https://x.com/ok';")]).findings).toEqual([]);
  });
  it('extracts urls embedded in a decoded document.write string', () => {
    const html = '<a href="https://x.com/a.exe">';
    const { findings } = run('', [script(`document.write(atob('${btoa(html)}'));`)]);
    expect(findings.map((f) => f.target)).toEqual(['https://x.com/a.exe']);
  });
});

describe('attribute fallback', () => {
  it('finds a base64 blob in a data attribute that decodes to a payload url', () => {
    const { findings } = run('<div data-u="aHR0cHM6Ly94LmNvbS9hLmV4ZQ=="></div>');
    expect(findings).toEqual([expect.objectContaining({ ruleId: 'obfuscation.decoded-payload-url', target: 'https://x.com/a.exe' })]);
    expect(findings[0].evidence.location).toMatchObject({ type: 'html_attribute', tag: 'div', attribute: 'data-u', line: 1 });
    expect(findings[0].evidence.normalizedValue).toBe('https://x.com/a.exe');
  });
  it('finds a blob inside an inline event handler', () => {
    const { findings } = run(`<a onclick="location=atob('aHR0cHM6Ly94LmNvbS9hLmV4ZQ==')">x</a>`);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence.location.attribute).toBe('onclick');
  });
  it('handles base64url and ignores blobs shorter than 24 characters', () => {
    const url = 'https://x.com/a.exe?x=~~~';
    const b64url = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(run(`<div data-u="${b64url}"></div>`).findings).toHaveLength(1);
    expect(run('<div data-u="aHR0cDovL2EuYg=="></div>').findings).toEqual([]);
  });
  it('ignores a base64 image header and ordinary long values', () => {
    const png = btoa(String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(40).fill(0)));
    expect(run(`<img src="data:image/png;base64,${png}"><div title="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"></div>`).findings).toEqual([]);
  });
});

describe('coverage', () => {
  it('records scripts that were not fully analyzed, with their reason', () => {
    const partial = { status: 'partial', reason: 'script_parse_limit_reached', navigations: [], urls: [], source: 'external', url: 'https://x.com/big.js' };
    const unknown = { status: 'unknown', reason: 'script_parse_failed', navigations: [], urls: [], source: 'inline' };
    const { coverage } = run('', [partial, unknown, script('var ok = 1;')]);
    expect(coverage).toEqual([
      { check: 'obfuscated-urls', page: 'https://x.com/big.js', state: 'unknown', reason: 'script_parse_limit_reached' },
      { check: 'obfuscated-urls', page: 'https://x.com/page/', state: 'unknown', reason: 'script_parse_failed' },
    ]);
  });
  it('returns no coverage entries when every script was analyzed', () => {
    expect(run('', [script('var ok = 1;')]).coverage).toEqual([]);
  });
});
