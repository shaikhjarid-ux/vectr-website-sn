import { describe, it, expect } from 'vitest';
import { payloadLinks, classifyPayloadUrl } from '../../src/detectors/payload-links.js';
import { makeCtx } from '../helpers/ctx.js';

const run = (html, opts) => payloadLinks.run(makeCtx(html, opts)).findings;

describe('classifyPayloadUrl', () => {
  it('classifies executables, archives and query filenames', () => {
    expect(classifyPayloadUrl('https://x.com/a/setup.EXE?x=1#f')).toEqual({ ruleId: 'payload.link.executable', severity: 'low', extension: 'exe' });
    for (const e of 'exe msi scr bat cmd ps1 jar vbs lnk pkg deb appimage apk dmg iso'.split(' ')) {
      expect(classifyPayloadUrl(`https://x.com/f.${e}`)?.ruleId, e).toBe('payload.link.executable');
    }
    for (const e of ['zip', 'rar', '7z']) expect(classifyPayloadUrl(`https://x.com/f.${e}`)).toEqual({ ruleId: 'payload.link.archive', severity: 'info', extension: e });
    expect(classifyPayloadUrl('https://x.com/dl?file=a.exe')).toEqual({ ruleId: 'payload.link.query-filename', severity: 'low', extension: 'exe' });
    expect(classifyPayloadUrl('https://x.com/dl?file=a%252eexe')?.ruleId).toBe('payload.link.query-filename');
  });
  it('never considers arbitrary query values or non-payload paths', () => {
    expect(classifyPayloadUrl('https://x.com/dl?q=a.exe')).toBeNull();
    expect(classifyPayloadUrl('https://x.com/index.html')).toBeNull();
    expect(classifyPayloadUrl('https://x.com/')).toBeNull();
  });
  it('prefers the pathname extension over a query filename', () => {
    expect(classifyPayloadUrl('https://x.com/a.zip?file=b.exe')?.ruleId).toBe('payload.link.archive');
  });
});

describe('payloadLinks detector', () => {
  it('has the expected id and version', () => {
    expect(payloadLinks.id).toBe('payload-links');
    expect(typeof payloadLinks.version).toBe('string');
  });
  it('flags an executable anchor with tag, attribute and resolved value', () => {
    const [f, ...rest] = run('<a href="/dl/setup.exe">Download</a>');
    expect(rest).toEqual([]);
    expect(f).toMatchObject({ detector: 'payload-links', ruleId: 'payload.link.executable', category: 'payload', proposedSeverity: 'low', confidence: 'medium', target: 'https://x.com/dl/setup.exe' });
    expect(f.evidence).toMatchObject({
      matchedValue: '/dl/setup.exe', normalizedValue: 'https://x.com/dl/setup.exe', sourceUrl: 'https://x.com/page/', context: 'Download',
      location: { type: 'html_attribute', tag: 'a', attribute: 'href', line: 1 },
    });
    expect(f.evidence.snippet).toContain('setup.exe');
    expect(f.evidence.snippet.length).toBeLessThanOrEqual(200);
  });
  it('flags query filenames with low confidence, including layered encoding', () => {
    for (const href of ['/dl?file=a.exe', '/dl?file=a%252eexe']) {
      const [f] = run(`<a href="${href}">x</a>`);
      expect(f, href).toMatchObject({ ruleId: 'payload.link.query-filename', proposedSeverity: 'low', confidence: 'low' });
    }
    expect(run('<a href="/dl?q=a.exe">x</a>')).toEqual([]);
  });
  it('matches the pathname even with a query string and fragment', () => {
    const [f] = run('<a href="/a.exe?x=1#frag">x</a>');
    expect(f.ruleId).toBe('payload.link.executable');
    expect(f.target).toBe('https://x.com/a.exe?x=1');
    expect(f.evidence.normalizedValue).toBe('https://x.com/a.exe?x=1#frag');
  });
  it('archives propose info', () => {
    expect(run('<a href="/f.zip">x</a>')[0]).toMatchObject({ ruleId: 'payload.link.archive', proposedSeverity: 'info', confidence: 'medium' });
  });
  it('finds srcset, link href, CSS url() and data-url references; ignores data-id', () => {
    const html = '<img srcset="a.jpg 1x, /f/a.zip 2x"><link href="x.exe" rel="stylesheet"><div style="background:url(a.iso)"></div><div data-url="https://x.com/a.exe"></div><div data-id="123"></div>';
    const found = run(html).map((f) => f.evidence.matchedValue).sort();
    expect(found).toEqual(['/f/a.zip', 'a.iso', 'https://x.com/a.exe', 'x.exe']);
  });
  it('ignores non-http schemes such as data: and javascript:', () => {
    expect(run('<a href="data:text/html,evil.exe">x</a><a href="javascript:go(\'a.exe\')">y</a><a href="mailto:a.exe@x.com">z</a>')).toEqual([]);
  });
  it('records separate raws for repeated links (merging happens later)', () => {
    expect(run('<a href="/a.exe">1</a><a href="/a.exe">2</a>')).toHaveLength(2);
  });
  it('flags refs inside iframe srcdoc', () => {
    const [f] = run('<iframe srcdoc="&lt;a href=&quot;/in.msi&quot;&gt;x&lt;/a&gt;"></iframe>');
    expect(f.ruleId).toBe('payload.link.executable');
  });
});
