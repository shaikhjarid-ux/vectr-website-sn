import { describe, it, expect } from 'vitest';
import { parseContentDisposition, headerHints } from '../../src/detectors/header-hints.js';
import { makeCtx } from '../helpers/ctx.js';

const run = (headers) => headerHints.run(makeCtx('', { headers }));

describe('parseContentDisposition', () => {
  it('prefers filename* over filename and decodes UTF-8', () => {
    expect(parseContentDisposition("attachment; filename=\"a.exe\"; filename*=UTF-8''%e2%82%ac.exe")).toEqual({ type: 'attachment', filename: '€.exe' });
  });
  it('falls back to filename when filename* is malformed', () => {
    expect(parseContentDisposition("attachment; filename=\"a.exe\"; filename*=UTF-8''%zz.exe").filename).toBe('a.exe');
    expect(parseContentDisposition("attachment; filename=\"a.exe\"; filename*=UTF-8''%ff%fe.exe").filename).toBe('a.exe');
    expect(parseContentDisposition("attachment; filename*=UTF-8''%zz.exe").filename).toBeNull();
  });
  it('handles quoted strings with escapes and semicolons, unquoted tokens, case and spacing', () => {
    expect(parseContentDisposition('attachment; filename="a;b\\"c.exe"').filename).toBe('a;b"c.exe');
    expect(parseContentDisposition('Attachment;FileName=setup.exe').filename).toBe('setup.exe');
    expect(parseContentDisposition('  inline ').type).toBe('inline');
  });
  it('supports ISO-8859-1 in filename*', () => {
    expect(parseContentDisposition("attachment; filename*=ISO-8859-1'en'%e9.exe").filename).toBe('é.exe');
  });
  it('returns nulls for empty or hostile values without throwing', () => {
    expect(parseContentDisposition('')).toEqual({ type: '', filename: null });
    expect(() => parseContentDisposition(';;;=\'"\\')).not.toThrow();
    expect(parseContentDisposition('attachment')).toEqual({ type: 'attachment', filename: null });
  });
});

describe('headerHints', () => {
  it('has id and version', () => {
    expect(headerHints.id).toBe('header-hints');
    expect(typeof headerHints.version).toBe('string');
  });
  it('reports an attachment as info, and low when the filename has a payload extension', () => {
    expect(run({ 'content-disposition': 'attachment' }).findings).toEqual([expect.objectContaining({ ruleId: 'header.content-disposition-attachment', proposedSeverity: 'info', category: 'distribution', detector: 'header-hints', target: 'https://x.com/page/' })]);
    const [f] = run({ 'content-disposition': 'attachment; filename="setup.exe"' }).findings;
    expect(f).toMatchObject({ ruleId: 'header.content-disposition-attachment', proposedSeverity: 'low' });
    expect(f.evidence).toMatchObject({ location: { type: 'response_header' }, matchedValue: 'setup.exe', sourceUrl: 'https://x.com/page/' });
    expect(f.evidence.snippet).toContain('attachment');
  });
  it('reports nothing for inline dispositions and ordinary content types', () => {
    expect(run({ 'content-disposition': 'inline; filename="a.exe"', 'content-type': 'text/html' }).findings).toEqual([]);
    expect(run({}).findings).toEqual([]);
  });
  it('reports each executable content type, ignoring parameters and case', () => {
    for (const ct of ['application/x-msdownload', 'application/vnd.microsoft.portable-executable', 'application/x-dosexec', 'application/x-msdos-program', 'application/java-archive', 'Application/X-MSDownload; charset=binary']) {
      expect(run({ 'content-type': ct }).findings.map((f) => f.ruleId), ct).toEqual(['header.executable-content-type']);
    }
    expect(run({ 'content-type': 'application/x-msdownload' }).findings[0].proposedSeverity).toBe('low');
  });
  it('reads header names case-insensitively and reports both rules together', () => {
    const rules = run({ 'Content-Type': 'application/x-dosexec', 'Content-Disposition': 'attachment; filename=a.exe' }).findings.map((f) => f.ruleId).sort();
    expect(rules).toEqual(['header.content-disposition-attachment', 'header.executable-content-type']);
  });
  it('escapes control characters in evidence', () => {
    const [f] = run({ 'content-disposition': 'attachment; filename="a\u202Eexe.txt"' }).findings;
    expect(JSON.stringify(f.evidence)).not.toMatch(/\u202e/);
  });
});
