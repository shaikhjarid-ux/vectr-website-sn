import { describe, it, expect } from 'vitest';
import { disguisedFilenames } from '../../src/detectors/disguised-filenames.js';
import { makeCtx } from '../helpers/ctx.js';

const run = (html) => disguisedFilenames.run(makeCtx(html)).findings;
const rules = (html) => run(html).map((f) => f.ruleId);
const link = (href) => `<a href="${href}">x</a>`;

describe('disguisedFilenames', () => {
  it('has id, version and category filename', () => {
    expect(disguisedFilenames.id).toBe('disguised-filenames');
    expect(run(link('/invoice.pdf.exe'))[0].category).toBe('filename');
  });
  it('flags a document or media extension followed by an executable one', () => {
    expect(rules(link('/invoice.pdf.exe'))).toEqual(['filename.double-extension']);
    expect(rules(link('/readme.txt.scr'))).toEqual(['filename.double-extension']);
    expect(rules(link('/photo.JPG.bat'))).toEqual(['filename.double-extension']);
    expect(run(link('/invoice.pdf.exe'))[0]).toMatchObject({ proposedSeverity: 'medium', detector: 'disguised-filenames', target: 'https://x.com/invoice.pdf.exe' });
  });
  it('sees double extensions padded with spaces', () => {
    expect(rules(link('/invoice.pdf%20%20%20%20.exe'))).toEqual(['filename.double-extension']);
  });
  it('flags right-to-left override and other control characters (escaped in evidence)', () => {
    const [f] = run(link('/photo%E2%80%AEgpj.exe'));
    expect(f.ruleId).toBe('filename.control-chars');
    expect(f.proposedSeverity).toBe('medium');
    expect(JSON.stringify(f.evidence)).not.toMatch(/[\u202a-\u202e\u2066-\u2069]/);
    expect(f.evidence.context).toContain('\\u202e');
    expect(rules(link('/a%E2%81%A6b.exe'))).toEqual(['filename.control-chars']);
  });
  it('flags executable-then-archive and archive-then-executable names', () => {
    expect(rules(link('/Setup.exe.zip'))).toEqual(['filename.archive-executable']);
    expect(rules(link('/Setup.zip.exe'))).toEqual(['filename.archive-executable']);
    expect(run(link('/Setup.exe.zip'))[0].proposedSeverity).toBe('medium');
  });
  it('flags mixed Latin and Cyrillic or Greek letters at low severity', () => {
    const [f] = run(link('/%D1%80ayload.exe')); // Cyrillic р + Latin "ayload"
    expect(f).toMatchObject({ ruleId: 'filename.homoglyph', proposedSeverity: 'low' });
    expect(rules(link('/%CE%B1pple.exe'))).toEqual(['filename.homoglyph']); // Greek α
  });
  it('ignores normal names', () => {
    for (const n of ['my.file.v2.zip', 'report.pdf', 'setup.exe', 'archive.tar.gz', 'photo.jpg', '%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf']) expect(run(link(`/${n}`)), n).toEqual([]);
  });
  it('inspects query filename parameters and download attributes', () => {
    expect(rules(link('/dl?file=invoice.pdf.exe'))).toEqual(['filename.double-extension']);
    expect(rules(link('/dl?q=invoice.pdf.exe'))).toEqual([]);
    const [f] = run('<a href="/dl" download="invoice.pdf.exe">x</a>');
    expect(f.ruleId).toBe('filename.double-extension');
    expect(f.evidence.location).toMatchObject({ type: 'html_attribute', tag: 'a', attribute: 'download' });
    expect(f.target).toBe('https://x.com/dl');
  });
  it('ignores non-http schemes', () => {
    expect(run(link('data:text/html,invoice.pdf.exe'))).toEqual([]);
  });
});
