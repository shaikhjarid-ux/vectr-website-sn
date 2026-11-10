import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { scanHtml } from '../helpers/gates.js';

const word = fc.stringMatching(/^[a-z]{3,10}$/);
const page = (body) => `<!doctype html><html><body><p>${'text '.repeat(60)}</p>${body}</body></html>`;

const singleSignal = fc.oneof(
  word.map((n) => `<a href="https://dl.example.net/${n}.exe">get</a>`),
  word.map((n) => `<a href="https://xn--${n}-9ya.example.com/">punycode host</a>`),
  word.map((n) => `<a href="blob:https://x.com/${n}">blob</a>`),
  word.map((n) => `<a href="https://mirror.example.org/${n}">Download mirror</a>`),
  word.map((n) => `<a href="/dl?file=${n}.msi">q</a>`),
  word.map((n) => `<a href="/files/${n}.zip">zip</a>`),
);

describe('severity gate', () => {
  it('no single-signal page produces a high finding', async () => {
    await fc.assert(
      fc.asyncProperty(singleSignal, async (body) => {
        const report = await scanHtml(page(body));
        expect(report.findings.filter((f) => f.severity === 'high'), body).toEqual([]);
      }),
      { numRuns: 60, seed: 20261108 },
    );
  });
  it('a lone executable link stays low', async () => {
    const report = await scanHtml(page('<a href="https://dl.example.net/setup.exe">get</a>'));
    expect(report.findings.map((f) => [f.ruleId, f.severity])).toEqual([['payload.link.executable', 'low']]);
  });
});
