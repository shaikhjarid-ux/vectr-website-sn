import { describe, it, expect } from 'vitest';
import { readJson, readFixture, scanHtml } from '../helpers/gates.js';
import { validateReport } from '../../src/schema/report.js';

const manifest = readJson('tests/fixtures/recall/manifest.json');

/** Every ruleId defined by the detectors in Tasks 15-21. */
const ALL_RULES = [
  'payload.link.executable', 'payload.link.archive', 'payload.link.query-filename',
  'filename.double-extension', 'filename.control-chars', 'filename.archive-executable', 'filename.homoglyph',
  'obfuscation.decoded-payload-url', 'obfuscation.decoded-url',
  'redirect.meta-refresh', 'redirect.script-navigation', 'redirect.chain-cross-domain', 'redirect.final-host-differs',
  'overlay.hidden-iframe', 'overlay.fullscreen-capture', 'overlay.offscreen-link',
  'form.off-origin-action', 'form.password-off-origin',
  'uri.data-download', 'uri.blob-reference', 'uri.javascript-href', 'uri.ms-handler',
  'header.content-disposition-attachment', 'header.executable-content-type',
];

describe('recall gate', () => {
  it('has at least one fixture expectation for every rule', () => {
    const covered = new Set(manifest.flatMap((m) => m.expected.map((e) => e.ruleId)));
    expect(ALL_RULES.filter((r) => !covered.has(r))).toEqual([]);
  });
  it.each(manifest.map((m) => [m.file, m]))('%s: every expected finding appears', async (file, m) => {
    const report = await scanHtml(readFixture('recall', file), { finalUrl: m.finalUrl, headers: m.headers, chain: m.chain });
    expect(validateReport(report).ok).toBe(true);
    for (const e of m.expected) {
      const hits = report.findings.filter((f) => f.ruleId === e.ruleId);
      expect(hits.length, `${file}: missing ${e.ruleId}`).toBeGreaterThan(0);
      if (e.tag || e.attribute) {
        const ok = hits.some((f) => f.observations.some((o) => (!e.tag || o.evidence.location.tag === e.tag) && (!e.attribute || o.evidence.location.attribute === e.attribute)));
        expect(ok, `${file}: ${e.ruleId} location ${e.tag ?? ''} ${e.attribute ?? ''}`).toBe(true);
      }
    }
  });
});
