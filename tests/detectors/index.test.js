import { describe, it, expect } from 'vitest';
import { runDetectors, finalizeFindings } from '../../src/detectors/index.js';
import { makeFingerprint } from '../../src/shared/url-safety.js';
import { validateReport } from '../../src/schema/report.js';

const ev = (n = 1, extra = {}) => ({
  snippet: `<a href="x${n}">`, sourceUrl: 'https://x.com/', matchedValue: `x${n}`, normalizedValue: 'https://x.com/a.exe', context: 'ctx',
  location: { type: 'html_attribute', tag: 'a', attribute: 'href', line: n, column: 1 }, ...extra,
});
const raw = (o = {}) => ({
  detector: 'payload-links', ruleId: 'payload.link.executable', category: 'payload', proposedSeverity: 'low', confidence: 'medium',
  title: 'Executable-looking link', target: 'https://x.com/a.exe', evidence: ev(), ...o,
});

describe('finalizeFindings grouping', () => {
  it('merges raws with the same rule and target into one finding with 2 observations', async () => {
    const [f, ...rest] = await finalizeFindings([raw({ evidence: ev(1) }), raw({ evidence: ev(2) })]);
    expect(rest).toEqual([]);
    expect(f.observations).toHaveLength(2);
    expect(f.observationCount).toBe(2);
    expect(f.observations[0]).toEqual({ evidence: expect.objectContaining({ matchedValue: 'x1' }) });
  });
  it('keeps different targets and different rules apart', async () => {
    const out = await finalizeFindings([raw(), raw({ target: 'https://x.com/b.exe' }), raw({ ruleId: 'payload.link.archive' })]);
    expect(out).toHaveLength(3);
  });
  it('500 identical raws become one finding with observationCount 500 and at most 20 observations', async () => {
    const [f, ...rest] = await finalizeFindings(Array.from({ length: 500 }, (_, i) => raw({ evidence: ev(i) })));
    expect(rest).toEqual([]);
    expect(f.observationCount).toBe(500);
    expect(f.observations.length).toBeLessThanOrEqual(20);
  });
  it('builds ids and fingerprints from rule and target', async () => {
    const [f] = await finalizeFindings([raw({ target: 'https://x.com/a.exe?token=SECRET123' })]);
    const fp = await makeFingerprint('payload.link.executable', 'https://x.com/a.exe?token=SECRET123');
    expect(f.fingerprint).toBe(fp);
    expect(f.id).toBe(`payload.link.executable:${fp.slice(0, 12)}`);
    expect(JSON.stringify(f)).not.toContain('SECRET123');
  });
  it('produces findings that satisfy the report schema', async () => {
    const findings = await finalizeFindings([raw(), raw({ ruleId: 'redirect.meta-refresh', detector: 'redirects', category: 'redirect', proposedSeverity: 'medium' })]);
    const report = { v: 1, engineVersion: '0', detectorVersions: {}, scannedAt: 'x', durationMs: 1, target: 't', finalUrl: 't', pagesScanned: [], findings, coverage: [], fetchStats: { attempted: 0, successful: 0, cached: 0, failed: 0 }, headers: {} };
    expect(validateReport(report)).toEqual({ ok: true, errors: [] });
  });
});

describe('finalizeFindings severity', () => {
  it('caps a lone weak payload.link.* proposed high to low', async () => {
    const [f] = await finalizeFindings([raw({ proposedSeverity: 'high' })]);
    expect(f.severity).toBe('low');
  });
  it('caps the other weak rules at low when nothing else shares the target', async () => {
    for (const ruleId of ['uri.blob-reference', 'uri.javascript-href', 'filename.homoglyph']) {
      const [f] = await finalizeFindings([raw({ ruleId, detector: 'x', proposedSeverity: 'medium' })]);
      expect(f.severity, ruleId).toBe('low');
    }
  });
  it('lets a weak rule keep its severity when another finding shares the target', async () => {
    const out = await finalizeFindings([
      raw({ ruleId: 'uri.blob-reference', detector: 'uri-schemes', proposedSeverity: 'medium', target: 'blob:https://x.com/1' }),
      raw({ ruleId: 'redirect.location', detector: 'redirects', category: 'redirect', proposedSeverity: 'medium', target: 'blob:https://x.com/1' }),
    ]);
    expect(out.map((f) => f.severity)).toEqual(['medium', 'medium']);
  });
  it('lets two independent detectors agreeing on a target reach high', async () => {
    const out = await finalizeFindings([
      raw({ proposedSeverity: 'high' }),
      raw({ detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'high', title: 'Redirect' }),
    ]);
    expect(out.map((f) => f.severity)).toEqual(['high', 'high']);
  });
  it('requires both corroborating findings to be at least medium', async () => {
    const out = await finalizeFindings([
      raw({ proposedSeverity: 'high' }),
      raw({ detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'low' }),
    ]);
    expect(out.find((f) => f.ruleId === 'payload.link.executable').severity).toBe('medium');
    expect(out.find((f) => f.ruleId === 'redirect.meta-refresh').severity).toBe('low');
  });
  it('lets an auto-triggered path to a payload extension reach high', async () => {
    const [f] = await finalizeFindings([raw({ detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'high', autoTriggered: true })]);
    expect(f.severity).toBe('high');
  });
  it('does not let auto-trigger raise a target without a payload extension', async () => {
    const [f] = await finalizeFindings([raw({ detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'high', autoTriggered: true, target: 'https://x.com/page.html' })]);
    expect(f.severity).toBe('medium');
  });
  it('caps any other uncorroborated high to medium', async () => {
    const [f] = await finalizeFindings([raw({ detector: 'obfuscated-urls', ruleId: 'obfuscation.base64-url', category: 'obfuscation', proposedSeverity: 'high' })]);
    expect(f.severity).toBe('medium');
  });
  it('takes the highest proposed severity in a group', async () => {
    const [f] = await finalizeFindings([raw({ ruleId: 'redirect.location', detector: 'redirects', proposedSeverity: 'low' }), raw({ ruleId: 'redirect.location', detector: 'redirects', proposedSeverity: 'medium' })]);
    expect(f.severity).toBe('medium');
  });
  it('takes confidence from observations at the final severity', async () => {
    const [f] = await finalizeFindings([
      raw({ ruleId: 'redirect.location', detector: 'redirects', proposedSeverity: 'medium', confidence: 'low' }),
      raw({ ruleId: 'redirect.location', detector: 'redirects', proposedSeverity: 'low', confidence: 'high' }),
    ]);
    expect(f).toMatchObject({ severity: 'medium', confidence: 'low' });
  });
  it('orders findings by severity then rule id', async () => {
    const out = await finalizeFindings([
      raw({ ruleId: 'redirect.a', detector: 'redirects', target: 'https://a.com/1', proposedSeverity: 'low' }),
      raw({ ruleId: 'redirect.b', detector: 'redirects', target: 'https://a.com/2', proposedSeverity: 'medium' }),
    ]);
    expect(out.map((f) => f.ruleId)).toEqual(['redirect.b', 'redirect.a']);
  });
});

describe('runDetectors', () => {
  const ctx = { pageUrl: 'https://x.com/', finalUrl: 'https://x.com/', baseUrl: 'https://x.com/', html: '', tree: null, headers: {}, chain: [], refs: [], scripts: [] };

  it('collects findings, candidates and coverage, adding an ok entry per detector', async () => {
    const candidate = { url: 'https://x.com/a.js', reason: 'script', priority: 1, sourceEvidence: ev(), depth: 1 };
    const d1 = { id: 'a', version: '1', run: () => ({ findings: [raw()], followCandidates: [candidate] }) };
    const d2 = { id: 'b', version: '1', run: async () => ({ findings: [], coverage: [{ check: 'b', state: 'skipped', reason: 'external_stylesheet_skipped' }] }) };
    const out = await runDetectors(ctx, [d1, d2]);
    expect(out.raw).toHaveLength(1);
    expect(out.candidates).toEqual([candidate]);
    expect(out.coverage).toEqual([
      { check: 'a', page: 'https://x.com/', state: 'ok' },
      { check: 'b', state: 'skipped', reason: 'external_stylesheet_skipped' },
    ]);
  });
  it('a throwing detector yields coverage unknown and does not stop the others', async () => {
    const bad = { id: 'bad', version: '1', run: () => { throw new Error('boom'); } };
    const rejects = { id: 'rej', version: '1', run: async () => { throw new Error('async boom'); } };
    const good = { id: 'good', version: '1', run: () => ({ findings: [raw()] }) };
    const out = await runDetectors(ctx, [bad, rejects, good]);
    expect(out.raw).toHaveLength(1);
    expect(out.coverage).toEqual([
      { check: 'bad', page: 'https://x.com/', state: 'unknown', reason: 'detector_failed' },
      { check: 'rej', page: 'https://x.com/', state: 'unknown', reason: 'detector_failed' },
      { check: 'good', page: 'https://x.com/', state: 'ok' },
    ]);
  });
});
