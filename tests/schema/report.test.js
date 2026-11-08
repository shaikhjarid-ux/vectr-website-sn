import { describe, it, expect } from 'vitest';
import { validateReport, SEVERITIES, CONFIDENCES, CATEGORIES, COVERAGE_STATES } from '../../src/schema/report.js';
import { ERROR_CODES, REASON_CODES } from '../../src/shared/codes.js';
import { sanitizeReport } from '../../src/shared/url-safety.js';

const S = 'https://a.com/p?token=SECRET123&ok=1';

export function minimalReport() {
  return {
    v: 1, engineVersion: '0.1.0', detectorVersions: {}, scannedAt: '2026-11-08T00:00:00.000Z', durationMs: 1,
    target: 'https://a.com/', finalUrl: 'https://a.com/', pagesScanned: [], findings: [], coverage: [],
    fetchStats: { attempted: 0, successful: 0, cached: 0, failed: 0 }, headers: {},
  };
}

function secretReport() {
  const ev = { snippet: `<a href="${S}">`, sourceUrl: S, location: { type: 'html_attribute', tag: 'a', attribute: 'href', line: 1, column: 1 }, matchedValue: S, normalizedValue: S, context: `x ${S} y` };
  const r = minimalReport();
  r.target = S; r.finalUrl = S;
  r.pagesScanned = [{ url: S, status: 200, contentType: 'text/html', bytesRead: 1, truncated: false, redirectChain: [{ url: S, status: 302, location: S }] }];
  r.findings = [{ id: 'r:abc', fingerprint: 'f', detector: 'd', ruleId: 'r', category: 'payload', severity: 'low', confidence: 'low', title: 't', observations: [{ evidence: ev }], observationCount: 1 }];
  return r;
}

describe('constants', () => {
  it('match the spec', () => {
    expect(SEVERITIES).toEqual(['info', 'low', 'medium', 'high']);
    expect(CONFIDENCES).toEqual(['low', 'medium', 'high']);
    expect(CATEGORIES).toContain('infrastructure');
    expect(COVERAGE_STATES).toEqual(['ok', 'unknown', 'skipped']);
    expect(ERROR_CODES).toEqual(['bad_request', 'blocked_target', 'bad_url', 'timeout', 'too_many_redirects', 'upstream_error', 'rate_limited', 'budget_exhausted']);
    for (const c of ['response_truncated', 'fetch_timeout', 'script_parse_limit_reached', 'resource_budget_exhausted', 'scan_deadline_reached', 'external_stylesheet_skipped', 'unsupported_runtime_behavior']) expect(REASON_CODES).toContain(c);
  });
});

describe('validateReport', () => {
  it('accepts a minimal valid report', () => {
    expect(validateReport(minimalReport())).toEqual({ ok: true, errors: [] });
  });
  it('rejects a missing v', () => {
    const r = minimalReport(); delete r.v;
    const res = validateReport(r);
    expect(res.ok).toBe(false);
    expect(res.errors.join()).toMatch(/\bv\b/);
  });
  it("rejects severity 'critical' and coverage state 'maybe'", () => {
    const r = secretReport(); r.findings[0].severity = 'critical';
    expect(validateReport(r).ok).toBe(false);
    const q = minimalReport(); q.coverage = [{ check: 'x', state: 'maybe' }];
    expect(validateReport(q).ok).toBe(false);
  });
  it('rejects non-objects without throwing', () => {
    for (const x of [null, 1, 'x', [], undefined]) expect(validateReport(x).ok).toBe(false);
  });
});

describe('sanitizeReport', () => {
  it('removes secrets from every URL-bearing field but keeps other params', () => {
    const r = secretReport();
    const out = sanitizeReport(r);
    const json = JSON.stringify(out);
    expect(json).not.toContain('SECRET123');
    expect(json).toContain('ok=1');
    expect(JSON.stringify(r)).toContain('SECRET123'); // deep copy: input untouched
    expect(validateReport(out).ok).toBe(true);
  });
});
