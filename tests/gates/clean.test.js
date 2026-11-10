import { describe, it, expect } from 'vitest';
import { readdirSync } from 'node:fs';
import { readJson, readFixture, scanHtml } from '../helpers/gates.js';
import { validateReport } from '../../src/schema/report.js';

const manifest = readJson('tests/fixtures/clean/manifest.json');

describe('clean-site gate', () => {
  it('has at least 10 fixtures, each documented as captured or synthetic', () => {
    expect(manifest.length).toBeGreaterThanOrEqual(10);
    for (const m of manifest) {
      expect(typeof m.description, m.file).toBe('string');
      expect(Boolean(m.capturedOn) || m.synthetic === true, `${m.file} needs capturedOn or synthetic: true`).toBe(true);
    }
  });
  it('the manifest and the directory list the same files', () => {
    const files = readdirSync('tests/fixtures/clean').filter((f) => f.endsWith('.html')).sort();
    expect(manifest.map((m) => m.file).sort()).toEqual(files);
  });
  it.each(manifest.map((m) => [m.file]))('%s produces zero high findings and a valid report', async (file) => {
    const report = await scanHtml(readFixture('clean', file));
    expect(validateReport(report)).toEqual({ ok: true, errors: [] });
    expect(report.findings.filter((f) => f.severity === 'high'), file).toEqual([]);
  });
});
