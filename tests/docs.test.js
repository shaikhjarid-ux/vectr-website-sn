import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_DETECTORS } from '../src/engine/scan.js';

const FORBIDDEN = ['prevents all SSRF', 'detects all malicious', 'proves a site safe', 'zero data collection'];
const HEADINGS = ['Supported inputs', 'Blind spots', 'Confidence', 'False positives'];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      // docs/superpowers holds the planning documents, which quote these phrases as things never to claim.
      if (p === join('docs', 'superpowers')) continue;
      walk(p, out);
    } else if (p.endsWith('.md')) out.push(p);
  }
  return out;
}

describe('detector docs', () => {
  it('has one doc per detector id', () => {
    const files = readdirSync('docs/detectors').filter((f) => f.endsWith('.md')).map((f) => f.replace(/\.md$/, '')).sort();
    expect(files).toEqual(DEFAULT_DETECTORS.map((d) => d.id).sort());
    expect(files).toHaveLength(8);
  });
  it.each(DEFAULT_DETECTORS.map((d) => [d.id]))('%s has the required headings', (id) => {
    const md = readFileSync(`docs/detectors/${id}.md`, 'utf8');
    for (const h of HEADINGS) expect(md, `${id}: ${h}`).toMatch(new RegExp(`^#{1,3} ${h}\\s*$`, 'm'));
  });
});

describe('release claims', () => {
  // CONTRIBUTING.md quotes these phrases as claims contributors must never make, so it is not scanned.
  const files = ['README.md', 'docs/RELEASE_NOTES.md', ...walk('docs')];
  it.each([...new Set(files)])('%s makes none of the forbidden claims', (file) => {
    const text = readFileSync(file, 'utf8').toLowerCase();
    for (const phrase of FORBIDDEN) expect(text, `${file}: "${phrase}"`).not.toContain(phrase.toLowerCase());
  });
  it('release notes have Residual risks (naming DNS rebinding) and Demonstrated coverage headings', () => {
    const md = readFileSync('docs/RELEASE_NOTES.md', 'utf8');
    expect(md).toMatch(/^#{1,3} Residual risks\s*$/m);
    expect(md).toMatch(/^#{1,3} Demonstrated coverage\s*$/m);
    const residual = md.slice(md.search(/^#{1,3} Residual risks\s*$/m));
    expect(residual.toLowerCase()).toContain('dns rebinding');
  });
  it('release notes list what was not verified', () => {
    expect(readFileSync('docs/RELEASE_NOTES.md', 'utf8')).toMatch(/^#{1,3} Not verified\s*$/m);
  });
  it('README and release notes state the limiter caveat', () => {
    for (const f of ['README.md', 'docs/RELEASE_NOTES.md']) expect(readFileSync(f, 'utf8'), f).toMatch(/Cache API entries are local to one data cent(re|er)/);
  });
});
