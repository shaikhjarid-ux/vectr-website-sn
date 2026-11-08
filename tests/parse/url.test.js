import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { resolveUrl, normalizeForMatch, extensionOf, PAYLOAD_EXTENSIONS, looksUrlLike, queryFilenames, extensionOfFilename } from '../../src/parse/url.js';

describe('resolveUrl', () => {
  it('resolves relative references', () => {
    expect(resolveUrl('../a.exe', 'https://x.com/d/e/')).toBe('https://x.com/d/a.exe');
    expect(resolveUrl('//cdn.x.com/a.zip', 'https://x.com/')).toBe('https://cdn.x.com/a.zip');
  });
  it('returns null when it cannot resolve', () => {
    expect(resolveUrl('http://', 'https://x.com/')).toBeNull();
    expect(resolveUrl('a', 'not a base')).toBeNull();
  });
});

describe('normalizeForMatch', () => {
  it('decodes layered encoding and reports passes', () => {
    const r = normalizeForMatch('https://x.com/a%252eexe');
    expect(r.url.endsWith('.exe')).toBe(true);
    expect(r.passes).toBe(2);
    expect(r.truncated).toBe(false);
  });
  it('drops the fragment', () => {
    expect(normalizeForMatch('https://x.com/a.exe#frag').url).toBe('https://x.com/a.exe');
  });
  it('decodes exactly 3 layers without flagging truncation', () => {
    const r = normalizeForMatch(`https://x.com/a%${'25'.repeat(2)}2eexe`);
    expect(r.url).toBe('https://x.com/a.exe');
    expect(r).toMatchObject({ passes: 3, truncated: false });
  });
  it('stops at 3 passes and flags a 5-layer encoding as truncated', () => {
    const r = normalizeForMatch(`https://x.com/a%${'25'.repeat(4)}2eexe`);
    expect(r.url).toBe('https://x.com/a%252eexe'); // one layer still undecoded
    expect(r).toMatchObject({ passes: 3, truncated: true });
  });
  it('tolerates malformed percent sequences', () => {
    expect(() => normalizeForMatch('https://x.com/%E0%A4%A')).not.toThrow();
    expect(normalizeForMatch('https://x.com/100%').url).toBe('https://x.com/100%');
  });
  it('terminates on random strings (property)', () => {
    fc.assert(fc.property(fc.string({ maxLength: 300 }), (s) => {
      const r = normalizeForMatch(s);
      expect(r.passes).toBeLessThanOrEqual(3);
      expect(typeof r.url).toBe('string');
    }), { numRuns: 1000, seed: 20261108 });
  });
});

describe('extensionOf', () => {
  it('uses the pathname only, lowercased', () => {
    expect(extensionOf('https://x.com/a/Setup.EXE?x=.zip#y')).toBe('exe');
    expect(extensionOf('https://x.com/dl?file=a.exe')).toBeNull();
    expect(extensionOf('https://x.com/a.tar.gz')).toBe('gz');
    expect(extensionOf('https://x.com/dir.v2/readme')).toBeNull();
  });
  it('sees through encoded dots and path parameters', () => {
    expect(extensionOf('https://x.com/a%2eexe')).toBe('exe');
    expect(extensionOf('https://x.com/a.exe;jsessionid=1')).toBe('exe');
  });
  it('ignores trailing dots and spaces that Windows would trim', () => {
    expect(extensionOf('https://x.com/a.exe.')).toBe('exe');
  });
  it('works for relative references and returns null for junk', () => {
    expect(extensionOf('/files/a.zip')).toBe('zip');
    expect(extensionOf('')).toBeNull();
  });
});

describe('PAYLOAD_EXTENSIONS', () => {
  it('lists the spec extensions', () => {
    expect([...PAYLOAD_EXTENSIONS].sort()).toEqual('exe msi zip rar 7z iso apk dmg scr bat cmd ps1 jar vbs lnk pkg deb appimage'.split(' ').sort());
  });
});

describe('looksUrlLike', () => {
  it('rejects ids and accepts urls', () => {
    expect(looksUrlLike('data-id', '123')).toBe(false);
    expect(looksUrlLike('data-url', 'https://x.com/a.exe')).toBe(true);
    expect(looksUrlLike('data-target', 'cdn.x.com/file.zip')).toBe(true);
    expect(looksUrlLike('data-hash', 'a1b2.c3')).toBe(false);
    expect(looksUrlLike('data-label', 'Download now')).toBe(false);
    expect(looksUrlLike('data-x', '/files/a.exe')).toBe(true);
    expect(looksUrlLike('data-x', 'javascript:go()')).toBe(true);
  });
});

describe('queryFilenames / extensionOfFilename', () => {
  it('extracts filename-like parameters with bounded decoding', () => {
    expect(queryFilenames('https://x.com/dl?file=a.exe&q=1')).toEqual(['a.exe']);
    expect(queryFilenames('https://x.com/dl?file=a%252eexe')).toEqual(['a.exe']);
    expect(queryFilenames('https://x.com/dl?q=a.exe')).toEqual([]);
    expect(queryFilenames('https://x.com/dl?FileName=b.msi&Download=c.zip')).toEqual(['b.msi', 'c.zip']);
  });
  it('caps values at 256 characters', () => {
    const [v] = queryFilenames(`https://x.com/dl?file=${'a'.repeat(500)}.exe`);
    expect(v.length).toBe(256);
  });
  it('finds the extension of a bare filename', () => {
    expect(extensionOfFilename('dir/Setup.EXE')).toBe('exe');
    expect(extensionOfFilename('C:\\tmp\\a.scr')).toBe('scr');
    expect(extensionOfFilename('noext')).toBeNull();
  });
});
