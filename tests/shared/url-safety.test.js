import { describe, it, expect } from 'vitest';
import { redactUrl, redactText, defang, displayUrl, makeFingerprint } from '../../src/shared/url-safety.js';

describe('redactUrl', () => {
  it('redacts secret-like parameters and leaves others', () => {
    expect(redactUrl('https://a.com/?token=abc&q=1')).toBe('https://a.com/?token=REDACTED&q=1');
    expect(redactUrl('https://a.com/?q=1')).toBe('https://a.com/?q=1');
  });
  it('is case-insensitive and covers every listed name', () => {
    for (const n of ['token', 'key', 'auth', 'session', 'signature', 'access_token', 'apikey', 'api_key', 'password', 'secret', 'TOKEN', 'Api_Key']) {
      expect(redactUrl(`https://a.com/?x=1&${n}=SECRET123&y=2`)).toBe(`https://a.com/?x=1&${n}=REDACTED&y=2`);
    }
  });
  it('redacts a percent-encoded parameter name and fragment parameters', () => {
    expect(redactUrl('https://a.com/?%74oken=SECRET123')).not.toContain('SECRET123');
    expect(redactUrl('https://a.com/#access_token=SECRET123&state=1')).toBe('https://a.com/#access_token=REDACTED&state=1');
  });
  it('returns the input unchanged if it does not parse', () => {
    expect(redactUrl('not a url?token=abc')).toBe('not a url?token=abc');
  });
});

describe('redactText', () => {
  it('redacts name=value after ?, & or ; inside free text', () => {
    const t = 'see https://a.com/x?token=SECRET123&q=1 and a;password=SECRET123; end';
    const out = redactText(t);
    expect(out).not.toContain('SECRET123');
    expect(out).toContain('q=1');
  });
});

describe('defang / displayUrl', () => {
  it('defangs scheme and host dots', () => {
    expect(defang('https://a.b.example/x.exe?x=1')).toBe('hxxps://a[.]b[.]example/x.exe?x=1');
    expect(defang('http://x.com/a')).toBe('hxxp://x[.]com/a');
  });
  it('displayUrl = defang(redactUrl)', () => {
    expect(displayUrl('https://a.com/?token=abc')).toBe('hxxps://a[.]com/?token=REDACTED');
  });
});

describe('makeFingerprint', () => {
  it('ignores secret values and separates rule ids', async () => {
    const a = await makeFingerprint('r1', 'https://a.com/x?token=one');
    const b = await makeFingerprint('r1', 'https://a.com/x?token=two');
    const c = await makeFingerprint('r2', 'https://a.com/x?token=one');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});
