import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { normalizeTarget, checkResolved } from '../../src/worker/guard.js';
import { isGlobalIp, parseIp } from '../../src/worker/ip.js';

describe('normalizeTarget blocked_target', () => {
  it.each([
    'http://127.1/', 'http://0x7f.1/', 'http://2130706433/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/',
    'http://localhost/', 'http://a.local/', 'http://a.internal/', 'http://admin.localhost/', 'http://api.localhost/',
    'http://x.test/', 'http://intranet/', 'https://example.com:8443/', 'https://u:p@example.com/',
  ])('%s', (u) => {
    const r = normalizeTarget(u);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('blocked_target');
  });
});

describe('normalizeTarget bad_url', () => {
  it.each(['ftp://example.com/', 'not a url', '', 'javascript:alert(1)'])('%j', (u) => {
    const r = normalizeTarget(u);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad_url');
  });
});

describe('normalizeTarget ok', () => {
  it('normalizes case and trailing dot', () => {
    const r = normalizeTarget('https://Example.COM./a?b#c');
    expect(r).toMatchObject({ ok: true, host: 'example.com', hostKind: 'domain' });
    expect(r.url).toBe('https://example.com/a?b');
  });
  it('accepts explicit default ports', () => {
    expect(normalizeTarget('http://x.com:80/').ok).toBe(true);
    expect(normalizeTarget('https://x.com:443/').ok).toBe(true);
  });
  it('converts IDNs to punycode', () => {
    expect(normalizeTarget('https://münchen.de/')).toMatchObject({ ok: true, host: 'xn--mnchen-3ya.de' });
  });
  it('accepts a global IP literal', () => {
    expect(normalizeTarget('http://8.8.8.8/')).toMatchObject({ ok: true, host: '8.8.8.8', hostKind: 'ip' });
  });
  it('keeps the query string (secrets are redacted only in reports)', () => {
    expect(normalizeTarget('https://x.com/p?token=abc').url).toBe('https://x.com/p?token=abc');
  });
});

describe('checkResolved', () => {
  it('rejects the whole set when one answer is bad', () => {
    expect(checkResolved(['93.184.216.34', '10.0.0.1'])).toMatchObject({ ok: false, reason: 'blocked_target' });
  });
  it('accepts all-global sets', () => {
    expect(checkResolved(['8.8.8.8', '2606:4700:4700::1111'])).toEqual({ ok: true });
  });
  it('fails closed on empty or unparsable answers', () => {
    expect(checkResolved([]).ok).toBe(false);
    expect(checkResolved(['nope']).ok).toBe(false);
  });
});

describe('properties', () => {
  it('never throws, and every ok result is http(s) with a global IP host', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.webUrl(), fc.constantFrom('http://0177.0.0.1/', 'http://[::]/', 'http://1.1.1.1.:80/')), (s) => {
        const r = normalizeTarget(s);
        if (r.ok) {
          const u = new URL(r.url);
          expect(['http:', 'https:']).toContain(u.protocol);
          const ip = parseIp(r.host);
          if (ip) expect(isGlobalIp(r.host)).toBe(true);
          expect(r.hostKind).toBe(ip ? 'ip' : 'domain');
        }
      }),
      { numRuns: 2000, seed: 20261108 },
    );
  });
});
