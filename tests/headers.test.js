import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";

/** Parses the Cloudflare _headers format: unindented path lines followed by indented `Name: value` lines. */
function parseHeaders(text) {
  const rules = [];
  let current = null;
  for (const line of text.split('\n')) {
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    if (/^\s/.test(line)) {
      const i = line.indexOf(':');
      current.headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
    } else {
      current = { path: line.trim(), headers: [] };
      rules.push(current);
    }
  }
  return rules;
}

const text = readFileSync('public/_headers', 'utf8');
const rules = parseHeaders(text);
const all = rules.find((r) => r.path === '/*');
const get = (name) => all.headers.filter(([n]) => n.toLowerCase() === name.toLowerCase()).map(([, v]) => v);

describe('public/_headers', () => {
  it('has a /* rule', () => {
    expect(all).toBeDefined();
  });
  it('sets the exact CSP', () => {
    expect(get('Content-Security-Policy')).toEqual([CSP]);
  });
  it('sets HSTS without includeSubDomains or preload', () => {
    expect(get('Strict-Transport-Security')).toEqual(['max-age=31536000']);
  });
  it('sets the other security headers exactly', () => {
    expect(get('X-Content-Type-Options')).toEqual(['nosniff']);
    expect(get('Referrer-Policy')).toEqual(['no-referrer']);
    expect(get('Permissions-Policy')).toEqual(['camera=(), microphone=(), geolocation=(), interest-cohort=()']);
    expect(get('X-Frame-Options')).toEqual(['DENY']);
  });
  it("has a separate report-only Trusted Types policy", () => {
    expect(get('Content-Security-Policy-Report-Only')).toEqual(["require-trusted-types-for 'script'"]);
  });
  it('stays within Cloudflare Pages/Workers header limits', () => {
    const count = rules.reduce((n, r) => n + 1 + r.headers.length, 0);
    expect(count).toBeLessThanOrEqual(100);
    for (const line of text.split('\n')) expect(line.length).toBeLessThanOrEqual(2000);
  });
  it('does not weaken the CSP with unsafe sources', () => {
    expect(get('Content-Security-Policy')[0]).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
  });
});
