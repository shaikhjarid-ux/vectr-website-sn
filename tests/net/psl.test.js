import { describe, it, expect } from 'vitest';
import { registrableDomain, crossesRegistrableDomain } from '../../src/net/psl.js';

describe('registrableDomain', () => {
  it('uses the Public Suffix List', () => {
    expect(registrableDomain('a.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('www.x.com')).toBe('x.com');
    expect(registrableDomain('evil.github.io')).toBe('evil.github.io');
  });
  it('returns null for IPs, single labels and junk', () => {
    expect(registrableDomain('1.2.3.4')).toBeNull();
    expect(registrableDomain('localhost')).toBeNull();
    expect(registrableDomain('')).toBeNull();
  });
});

describe('crossesRegistrableDomain', () => {
  it('is false within one registrable domain', () => {
    expect(crossesRegistrableDomain('a.example.co.uk', 'b.example.co.uk')).toBe(false);
    expect(crossesRegistrableDomain('www.x.com', 'x.com')).toBe(false);
    expect(crossesRegistrableDomain('WWW.X.COM', 'x.com.')).toBe(false);
  });
  it('is true across private-suffix tenants and different domains', () => {
    expect(crossesRegistrableDomain('evil.github.io', 'good.github.io')).toBe(true);
    expect(crossesRegistrableDomain('x.com', 'y.com')).toBe(true);
  });
  it('compares IPs literally', () => {
    expect(crossesRegistrableDomain('1.2.3.4', '1.2.3.5')).toBe(true);
    expect(crossesRegistrableDomain('1.2.3.4', '1.2.3.4')).toBe(false);
    expect(crossesRegistrableDomain('[::1]', '::1')).toBe(false);
    expect(crossesRegistrableDomain('1.2.3.4', 'x.com')).toBe(true);
  });
  it('compares hosts without a registrable domain literally', () => {
    expect(crossesRegistrableDomain('localhost', 'localhost')).toBe(false);
    expect(crossesRegistrableDomain('localhost', 'intranet')).toBe(true);
  });
});
