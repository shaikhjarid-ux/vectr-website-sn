import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import ipaddr from 'ipaddr.js';
import { parseIp, isGlobalIp, isSpecialUseHost } from '../../src/worker/ip.js';

const NON_GLOBAL = ['0.0.0.0', '10.1.2.3', '127.0.0.1', '169.254.169.254', '100.64.0.1', '172.16.0.1', '192.168.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::', '::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:8.8.8.8', 'fe80::1%eth0', 'not-an-ip'];
const GLOBAL = ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'];

describe('isGlobalIp', () => {
  it.each(NON_GLOBAL)('%s is not global', (ip) => expect(isGlobalIp(ip)).toBe(false));
  it.each(GLOBAL)('%s is global', (ip) => expect(isGlobalIp(ip)).toBe(true));
  it('honours registry sub-allocations that are globally reachable', () => {
    expect(isGlobalIp('192.0.0.9')).toBe(true); // PCP anycast inside 192.0.0.0/24
    expect(isGlobalIp('192.0.0.1')).toBe(false);
  });
  it('agrees with ipaddr.js for 5,000 random addresses (non-unicast => not global)', () => {
    const v4 = fc.tuple(...Array(4).fill(fc.integer({ min: 0, max: 255 }))).map((b) => b.join('.'));
    const v6 = fc.tuple(...Array(8).fill(fc.integer({ min: 0, max: 0xffff }))).map((g) => g.map((x) => x.toString(16)).join(':'));
    fc.assert(
      fc.property(fc.oneof(v4, v6), (ip) => {
        const range = ipaddr.parse(ip).range();
        if (range !== 'unicast') expect(isGlobalIp(ip), `${ip} (${range})`).toBe(false);
      }),
      { numRuns: 5000, seed: 20261108 },
    );
  });
});

describe('parseIp', () => {
  it('parses IPv4, IPv6 with compression and embedded IPv4', () => {
    expect(parseIp('8.8.4.4')).toEqual({ version: 4, bytes: Uint8Array.from([8, 8, 4, 4]) });
    expect(parseIp('::1').bytes[15]).toBe(1);
    expect(parseIp('::ffff:1.2.3.4').bytes.slice(10)).toEqual(Uint8Array.from([255, 255, 1, 2, 3, 4]));
    expect(parseIp('2606:4700:4700::1111').version).toBe(6);
  });
  it('returns null for zone ids and junk', () => {
    for (const s of ['fe80::1%eth0', 'x', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1::2::3', '', '01.2.3.4']) expect(parseIp(s), s).toBeNull();
  });
});

describe('isSpecialUseHost', () => {
  it.each(['localhost', 'admin.localhost', 'api.localhost', 'a.b.localhost', 'x.test', 'foo.home.arpa', 'a.onion', '1.0.0.10.in-addr.arpa', 'service.arpa', 'anything.invalid', 'x.local', 'corp.internal'])('%s is special-use', (h) => expect(isSpecialUseHost(h)).toBe(true));
  it.each(['example.com', 'www.example.org', 'latest.com', 'myexample.com', 'test-site.com'])('%s is not special-use', (h) => expect(isSpecialUseHost(h)).toBe(false));
});
