import { describe, it, expect } from 'vitest';
import { parseTable, cleanDomains, build, v4Range, v6Range, SUPPLEMENTARY_NON_GLOBAL_V4 } from '../scripts/gen-ranges.mjs';
import { isGlobalIp } from '../src/worker/ip.js';

const COLS = ['Address Block', 'Globally Reachable'];

describe('parseTable input validation', () => {
  it('rejects an HTML page (such as a 404) with a helpful message', () => {
    const html = '\n<!doctype html>\n<html>\n<head>\n    <title>Page not found</title>';
    expect(() => parseTable(html, 'special.csv', ['Name'])).toThrow(/looks like HTML, not CSV.*special\.csv|special\.csv.*looks like HTML, not CSV/s);
  });
  it('lists the columns found when a required one is missing', () => {
    expect(() => parseTable('Foo,Bar\n1,2\n', 'x.csv', ['Name'])).toThrow(/expected a column named "Name".*"Foo".*"Bar"/s);
  });
  it('strips a BOM and matches column names ignoring case and spacing', () => {
    const rows = parseTable('\uFEFFaddress block,GLOBALLY  reachable\n10.0.0.0/8,False\n', 'x.csv', COLS);
    expect(rows).toEqual([{ 'Address Block': '10.0.0.0/8', 'Globally Reachable': 'False' }]);
  });
  it('handles quoted cells with commas and newlines', () => {
    const rows = parseTable('Name,Reference\n"a, b","line1\nline2"\n', 'x.csv', ['Name', 'Reference']);
    expect(rows).toEqual([{ Name: 'a, b', Reference: 'line1\nline2' }]);
  });
});

describe('cleanDomains', () => {
  it('removes suffixes like (DEPRECATED) before the trailing dot, lowercases and dedupes', () => {
    const rows = [{ Name: 'eap-noob.arpa. (DEPRECATED)' }, { Name: 'Home.ARPA.' }, { Name: 'alt.' }, { Name: 'alt.' }, { Name: '' }, { Name: '<html>' }];
    expect(cleanDomains(rows)).toEqual(['alt', 'eap-noob.arpa', 'home.arpa']);
  });
});

describe('build', () => {
  it('collects every non-True block, tolerating footnotes and comma-separated blocks', () => {
    const rows = [
      { 'Address Block': '10.0.0.0/8', 'Globally Reachable': 'False' },
      { 'Address Block': '192.0.0.0/24 [2], 198.18.0.0/15', 'Globally Reachable': 'False [4]' },
      { 'Address Block': '192.0.0.9/32', 'Globally Reachable': 'True' },
      { 'Address Block': '192.88.99.0/24', 'Globally Reachable': 'N/A' },
    ];
    const ranges = build(rows, v4Range);
    const inside = (n) => ranges.some(([s, e]) => n >= s && n <= e);
    const ip = (a) => a.split('.').reduce((x, o) => x * 256 + Number(o), 0);
    expect(inside(ip('10.1.2.3'))).toBe(true);
    expect(inside(ip('192.0.0.1'))).toBe(true);
    expect(inside(ip('198.19.0.1'))).toBe(true);
    expect(inside(ip('192.88.99.5'))).toBe(true);
    expect(inside(ip('192.0.0.9'))).toBe(false); // globally reachable sub-allocation
  });
  it('adds supplementary ranges that are not registry rows (multicast)', () => {
    expect(SUPPLEMENTARY_NON_GLOBAL_V4).toContain('224.0.0.0/4');
    const [[s, e]] = build([], v4Range, SUPPLEMENTARY_NON_GLOBAL_V4);
    expect([s, e]).toEqual([3758096384, 4026531839]);
  });
  it('builds IPv6 ranges', () => {
    const [[s, e]] = build([{ 'Address Block': '2001:db8::/32', 'Globally Reachable': 'False' }], v6Range);
    expect(e - s + 1n).toBe(1n << 96n);
  });
});

describe('the generated tables in the repository', () => {
  it('keep multicast and the standard private ranges non-global', () => {
    for (const ip of ['224.0.0.1', '239.255.255.250', '10.0.0.1', '127.0.0.1', '169.254.169.254', 'ff02::1', '::1', 'fe80::1']) expect(isGlobalIp(ip), ip).toBe(false);
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) expect(isGlobalIp(ip), ip).toBe(true);
  });
});
