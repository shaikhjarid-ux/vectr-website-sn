// IP parsing and classification from generated IANA-derived tables.
import { RANGES } from './ranges.js';
import { SPECIAL_DOMAINS } from './special-domains.js';

/** Documented allowlist: special-use registry names that resolve publicly. The DoH check still applies. */
const ALLOWED_SPECIAL = ['example.com', 'example.net', 'example.org'];

const V4 = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;

function parseV4(text) {
  if (!V4.test(text)) return null;
  const parts = text.split('.').map(Number);
  return parts.some((n) => n > 255) ? null : Uint8Array.from(parts);
}

function parseV6(text) {
  if (text.includes('%') || !text.includes(':')) return null;
  const dbl = text.split('::');
  if (dbl.length > 2) return null;
  const expand = (s) => {
    if (s === '') return [];
    const groups = [];
    const parts = s.split(':');
    for (let i = 0; i < parts.length; i++) {
      const g = parts[i];
      if (g.includes('.')) {
        if (i !== parts.length - 1) return null;
        const v4 = parseV4(g);
        if (!v4) return null;
        groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!HEX_GROUP.test(g)) return null;
        groups.push(parseInt(g, 16));
      }
    }
    return groups;
  };
  const head = expand(dbl[0]);
  const tail = dbl.length === 2 ? expand(dbl[1]) : [];
  if (!head || !tail) return null;
  let groups;
  if (dbl.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill(0), ...tail];
  } else groups = head;
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => { bytes[i * 2] = g >> 8; bytes[i * 2 + 1] = g & 0xff; });
  return bytes;
}

/**
 * @param {string} text
 * @returns {{version: 4 | 6, bytes: Uint8Array} | null}
 */
export function parseIp(text) {
  if (typeof text !== 'string') return null;
  const v4 = parseV4(text);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = parseV6(text);
  return v6 ? { version: 6, bytes: v6 } : null;
}

function inRanges(ranges, value) {
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = ranges[mid];
    if (value < s) hi = mid - 1;
    else if (value > e) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * True only for a parseable, globally reachable unicast address. Fails closed.
 * @param {string} ip
 */
export function isGlobalIp(ip) {
  const parsed = parseIp(ip);
  if (!parsed) return false;
  if (parsed.version === 4) {
    const b = parsed.bytes;
    return !inRanges(RANGES.v4, ((b[0] * 256 + b[1]) * 256 + b[2]) * 256 + b[3]);
  }
  const b = parsed.bytes;
  if ((b[0] & 0xe0) !== 0x20) return false; // outside 2000::/3 (includes IPv4-mapped ::ffff:0:0/96)
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return !inRanges(RANGES.v6, n);
}

/**
 * True when the host equals or is a subdomain of a special-use registry name,
 * is under .arpa or .internal. Label-boundary matching: latest.com is not "test".
 * @param {string} host
 */
export function isSpecialUseHost(host) {
  if (typeof host !== 'string') return true;
  const h = host.toLowerCase().replace(/\.$/, '');
  if (h === '') return true;
  const under = (d) => h === d || h.endsWith(`.${d}`);
  if (ALLOWED_SPECIAL.some(under)) return false;
  if (under('arpa') || under('internal')) return true;
  return SPECIAL_DOMAINS.some(under);
}
