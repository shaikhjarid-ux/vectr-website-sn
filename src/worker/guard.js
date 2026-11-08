// SSRF guard: pure functions, testable without a network.
import { isGlobalIp, isSpecialUseHost, parseIp } from './ip.js';

/** @typedef {{ok: true, url: string, host: string, hostKind: 'domain' | 'ip'} | {ok: false, reason: 'bad_url' | 'blocked_target', detail: string}} GuardResult */

const blocked = (detail) => ({ ok: false, reason: 'blocked_target', detail });
const bad = (detail) => ({ ok: false, reason: 'bad_url', detail });

/**
 * Parse once with the WHATWG URL class (it normalizes odd IPv4 forms and IDNA),
 * then decide on the normalized host. Details never echo the full URL.
 * @param {string} input
 * @returns {GuardResult}
 */
export function normalizeTarget(input) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    return bad('unparsable URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return bad('only http and https are allowed');
  if (url.username !== '' || url.password !== '') return blocked('credentials in URL are not allowed');
  if (url.port !== '') return blocked('only ports 80 and 443 are allowed');

  let host = url.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = host.replace(/\.$/, '');
  if (host === '') return bad('empty host');

  if (parseIp(host)) {
    if (!isGlobalIp(host)) return blocked('IP address is not globally reachable');
    url.hash = '';
    return { ok: true, url: url.href, host, hostKind: 'ip' };
  }
  if (host.includes(':')) return blocked('unparsable IP literal'); // IPv6 text that parseIp rejected: fail closed
  if (!host.includes('.')) return blocked('single-label hosts are not allowed');
  if (isSpecialUseHost(host)) return blocked('special-use hostname');

  url.hostname = host;
  url.hash = '';
  return { ok: true, url: url.href, host, hostKind: 'domain' };
}

/**
 * Every resolved address must be global; one bad answer rejects the whole set.
 * @param {string[]} addresses
 * @returns {{ok: true} | {ok: false, reason: 'blocked_target', detail: string}}
 */
export function checkResolved(addresses) {
  if (!Array.isArray(addresses) || addresses.length === 0) return blocked('no addresses to validate');
  for (const a of addresses) {
    if (!isGlobalIp(a)) return blocked('hostname resolves to a non-global address');
  }
  return { ok: true };
}
