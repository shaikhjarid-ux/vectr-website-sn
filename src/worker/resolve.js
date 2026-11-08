// DNS resolution policy: resolve A and AAAA through Cloudflare's DoH resolver
// and require every answer (including addresses behind CNAME chains) to be
// globally reachable. Fails closed. Target hostnames are sent to this resolver
// (the privacy notice states this).
import { checkResolved } from './guard.js';
import { isGlobalIp, parseIp } from './ip.js';

const DOH = 'https://cloudflare-dns.com/dns-query';

const isAbort = (err, signal) =>
  Boolean(signal?.aborted) || (err && (err.name === 'AbortError' || err.name === 'TimeoutError'));

async function query(host, type, fetchFn, signal) {
  let res;
  try {
    res = await fetchFn(`${DOH}?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
      signal,
    });
  } catch (err) {
    return { error: isAbort(err, signal) ? 'timeout' : 'doh_failed' };
  }
  if (!res.ok) return { error: 'doh_failed' };
  let body;
  try {
    body = await res.json();
  } catch (err) {
    return { error: isAbort(err, signal) ? 'timeout' : 'doh_failed' };
  }
  if (!body || typeof body !== 'object' || typeof body.Status !== 'number') return { error: 'doh_failed' };
  if (body.Status === 3) return { nxdomain: true, addresses: [] };
  if (body.Status !== 0) return { error: 'doh_failed' };
  const answers = Array.isArray(body.Answer) ? body.Answer : [];
  const addresses = answers
    .filter((a) => a && (a.type === 1 || a.type === 28) && typeof a.data === 'string')
    .map((a) => a.data);
  return { addresses };
}

/**
 * @param {string} host
 * @param {typeof fetch} fetchFn
 * @param {AbortSignal} [signal]
 * @returns {Promise<{ok: true, addresses: string[], subrequests: 2} | {ok: false, reason: 'doh_failed' | 'no_answer' | 'timeout', subrequests: number}>}
 */
export async function resolveHost(host, fetchFn, signal) {
  const [a, aaaa] = await Promise.all([query(host, 'A', fetchFn, signal), query(host, 'AAAA', fetchFn, signal)]);
  const results = [a, aaaa];
  if (results.some((r) => r.error === 'timeout')) return { ok: false, reason: 'timeout', subrequests: 2 };
  if (results.some((r) => r.error)) return { ok: false, reason: 'doh_failed', subrequests: 2 };
  if (results.some((r) => r.nxdomain)) return { ok: false, reason: 'no_answer', subrequests: 2 };
  const addresses = [...a.addresses, ...aaaa.addresses];
  if (addresses.length === 0) return { ok: false, reason: 'no_answer', subrequests: 2 };
  return { ok: true, addresses, subrequests: 2 };
}

/**
 * @param {string} host
 * @param {typeof fetch} fetchFn
 * @param {AbortSignal} [signal]
 * @returns {Promise<{ok: true, subrequests: number} | {ok: false, reason: 'blocked_target' | 'doh_failed' | 'no_answer' | 'timeout', detail: string, subrequests: number}>}
 */
export async function assertPublicHost(host, fetchFn, signal) {
  if (parseIp(host)) {
    return isGlobalIp(host)
      ? { ok: true, subrequests: 0 }
      : { ok: false, reason: 'blocked_target', detail: 'IP address is not globally reachable', subrequests: 0 };
  }
  const r = await resolveHost(host, fetchFn, signal);
  if (!r.ok) return { ok: false, reason: r.reason, detail: `DNS lookup failed: ${r.reason}`, subrequests: r.subrequests };
  const verdict = checkResolved(r.addresses);
  if (!verdict.ok) return { ok: false, reason: 'blocked_target', detail: verdict.detail, subrequests: r.subrequests };
  return { ok: true, subrequests: r.subrequests };
}
