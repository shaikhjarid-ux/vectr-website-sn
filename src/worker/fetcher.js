// Guarded manual-redirect fetcher. One shared deadline covers DNS and every
// hop; every hop is revalidated; the byte cap counts bytes actually read.
import { normalizeTarget } from './guard.js';
import { assertPublicHost } from './resolve.js';

export const LIMITS = Object.freeze({
  maxHops: 5,
  timeoutMs: 8000,
  pageBytes: 1048576,
  scriptBytes: 262144,
  subrequestAbort: 40,
});

/** Response headers that may be returned to the client. Set-Cookie, authentication and proxy headers are never included. */
export const HEADER_ALLOWLIST = [
  'content-type', 'content-disposition', 'content-length', 'content-encoding',
  'cache-control', 'etag', 'last-modified', 'server', 'x-powered-by', 'location',
  'content-security-policy', 'strict-transport-security', 'x-frame-options',
  'x-content-type-options', 'referrer-policy', 'permissions-policy',
];

const OUTBOUND_HEADERS = Object.freeze({
  'user-agent': 'Vectr-Website-SN/0.1 (static analysis only; abuse reports: see SECURITY.md in the project repository)',
  accept: 'text/html,application/xhtml+xml,application/javascript;q=0.9,*/*;q=0.8',
  'accept-language': 'en',
});

const SCRIPT_TYPES = new Set([
  'application/javascript', 'text/javascript', 'application/x-javascript',
  'application/ecmascript', 'text/ecmascript',
]);

class DeadlineError extends Error {}
class BudgetError extends Error {}

/**
 * @typedef {import('../schema/report.js').ChainEntry} ChainEntry
 * @typedef {{ok: true, finalUrl: string, chain: ChainEntry[], status: number, contentType: string, bytesRead: number, truncated: boolean, headers: Record<string, string>, body: Uint8Array, subrequests: number, hadSetCookie: boolean}
 *   | {ok: false, error: string, detail: string, chain: ChainEntry[]}} FetchOutcome
 */

/**
 * @param {string} url
 * @param {{kind: 'page' | 'script', fetchFn: typeof fetch, limits?: Partial<typeof LIMITS>}} opts
 * @returns {Promise<FetchOutcome>}
 */
export async function fetchTarget(url, opts) {
  const limits = { ...LIMITS, ...opts.limits };
  const { kind } = opts;
  /** @type {ChainEntry[]} */
  const chain = [];
  const controller = new AbortController();
  const { signal } = controller;
  const timer = setTimeout(() => controller.abort(), limits.timeoutMs);

  const deadline = new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(new DeadlineError('deadline')), { once: true });
  });
  deadline.catch(() => {});
  const race = (p) => Promise.race([p, deadline]);

  let subrequests = 0;
  let budgetHit = false;
  const counted = (input, init) => {
    if (subrequests >= limits.subrequestAbort) {
      budgetHit = true;
      throw new BudgetError('subrequest limit reached');
    }
    subrequests++;
    return opts.fetchFn(input, { ...init, signal });
  };

  const fail = (error, detail) => ({ ok: false, error, detail, chain });
  const failFromThrown = (err) => {
    if (budgetHit || err instanceof BudgetError) return fail('budget_exhausted', 'subrequest limit reached');
    if (err instanceof DeadlineError || signal.aborted) return fail('timeout', 'upstream deadline exceeded');
    return fail('upstream_error', 'upstream request failed');
  };

  try {
    let current = url;
    let hops = 0;
    const seen = new Set();
    for (;;) {
      const norm = normalizeTarget(current);
      if (!norm.ok) return fail(norm.reason, norm.detail);
      if (seen.has(norm.url)) return fail('too_many_redirects', 'redirect loop');
      seen.add(norm.url);

      const pub = await race(assertPublicHost(norm.host, counted, signal));
      if (budgetHit) return fail('budget_exhausted', 'subrequest limit reached');
      if (!pub.ok) {
        if (pub.reason === 'blocked_target') return fail('blocked_target', pub.detail);
        if (pub.reason === 'timeout') return fail('timeout', 'DNS lookup exceeded the deadline');
        return fail('upstream_error', pub.reason === 'no_answer' ? 'host did not resolve' : 'DNS lookup failed');
      }

      const res = await race(counted(norm.url, { method: 'GET', redirect: 'manual', headers: { ...OUTBOUND_HEADERS } }));

      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location) {
        res.body?.cancel().catch(() => {});
        let next;
        try {
          next = new URL(location, norm.url);
        } catch {
          chain.push({ url: norm.url, status: res.status });
          return fail('upstream_error', 'invalid redirect location');
        }
        /** @type {ChainEntry} */
        const entry = { url: norm.url, status: res.status, location: next.href };
        chain.push(entry);
        if (new URL(norm.url).protocol === 'https:' && next.protocol === 'http:') {
          entry.note = 'downgrade_blocked';
          return fail('blocked_target', 'https to http redirect not followed');
        }
        hops++;
        if (hops > limits.maxHops) return fail('too_many_redirects', 'too many redirects');
        current = next.href;
        continue;
      }

      chain.push({ url: norm.url, status: res.status });
      const contentType = res.headers.get('content-type') ?? '';
      const mime = contentType.split(';')[0].trim().toLowerCase();
      const wanted = kind === 'script'
        ? SCRIPT_TYPES.has(mime)
        : mime === '' || mime.startsWith('text/') || mime === 'application/xhtml+xml';

      /** @type {Record<string, string>} */
      const headers = {};
      // Set-Cookie is never returned; remember it only so the caller refuses to cache the response.
      const hadSetCookie = res.headers.has('set-cookie');
      for (const [k, v] of res.headers) {
        const name = k.toLowerCase();
        if (HEADER_ALLOWLIST.includes(name)) headers[name] = v;
      }

      let body = new Uint8Array(0);
      let truncated = false;
      if (wanted && res.body) {
        const cap = kind === 'script' ? limits.scriptBytes : limits.pageBytes;
        const reader = res.body.getReader();
        const parts = [];
        let total = 0;
        for (;;) {
          const { done, value } = await race(reader.read());
          if (done) break;
          if (total + value.length > cap) {
            parts.push(value.subarray(0, cap - total));
            total = cap;
            truncated = true;
            reader.cancel().catch(() => {});
            break;
          }
          parts.push(value);
          total += value.length;
        }
        body = new Uint8Array(total);
        let off = 0;
        for (const p of parts) { body.set(p, off); off += p.length; }
      } else {
        res.body?.cancel().catch(() => {});
      }

      return {
        ok: true, finalUrl: norm.url, chain, status: res.status, contentType,
        bytesRead: body.length, truncated, headers, body, subrequests, hadSetCookie,
      };
    }
  } catch (err) {
    return failFromThrown(err);
  } finally {
    clearTimeout(timer);
  }
}
