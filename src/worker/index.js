// Worker entry: handles /api/* only (static assets are served by the platform).
// Order: method, Origin, content type, size, JSON schema, rate limit, cache
// read, guarded fetch, cache write, response. Logs record counters and error
// codes only, never URLs, query strings or content.
import { fetchTarget } from './fetcher.js';
import { normalizeTarget } from './guard.js';
import { encodeMeta, decodeMeta, securityHeaders } from './headers.js';
import { REQUEST_LIMITS } from './limits.js';

const STATUS = {
  bad_request: 400, bad_url: 400, blocked_target: 403, rate_limited: 429,
  timeout: 504, too_many_redirects: 502, upstream_error: 502, budget_exhausted: 502,
};

function errorResponse(error, detail, { status, extra, headers } = {}) {
  return new Response(JSON.stringify({ error, detail, ...extra }), {
    status: status ?? STATUS[error] ?? 500,
    headers: { 'content-type': 'application/json', ...securityHeaders(), ...headers },
  });
}

async function readCapped(request, cap) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > cap) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) { reader.cancel().catch(() => {}); return null; }
    parts.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { all.set(p, off); off += p.length; }
  return new TextDecoder().decode(all);
}

/**
 * @param {Request} request
 * @returns {Promise<{ok: true, body: {url: string, kind: 'page' | 'script'}} | {ok: false, status: number, error: string, detail?: string}>}
 */
export async function validateRequest(request) {
  if (request.method !== 'POST') return { ok: false, status: 405, error: 'bad_request', detail: 'POST only' };
  if (request.headers.get('origin') !== new URL(request.url).origin) {
    return { ok: false, status: 403, error: 'bad_request', detail: 'origin not allowed' };
  }
  const mime = (request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
  if (mime !== 'application/json') return { ok: false, status: 415, error: 'bad_request', detail: 'content type must be application/json' };
  const text = await readCapped(request, REQUEST_LIMITS.maxBodyBytes);
  if (text === null) return { ok: false, status: 413, error: 'bad_request', detail: 'request body too large' };
  let body;
  try { body = JSON.parse(text); } catch { return { ok: false, status: 400, error: 'bad_request', detail: 'invalid JSON' }; }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return { ok: false, status: 400, error: 'bad_request', detail: 'body must be an object' };
  if (Object.keys(body).some((k) => k !== 'url' && k !== 'kind')) return { ok: false, status: 400, error: 'bad_request', detail: 'unknown field' };
  if (typeof body.url !== 'string' || body.url === '') return { ok: false, status: 400, error: 'bad_request', detail: 'url required' };
  if (body.url.length > REQUEST_LIMITS.maxUrlLength) return { ok: false, status: 400, error: 'bad_request', detail: 'url too long' };
  if (body.kind !== 'page' && body.kind !== 'script') return { ok: false, status: 400, error: 'bad_request', detail: 'kind must be page or script' };
  return { ok: true, body: { url: body.url, kind: body.kind } };
}

const NOT_CACHEABLE = /(?:^|[\s,])(?:no-store|private)(?:[\s,=]|$)/i;

function getCache() {
  try { return globalThis.caches?.default ?? null; } catch { return null; }
}

function log(env, fields) {
  console.log(JSON.stringify({ event: 'fetch', env: env?.ENVIRONMENT, ...fields }));
}

/**
 * @param {{fetchFn?: typeof fetch}} [deps]
 */
export function createHandler(deps = {}) {
  const fetchFn = deps.fetchFn ?? ((input, init) => fetch(input, init));

  return async function handle(request, env, ctx) {
    const { pathname } = new URL(request.url);
    if (!pathname.startsWith('/api/')) return new Response('Not found', { status: 404 });
    if (pathname !== '/api/fetch') return errorResponse('bad_request', 'unknown endpoint', { status: 404 });

    const valid = await validateRequest(request);
    if (!valid.ok) {
      log(env, { outcome: valid.error, status: valid.status });
      return errorResponse(valid.error, valid.detail ?? 'invalid request', { status: valid.status, headers: valid.status === 405 ? { allow: 'POST' } : undefined });
    }
    const { url, kind } = valid.body;

    try {
      const key = request.headers.get('cf-connecting-ip') ?? 'unknown';
      const verdict = await env.FETCH_LIMITER.limit({ key });
      if (!verdict.success) {
        log(env, { outcome: 'rate_limited' });
        return errorResponse('rate_limited', 'too many requests', { headers: { 'retry-after': String(REQUEST_LIMITS.retryAfterSeconds) } });
      }
    } catch {
      log(env, { outcome: 'limiter_unavailable' });
      return errorResponse('upstream_error', 'rate limiter unavailable', { status: 503 });
    }

    const norm = normalizeTarget(url);
    const cache = norm.ok ? getCache() : null;
    const cacheKey = norm.ok ? new Request(`https://cache.internal/fetch/${kind}/${norm.url}`) : null;

    if (cache && cacheKey) {
      try {
        const hit = await cache.match(cacheKey);
        const stored = hit?.headers.get('x-audit-meta');
        if (hit && stored) {
          const meta = { ...decodeMeta(stored), cache: 'hit' };
          log(env, { outcome: 'ok', cache: 'hit' });
          return new Response(await hit.arrayBuffer(), {
            status: 200,
            headers: { 'content-type': 'application/octet-stream', ...securityHeaders(), 'x-audit-meta': encodeMeta(meta) },
          });
        }
      } catch { /* cache failures are never scan failures */ }
    }

    let outcome;
    try {
      outcome = await fetchTarget(url, { kind, fetchFn });
    } catch {
      outcome = { ok: false, error: 'upstream_error', detail: 'unexpected error', chain: [] };
    }
    if (!outcome.ok) {
      log(env, { outcome: outcome.error });
      return errorResponse(outcome.error, outcome.detail, { extra: { chain: outcome.chain } });
    }

    const meta = {
      finalUrl: outcome.finalUrl,
      chain: outcome.chain,
      status: outcome.status,
      contentType: outcome.contentType,
      bytesRead: outcome.bytesRead,
      truncated: outcome.truncated,
      cache: 'miss',
      fetchedAt: new Date().toISOString(),
      headers: outcome.headers,
    };

    const cacheControl = outcome.headers['cache-control'] ?? '';
    if (cache && cacheKey && !outcome.hadSetCookie && !NOT_CACHEABLE.test(cacheControl)) {
      const entry = new Response(outcome.body, {
        status: 200,
        headers: {
          'content-type': 'application/octet-stream',
          'cache-control': `public, max-age=${REQUEST_LIMITS.cacheTtlSeconds}`,
          'x-audit-meta': encodeMeta(meta),
        },
      });
      ctx.waitUntil(cache.put(cacheKey, entry).catch(() => {}));
    }

    log(env, { outcome: 'ok', cache: 'miss', subrequests: outcome.subrequests });
    return new Response(outcome.body, {
      status: 200,
      headers: { 'content-type': 'application/octet-stream', ...securityHeaders(), 'x-audit-meta': encodeMeta(meta) },
    });
  };
}

const handler = createHandler();

export default {
  /** @param {Request} request @param {{FETCH_LIMITER: {limit(o: {key: string}): Promise<{success: boolean}>}, ENVIRONMENT: string}} env @param {ExecutionContext} ctx */
  fetch(request, env, ctx) {
    return handler(request, env, ctx);
  },
};
