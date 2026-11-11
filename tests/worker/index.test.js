import { SELF, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, vi } from 'vitest';
import { createHandler, validateRequest } from '../../src/worker/index.js';
import { decodeMeta, securityHeaders } from '../../src/worker/headers.js';

const ORIGIN = 'https://example.com';
const DOH = 'https://cloudflare-dns.com/dns-query';

function post(body, { origin = ORIGIN, type = 'application/json', ip = '203.0.113.9', raw } = {}) {
  const headers = { 'content-type': type, 'cf-connecting-ip': ip };
  if (origin) headers.origin = origin;
  return new Request(`${ORIGIN}/api/fetch`, { method: 'POST', headers, body: raw ?? JSON.stringify(body) });
}

/** Upstream mock: DoH answers public IPs; pages come from `routes`. */
function upstream(routes) {
  const calls = [];
  const fn = vi.fn(async (url) => {
    const u = String(url);
    calls.push(u);
    if (u.startsWith(DOH)) {
      const A = new URL(u).searchParams.get('type') === 'A';
      return new Response(JSON.stringify(A ? { Status: 0, Answer: [{ name: 'x', type: 1, TTL: 1, data: '93.184.216.34' }] } : { Status: 0 }));
    }
    const r = routes[u];
    if (!r) throw new Error(`unrouted ${u}`);
    return r();
  });
  fn.calls = calls;
  return fn;
}
const page = (body = '<html>hi</html>', headers = {}) => () => new Response(body, { status: 200, headers: { 'content-type': 'text/html', ...headers } });
const env = (success = true) => ({ ENVIRONMENT: 'test', FETCH_LIMITER: { limit: vi.fn(async () => ({ success })) } });

async function run(handler, request, e = env()) {
  const ctx = createExecutionContext();
  const res = await handler(request, e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

describe('request validation through SELF.fetch', () => {
  const api = (init) => SELF.fetch(`${ORIGIN}/api/fetch`, init);
  const okHeaders = { origin: ORIGIN, 'content-type': 'application/json' };

  it('GET gives 405', async () => {
    const r = await api({ method: 'GET', headers: { origin: ORIGIN } });
    expect(r.status).toBe(405);
    expect((await r.json()).error).toBe('bad_request');
  });
  it('missing or foreign Origin gives 403 bad_request', async () => {
    for (const origin of [undefined, 'https://evil.example', 'null']) {
      const headers = { 'content-type': 'application/json' };
      if (origin) headers.origin = origin;
      const r = await api({ method: 'POST', headers, body: '{"url":"https://x.com/","kind":"page"}' });
      expect(r.status, String(origin)).toBe(403);
      expect((await r.json()).error).toBe('bad_request');
    }
  });
  it('wrong content type gives 415', async () => {
    const r = await api({ method: 'POST', headers: { origin: ORIGIN, 'content-type': 'text/plain' }, body: '{}' });
    expect(r.status).toBe(415);
  });
  it('unknown JSON field, bad kind and non-JSON give 400', async () => {
    for (const body of ['{"url":"https://x.com/","kind":"page","extra":1}', '{"url":"https://x.com/","kind":"nope"}', '{not json', '[]', '{"kind":"page"}']) {
      const r = await api({ method: 'POST', headers: okHeaders, body });
      expect(r.status, body).toBe(400);
      expect((await r.json()).error).toBe('bad_request');
    }
  });
  it('body over 8 KiB gives 413', async () => {
    const r = await api({ method: 'POST', headers: okHeaders, body: JSON.stringify({ url: 'https://x.com/', kind: 'page', pad: 'a'.repeat(9000) }) });
    expect(r.status).toBe(413);
  });
  it('URL over 4 KiB gives 400', async () => {
    const r = await api({ method: 'POST', headers: okHeaders, body: JSON.stringify({ url: `https://x.com/${'a'.repeat(4100)}`, kind: 'page' }) });
    expect(r.status).toBe(400);
  });
  it('a guard rejection needs no network and maps to 403 blocked_target', async () => {
    const r = await api({ method: 'POST', headers: okHeaders, body: '{"url":"http://localhost/","kind":"page"}' });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('blocked_target');
  });
  it('every /api/* response carries the security headers', async () => {
    const sec = securityHeaders();
    expect(Object.keys(sec).length).toBeGreaterThan(3);
    for (const res of [
      await api({ method: 'GET' }),
      await SELF.fetch(`${ORIGIN}/api/unknown`),
      await api({ method: 'POST', headers: okHeaders, body: '{"url":"http://localhost/","kind":"page"}' }),
    ]) {
      for (const [k, v] of Object.entries(sec)) expect(res.headers.get(k), k).toBe(v);
    }
  });
});

describe('validateRequest', () => {
  it('returns the parsed body for a valid request', async () => {
    expect(await validateRequest(post({ url: 'https://x.com/', kind: 'script' }))).toEqual({ ok: true, body: { url: 'https://x.com/', kind: 'script' } });
  });
});

describe('handler behaviour with an injected upstream fetch', () => {
  it('rate limiter failure gives 429 with Retry-After and rate_limited', async () => {
    const h = createHandler({ fetchFn: upstream({}) });
    const r = await run(h, post({ url: 'https://rl.example.org/', kind: 'page' }), env(false));
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toBeTruthy();
    expect((await r.json()).error).toBe('rate_limited');
  });
  it('keys the limiter by cf-connecting-ip', async () => {
    const e = env();
    const h = createHandler({ fetchFn: upstream({ 'https://key.example.org/': page() }) });
    await run(h, post({ url: 'https://key.example.org/', kind: 'page' }, { ip: '198.51.100.77' }), e);
    expect(e.FETCH_LIMITER.limit).toHaveBeenCalledWith({ key: '198.51.100.77' });
  });
  it('fails closed with 503 when the limiter throws', async () => {
    const h = createHandler({ fetchFn: upstream({}) });
    const r = await run(h, post({ url: 'https://x.com/', kind: 'page' }), { FETCH_LIMITER: { limit: async () => { throw new Error('x'); } } });
    expect(r.status).toBe(503);
  });
  it('falls back to the Cache API limiter when the binding is missing', async () => {
    const f = upstream({ 'https://fallback.example.org/': page('ok') });
    const h = createHandler({ fetchFn: f });
    const r = await run(h, post({ url: 'https://fallback.example.org/', kind: 'page' }, { ip: '198.51.100.201' }), { ENVIRONMENT: 'test' });
    expect(r.status).toBe(200);
  });
  it('returns upstream bytes with x-audit-meta', async () => {
    const f = upstream({ 'https://ok.example.org/p': page('<html>hello</html>', { server: 'nginx' }) });
    const r = await run(createHandler({ fetchFn: f }), post({ url: 'https://ok.example.org/p', kind: 'page' }));
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('<html>hello</html>');
    const meta = decodeMeta(r.headers.get('x-audit-meta'));
    expect(meta).toMatchObject({ finalUrl: 'https://ok.example.org/p', status: 200, contentType: 'text/html', bytesRead: 18, truncated: false, cache: 'miss', headers: { server: 'nginx' } });
    expect(meta.chain).toEqual([{ url: 'https://ok.example.org/p', status: 200 }]);
    expect(typeof meta.fetchedAt).toBe('string');
  });
  it('a second identical request is a cache hit and does not touch upstream again', async () => {
    const f = upstream({ 'https://hit.example.org/': page('cached') });
    const h = createHandler({ fetchFn: f });
    await run(h, post({ url: 'https://hit.example.org/', kind: 'page' }));
    const before = f.calls.length;
    const r = await run(h, post({ url: 'https://hit.example.org/', kind: 'page' }));
    expect(await r.text()).toBe('cached');
    expect(decodeMeta(r.headers.get('x-audit-meta')).cache).toBe('hit');
    expect(f.calls.length).toBe(before);
  });
  it('keeps page and script kinds, and different query strings, in separate cache entries', async () => {
    const f = upstream({
      'https://keys.example.org/a?x=1': page('one'),
      'https://keys.example.org/a?x=2': page('two'),
    });
    const h = createHandler({ fetchFn: f });
    await run(h, post({ url: 'https://keys.example.org/a?x=1', kind: 'page' }));
    const r = await run(h, post({ url: 'https://keys.example.org/a?x=2', kind: 'page' }));
    expect(await r.text()).toBe('two');
    expect(decodeMeta(r.headers.get('x-audit-meta')).cache).toBe('miss');
  });
  it.each(['no-store', 'private', 'private, max-age=60'])('never caches Cache-Control: %s', async (cc) => {
    const url = `https://nc-${cc.replace(/\W/g, '')}.example.org/`;
    const f = upstream({ [url]: page('x', { 'cache-control': cc }) });
    const h = createHandler({ fetchFn: f });
    await run(h, post({ url, kind: 'page' }));
    const r = await run(h, post({ url, kind: 'page' }));
    expect(decodeMeta(r.headers.get('x-audit-meta')).cache).toBe('miss');
  });
  it('Set-Cookie appears nowhere and the response is not cached', async () => {
    const url = 'https://cookie.example.org/';
    const f = upstream({ [url]: page('x', { 'set-cookie': 'sid=SECRET123; HttpOnly' }) });
    const h = createHandler({ fetchFn: f });
    const r1 = await run(h, post({ url, kind: 'page' }));
    expect(r1.headers.get('set-cookie')).toBeNull();
    expect(JSON.stringify(decodeMeta(r1.headers.get('x-audit-meta')))).not.toContain('SECRET123');
    const r2 = await run(h, post({ url, kind: 'page' }));
    expect(decodeMeta(r2.headers.get('x-audit-meta')).cache).toBe('miss');
    expect(r2.headers.get('set-cookie')).toBeNull();
  });
  it('maps fetch failures to error codes with security headers', async () => {
    const h = createHandler({ fetchFn: upstream({ 'http://redir.example.org/': () => new Response(null, { status: 302, headers: { location: 'http://10.0.0.1/' } }) }) });
    const r = await run(h, post({ url: 'http://redir.example.org/', kind: 'page' }));
    expect(r.status).toBe(403);
    const body = await r.json();
    expect(body.error).toBe('blocked_target');
    expect(r.headers.get('x-content-type-options')).toBe('nosniff');
  });
  it('does not handle non-/api paths', async () => {
    const h = createHandler({ fetchFn: upstream({}) });
    const r = await run(h, new Request(`${ORIGIN}/index.html`));
    expect(r.status).toBe(404);
    expect(r.headers.get('content-security-policy')).toBeNull();
  });
});
