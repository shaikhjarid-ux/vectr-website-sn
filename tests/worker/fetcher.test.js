import { describe, it, expect, vi, afterEach } from 'vitest';
import { fetchTarget, LIMITS, HEADER_ALLOWLIST } from '../../src/worker/fetcher.js';

const DOH = 'https://cloudflare-dns.com/dns-query';
const dohAnswer = (url) => {
  const type = new URL(url).searchParams.get('type');
  return new Response(JSON.stringify(type === 'A' ? { Status: 0, Answer: [{ name: 'x', type: 1, TTL: 1, data: '93.184.216.34' }] } : { Status: 0 }));
};
const html = (body = '<html></html>', headers = {}) => new Response(body, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
const redirect = (to, status = 302) => new Response(null, { status, headers: { location: to } });

/** Router: DoH answers public IPs; other URLs come from `routes` (value or function). */
function router(routes) {
  const calls = [];
  const fn = vi.fn(async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).startsWith(DOH)) return dohAnswer(String(url));
    const r = routes[String(url)];
    if (r === undefined) throw new Error(`unrouted ${url}`);
    return typeof r === 'function' ? r(init) : r.clone();
  });
  fn.calls = calls;
  return fn;
}
const upstream = (fn) => fn.calls.filter((c) => !c.url.startsWith(DOH));

afterEach(() => vi.useRealTimers());

describe('constants', () => {
  it('match the spec', () => {
    expect(LIMITS).toEqual({ maxHops: 5, timeoutMs: 8000, pageBytes: 1048576, scriptBytes: 262144, subrequestAbort: 40 });
    expect(HEADER_ALLOWLIST).toEqual(expect.arrayContaining(['content-type', 'content-disposition', 'content-length', 'content-encoding', 'cache-control', 'etag', 'last-modified', 'server', 'x-powered-by', 'location']));
    expect(HEADER_ALLOWLIST).not.toContain('set-cookie');
    expect(HEADER_ALLOWLIST).not.toContain('authorization');
  });
});

describe('request shape', () => {
  it('is GET, redirect manual, with exactly user-agent, accept, accept-language', async () => {
    const f = router({ 'https://x.com/': html() });
    const r = await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    expect(r.ok).toBe(true);
    const [c] = upstream(f);
    expect(c.init.method).toBe('GET');
    expect(c.init.redirect).toBe('manual');
    expect(Object.keys(c.init.headers).sort()).toEqual(['accept', 'accept-language', 'user-agent']);
    expect(c.init.body).toBeUndefined();
    expect(c.init.credentials).toBeUndefined();
  });
  it('returns the final URL, chain, status and decoded body bytes', async () => {
    const f = router({ 'https://x.com/': html('hello') });
    const r = await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: true, finalUrl: 'https://x.com/', status: 200, truncated: false, bytesRead: 5 });
    expect(new TextDecoder().decode(r.body)).toBe('hello');
    expect(r.chain).toEqual([{ url: 'https://x.com/', status: 200 }]);
    expect(r.subrequests).toBe(3); // 2 DoH + 1 fetch
  });
});

describe('redirects', () => {
  it('follows redirects, resolving Location against the current URL', async () => {
    const f = router({ 'https://x.com/a': redirect('/b'), 'https://x.com/b': html('ok') });
    const r = await fetchTarget('https://x.com/a', { kind: 'page', fetchFn: f });
    expect(r.ok && r.finalUrl).toBe('https://x.com/b');
    expect(r.chain).toEqual([{ url: 'https://x.com/a', status: 302, location: 'https://x.com/b' }, { url: 'https://x.com/b', status: 200 }]);
  });
  it('blocks a redirect to a private address and records the chain', async () => {
    // Starts at http:// so the private-address check, not the downgrade rule, is what blocks it.
    const f = router({ 'http://x.com/': redirect('http://10.0.0.1/') });
    const r = await fetchTarget('http://x.com/', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: false, error: 'blocked_target' });
    expect(r.chain).toEqual([{ url: 'http://x.com/', status: 302, location: 'http://10.0.0.1/' }]);
    expect(upstream(f)).toHaveLength(1);
  });
  it('blocks a redirect to cloud metadata', async () => {
    const f = router({ 'http://x.com/': redirect('http://169.254.169.254/latest/meta-data/') });
    const r = await fetchTarget('http://x.com/', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: false, error: 'blocked_target' });
    expect(r.chain.at(-1).note).toBeUndefined();
    expect(upstream(f)).toHaveLength(1);
  });
  it('detects loops', async () => {
    const f = router({ 'https://x.com/a': redirect('/b'), 'https://x.com/b': redirect('/a') });
    expect(await fetchTarget('https://x.com/a', { kind: 'page', fetchFn: f })).toMatchObject({ ok: false, error: 'too_many_redirects' });
  });
  it('allows 5 redirects but not 6', async () => {
    const chain = (n) => {
      const routes = {};
      for (let i = 0; i < n; i++) routes[`https://x.com/${i}`] = redirect(`/${i + 1}`);
      routes[`https://x.com/${n}`] = html('end');
      return routes;
    };
    expect((await fetchTarget('https://x.com/0', { kind: 'page', fetchFn: router(chain(5)) })).ok).toBe(true);
    expect(await fetchTarget('https://x.com/0', { kind: 'page', fetchFn: router(chain(6)) })).toMatchObject({ ok: false, error: 'too_many_redirects' });
  });
  it('does not follow https to http downgrades', async () => {
    const f = router({ 'https://x.com/': redirect('http://y.com/') });
    const r = await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: false, error: 'blocked_target' });
    expect(r.chain.at(-1).note).toBe('downgrade_blocked');
    expect(upstream(f)).toHaveLength(1);
  });
  it('treats a redirect without Location as a final response', async () => {
    const f = router({ 'https://x.com/': new Response('x', { status: 301, headers: { 'content-type': 'text/html' } }) });
    expect(await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f })).toMatchObject({ ok: true, status: 301 });
  });
});

describe('body handling', () => {
  const big = (total, chunk = 65536) => {
    let sent = 0;
    return new ReadableStream({
      pull(ctl) {
        if (sent >= total) return ctl.close();
        const n = Math.min(chunk, total - sent);
        sent += n;
        ctl.enqueue(new Uint8Array(n).fill(97));
      },
    });
  };
  it('caps on bytes actually read, not Content-Length', async () => {
    const f = router({ 'https://x.com/': () => new Response(big(2 * 1048576), { status: 200, headers: { 'content-type': 'text/html', 'content-length': '10' } }) });
    const r = await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: true, truncated: true, bytesRead: 1048576 });
    expect(r.body.length).toBe(1048576);
  });
  it('is not truncated when the body is exactly the cap', async () => {
    const f = router({ 'https://x.com/': () => new Response(big(1048576), { status: 200, headers: { 'content-type': 'text/html' } }) });
    expect(await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f })).toMatchObject({ ok: true, truncated: false, bytesRead: 1048576 });
  });
  it('uses the 256 KiB cap for scripts', async () => {
    const f = router({ 'https://x.com/a.js': () => new Response(big(1048576), { status: 200, headers: { 'content-type': 'application/javascript' } }) });
    expect(await fetchTarget('https://x.com/a.js', { kind: 'script', fetchFn: f })).toMatchObject({ ok: true, truncated: true, bytesRead: 262144 });
  });
  it('never returns Set-Cookie or Authorization, but keeps allowlisted headers', async () => {
    const f = router({ 'https://x.com/': html('x', { 'set-cookie': 'sid=SECRET', authorization: 'Bearer SECRET', 'x-secret': 'SECRET', server: 'nginx', 'content-disposition': 'attachment; filename="a.exe"' }) });
    const r = await fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    expect(JSON.stringify(r.headers)).not.toContain('SECRET');
    expect(r.headers).toMatchObject({ server: 'nginx', 'content-disposition': 'attachment; filename="a.exe"' });
    expect(Object.keys(r.headers).every((k) => HEADER_ALLOWLIST.includes(k))).toBe(true);
  });
  it('returns an empty body for a binary page and preserves the content type', async () => {
    const f = router({ 'https://x.com/a.zip': new Response('PKzip', { status: 200, headers: { 'content-type': 'application/zip' } }) });
    const r = await fetchTarget('https://x.com/a.zip', { kind: 'page', fetchFn: f });
    expect(r).toMatchObject({ ok: true, contentType: 'application/zip', bytesRead: 0, truncated: false });
    expect(r.body.length).toBe(0);
  });
  it('returns a script body only for javascript content types', async () => {
    const js = new Response('var a=1', { status: 200, headers: { 'content-type': 'text/javascript; charset=utf-8' } });
    const f1 = router({ 'https://x.com/a.js': js });
    expect((await fetchTarget('https://x.com/a.js', { kind: 'script', fetchFn: f1 })).body.length).toBe(7);
    const f2 = router({ 'https://x.com/a.js': html('<html>') });
    expect((await fetchTarget('https://x.com/a.js', { kind: 'script', fetchFn: f2 })).body.length).toBe(0);
  });
});

describe('deadlines and budgets', () => {
  it('times out a fetch that never resolves (8 s shared deadline)', async () => {
    vi.useFakeTimers();
    const f = vi.fn((url) => (String(url).startsWith(DOH) ? Promise.resolve(dohAnswer(String(url))) : new Promise(() => {})));
    const p = fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    await vi.advanceTimersByTimeAsync(8001);
    expect(await p).toMatchObject({ ok: false, error: 'timeout' });
  });
  it('times out when the DoH lookup hangs past the deadline', async () => {
    vi.useFakeTimers();
    const f = vi.fn(() => new Promise(() => {}));
    const p = fetchTarget('https://x.com/', { kind: 'page', fetchFn: f });
    await vi.advanceTimersByTimeAsync(8001);
    expect(await p).toMatchObject({ ok: false, error: 'timeout' });
  });
  it('shares one deadline signal across DoH and upstream calls on every hop', async () => {
    const f = router({ 'https://x.com/a': redirect('https://y.com/b'), 'https://y.com/b': html() });
    await fetchTarget('https://x.com/a', { kind: 'page', fetchFn: f });
    const signals = new Set(f.calls.map((c) => c.init.signal));
    expect(signals.size).toBe(1);
    expect([...signals][0]).toBeInstanceOf(AbortSignal);
    expect(f.calls.filter((c) => c.url.startsWith(DOH))).toHaveLength(4); // 2 hosts x (A + AAAA)
  });
  it('aborts with budget_exhausted at the subrequest limit', async () => {
    const f = router({ 'https://x.com/a': redirect('/b'), 'https://x.com/b': redirect('/c'), 'https://x.com/c': html() });
    const r = await fetchTarget('https://x.com/a', { kind: 'page', fetchFn: f, limits: { subrequestAbort: 4 } });
    expect(r).toMatchObject({ ok: false, error: 'budget_exhausted' });
    expect(f.calls.length).toBeLessThanOrEqual(4);
  });
});

describe('error mapping', () => {
  it('maps guard failures and lookup failures to error codes', async () => {
    expect(await fetchTarget('http://localhost/', { kind: 'page', fetchFn: router({}) })).toMatchObject({ ok: false, error: 'blocked_target' });
    expect(await fetchTarget('ftp://x.com/', { kind: 'page', fetchFn: router({}) })).toMatchObject({ ok: false, error: 'bad_url' });
    const nx = vi.fn(async () => new Response(JSON.stringify({ Status: 3 })));
    expect(await fetchTarget('https://nope.com/', { kind: 'page', fetchFn: nx })).toMatchObject({ ok: false, error: 'upstream_error' });
    const boom = router({ 'https://x.com/': () => { throw new TypeError('network'); } });
    expect(await fetchTarget('https://x.com/', { kind: 'page', fetchFn: boom })).toMatchObject({ ok: false, error: 'upstream_error' });
  });
});
