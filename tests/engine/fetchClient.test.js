import { describe, it, expect, vi } from 'vitest';
import { createFetchClient } from '../../src/engine/fetchClient.js';
import { encodeMeta } from '../../src/worker/headers.js';

const meta = (o = {}) => ({ finalUrl: 'https://x.com/', chain: [{ url: 'https://x.com/', status: 200 }], status: 200, contentType: 'text/html; charset=utf-8', bytesRead: 5, truncated: false, cache: 'miss', fetchedAt: '2026-11-08T00:00:00Z', headers: { server: 'nginx' }, ...o });
const ok = (body, m = meta()) => new Response(body, { status: 200, headers: { 'x-audit-meta': encodeMeta(m), 'content-type': 'application/octet-stream' } });

describe('createFetchClient', () => {
  it('posts to /api/fetch with credentials omit, JSON body and the abort signal', async () => {
    const f = vi.fn(async () => ok('hello'));
    const ctl = new AbortController();
    await createFetchClient({ fetchFn: f }).fetchDoc('https://x.com/', 'page', ctl.signal);
    const [url, init] = f.mock.calls[0];
    expect(url).toBe('/api/fetch');
    expect(init).toMatchObject({ method: 'POST', credentials: 'omit', signal: ctl.signal });
    expect(init.headers['content-type']).toBe('application/json');
    expect(JSON.parse(init.body)).toEqual({ url: 'https://x.com/', kind: 'page' });
  });
  it('decodes x-audit-meta and the body', async () => {
    const doc = await createFetchClient({ fetchFn: async () => ok('hello') }).fetchDoc('https://x.com/', 'page');
    expect(doc).toMatchObject({ finalUrl: 'https://x.com/', status: 200, contentType: 'text/html; charset=utf-8', bytesRead: 5, truncated: false, cache: 'miss', headers: { server: 'nginx' }, text: 'hello', charset: 'utf-8', isHtml: true, isBinary: false });
    expect(doc.chain).toHaveLength(1);
  });
  it('marks application/zip as binary and not html', async () => {
    const doc = await createFetchClient({ fetchFn: async () => ok('', meta({ contentType: 'application/zip', bytesRead: 0 })) }).fetchDoc('https://x.com/a.zip', 'page');
    expect(doc).toMatchObject({ isBinary: true, isHtml: false, text: '' });
  });
  it('treats javascript for kind script as neither html nor binary', async () => {
    const doc = await createFetchClient({ fetchFn: async () => ok('var a=1', meta({ contentType: 'application/javascript', bytesRead: 7 })) }).fetchDoc('https://x.com/a.js', 'script');
    expect(doc).toMatchObject({ isBinary: false, isHtml: false, text: 'var a=1' });
  });
  it('maps a 429 body to rate_limited', async () => {
    const f = async () => new Response(JSON.stringify({ error: 'rate_limited', detail: 'too many requests' }), { status: 429, headers: { 'content-type': 'application/json' } });
    expect(await createFetchClient({ fetchFn: f }).fetchDoc('https://x.com/', 'page')).toEqual({ error: 'rate_limited', detail: 'too many requests' });
  });
  it('keeps known error codes and carries the chain', async () => {
    const f = async () => new Response(JSON.stringify({ error: 'blocked_target', detail: 'nope', chain: [{ url: 'http://x.com/', status: 302 }] }), { status: 403 });
    expect(await createFetchClient({ fetchFn: f }).fetchDoc('http://x.com/', 'page')).toMatchObject({ error: 'blocked_target', chain: [{ url: 'http://x.com/', status: 302 }] });
  });
  it('maps unknown bodies, network errors and aborts to failures', async () => {
    const c1 = createFetchClient({ fetchFn: async () => new Response('<html>gateway</html>', { status: 502 }) });
    expect(await c1.fetchDoc('https://x.com/', 'page')).toMatchObject({ error: 'upstream_error' });
    const c2 = createFetchClient({ fetchFn: async () => { throw new TypeError('offline'); } });
    expect(await c2.fetchDoc('https://x.com/', 'page')).toMatchObject({ error: 'upstream_error' });
    const c3 = createFetchClient({ fetchFn: async () => { throw new DOMException('aborted', 'AbortError'); } });
    expect(await c3.fetchDoc('https://x.com/', 'page')).toMatchObject({ error: 'timeout' });
  });
  it('fails cleanly when the metadata header is missing or corrupt', async () => {
    const c1 = createFetchClient({ fetchFn: async () => new Response('x', { status: 200 }) });
    expect(await c1.fetchDoc('https://x.com/', 'page')).toMatchObject({ error: 'upstream_error' });
    const c2 = createFetchClient({ fetchFn: async () => new Response('x', { status: 200, headers: { 'x-audit-meta': '!!!' } }) });
    expect(await c2.fetchDoc('https://x.com/', 'page')).toMatchObject({ error: 'upstream_error' });
  });
});
