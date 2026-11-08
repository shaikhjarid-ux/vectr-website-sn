import { describe, it, expect, vi } from 'vitest';
import { resolveHost, assertPublicHost } from '../../src/worker/resolve.js';

const json = (body, status = 200) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
const ans = (type, data, name = 'x.com') => ({ name, type, TTL: 60, data });

/** fetchFn answering by record type from a table: {A: body, AAAA: body} */
function dohMock(table) {
  return vi.fn(async (url) => {
    const u = new URL(url);
    const type = u.searchParams.get('type');
    const entry = table[type];
    if (entry instanceof Error) throw entry;
    return typeof entry === 'function' ? entry() : json(entry);
  });
}

describe('resolveHost', () => {
  it('queries A and AAAA from cloudflare-dns.com with the dns-json accept header', async () => {
    const f = dohMock({ A: { Status: 0, Answer: [ans(1, '93.184.216.34')] }, AAAA: { Status: 0 } });
    const r = await resolveHost('x.com', f);
    expect(r).toEqual({ ok: true, addresses: ['93.184.216.34'], subrequests: 2 });
    expect(f).toHaveBeenCalledTimes(2);
    const urls = f.mock.calls.map((c) => c[0]).sort();
    expect(urls).toEqual([
      'https://cloudflare-dns.com/dns-query?name=x.com&type=A',
      'https://cloudflare-dns.com/dns-query?name=x.com&type=AAAA',
    ]);
    for (const c of f.mock.calls) expect(new Headers(c[1].headers).get('accept')).toBe('application/dns-json');
  });

  it('collects answers behind a CNAME chain (types 1 and 28 only)', async () => {
    const f = dohMock({
      A: { Status: 0, Answer: [ans(5, 'cdn.example.net.'), ans(1, '8.8.8.8', 'cdn.example.net')] },
      AAAA: { Status: 0, Answer: [ans(28, '2606:4700:4700::1111', 'cdn.example.net')] },
    });
    const r = await resolveHost('x.com', f);
    expect(r.ok && r.addresses.sort()).toEqual(['2606:4700:4700::1111', '8.8.8.8']);
  });

  it('NXDOMAIN gives no_answer', async () => {
    const f = dohMock({ A: { Status: 3 }, AAAA: { Status: 3 } });
    expect(await resolveHost('x.com', f)).toMatchObject({ ok: false, reason: 'no_answer', subrequests: 2 });
  });

  it('HTTP 500 and malformed JSON give doh_failed', async () => {
    expect(await resolveHost('x.com', dohMock({ A: () => json('boom', 500), AAAA: { Status: 0 } }))).toMatchObject({ ok: false, reason: 'doh_failed' });
    expect(await resolveHost('x.com', dohMock({ A: () => json('{not json'), AAAA: { Status: 0 } }))).toMatchObject({ ok: false, reason: 'doh_failed' });
  });

  it('SERVFAIL (Status 2) gives doh_failed', async () => {
    expect(await resolveHost('x.com', dohMock({ A: { Status: 2 }, AAAA: { Status: 0 } }))).toMatchObject({ ok: false, reason: 'doh_failed' });
  });
});

describe('assertPublicHost', () => {
  it('blocks a CNAME chain ending in a private A record', async () => {
    const f = dohMock({ A: { Status: 0, Answer: [ans(5, 'internal.example.net.'), ans(1, '10.0.0.1', 'internal.example.net')] }, AAAA: { Status: 0 } });
    expect(await assertPublicHost('x.com', f)).toMatchObject({ ok: false, reason: 'blocked_target', subrequests: 2 });
  });

  it('blocks when A is public but AAAA is ::1', async () => {
    const f = dohMock({ A: { Status: 0, Answer: [ans(1, '8.8.8.8')] }, AAAA: { Status: 0, Answer: [ans(28, '::1')] } });
    expect(await assertPublicHost('x.com', f)).toMatchObject({ ok: false, reason: 'blocked_target' });
  });

  it('allows an all-public answer set', async () => {
    const f = dohMock({ A: { Status: 0, Answer: [ans(1, '8.8.8.8')] }, AAAA: { Status: 0 } });
    expect(await assertPublicHost('x.com', f)).toEqual({ ok: true, subrequests: 2 });
  });

  it('fails closed on doh_failed and no_answer', async () => {
    const bad = dohMock({ A: () => json('x', 500), AAAA: { Status: 0 } });
    expect(await assertPublicHost('x.com', bad)).toMatchObject({ ok: false, reason: 'doh_failed' });
    const none = dohMock({ A: { Status: 3 }, AAAA: { Status: 3 } });
    expect(await assertPublicHost('x.com', none)).toMatchObject({ ok: false, reason: 'no_answer' });
  });

  it('skips DoH for IP-literal hosts (0 subrequests) and still checks them', async () => {
    const f = vi.fn();
    expect(await assertPublicHost('8.8.8.8', f)).toEqual({ ok: true, subrequests: 0 });
    expect(await assertPublicHost('10.0.0.1', f)).toMatchObject({ ok: false, reason: 'blocked_target', subrequests: 0 });
    expect(f).not.toHaveBeenCalled();
  });

  it('an already-aborted signal gives timeout and both requests receive the signal', async () => {
    const ctl = new AbortController();
    ctl.abort();
    const f = vi.fn(async (_u, init) => { if (init.signal.aborted) throw new DOMException('aborted', 'AbortError'); return json({ Status: 0 }); });
    const r = await assertPublicHost('x.com', f, ctl.signal);
    expect(r).toMatchObject({ ok: false, reason: 'timeout' });
    expect(f).toHaveBeenCalledTimes(2);
    for (const c of f.mock.calls) expect(c[1].signal).toBe(ctl.signal);
  });

  it('a later abort gives timeout', async () => {
    const ctl = new AbortController();
    const f = vi.fn((_u, init) => new Promise((_res, rej) => init.signal.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')))));
    const p = assertPublicHost('x.com', f, ctl.signal);
    setTimeout(() => ctl.abort(), 5);
    expect(await p).toMatchObject({ ok: false, reason: 'timeout' });
    for (const c of f.mock.calls) expect(c[1].signal).toBe(ctl.signal);
  });
});
