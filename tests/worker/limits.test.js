import { describe, it, expect } from 'vitest';
import { createCacheLimiter } from '../../src/worker/limits.js';

function fakeCache() {
  const store = new Map();
  return {
    store,
    async match(req) { const r = store.get(req.url); return r ? r.clone() : undefined; },
    async put(req, res) { store.set(req.url, res); },
  };
}

describe('createCacheLimiter', () => {
  it('allows 30 per 60 seconds per key by default, then refuses', async () => {
    const lim = createCacheLimiter(fakeCache(), { now: () => 120_000 });
    for (let i = 0; i < 30; i++) expect((await lim.limit({ key: 'a' })).success, `call ${i + 1}`).toBe(true);
    expect((await lim.limit({ key: 'a' })).success).toBe(false);
  });
  it('keeps keys independent', async () => {
    const lim = createCacheLimiter(fakeCache(), { limit: 1, now: () => 0 });
    expect((await lim.limit({ key: 'a' })).success).toBe(true);
    expect((await lim.limit({ key: 'a' })).success).toBe(false);
    expect((await lim.limit({ key: 'b' })).success).toBe(true);
  });
  it('starts a fresh window when the period rolls over', async () => {
    let t = 0;
    const lim = createCacheLimiter(fakeCache(), { limit: 2, periodSeconds: 60, now: () => t });
    expect((await lim.limit({ key: 'k' })).success).toBe(true);
    expect((await lim.limit({ key: 'k' })).success).toBe(true);
    expect((await lim.limit({ key: 'k' })).success).toBe(false);
    t = 61_000;
    expect((await lim.limit({ key: 'k' })).success).toBe(true);
  });
  it('is configurable and sets a TTL that ends with the window', async () => {
    const cache = fakeCache();
    const lim = createCacheLimiter(cache, { limit: 5, periodSeconds: 10, now: () => 3_000 });
    await lim.limit({ key: 'k' });
    const [res] = [...cache.store.values()];
    expect(res.headers.get('cache-control')).toBe('public, max-age=7');
  });
  it('encodes keys safely', async () => {
    const cache = fakeCache();
    await createCacheLimiter(cache, { now: () => 0 }).limit({ key: 'a b/c?d' });
    expect([...cache.store.keys()][0]).toBe('https://ratelimit.internal/a%20b%2Fc%3Fd/0');
  });
});
