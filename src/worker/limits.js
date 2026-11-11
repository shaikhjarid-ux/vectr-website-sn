// Request-size limits and abuse-control constants for /api/fetch.
export const REQUEST_LIMITS = Object.freeze({
  maxBodyBytes: 8192,
  maxUrlLength: 4096,
  cacheTtlSeconds: 600,
  retryAfterSeconds: 60,
});

/**
 * Best-effort per-key rate limiter on the Cache API, used only when the Rate
 * Limiting binding is unavailable. Cache API entries are local to one data
 * centre and updates are not atomic, so this is a weaker control than the
 * binding: it slows casual abuse, it is not a security boundary.
 *
 * @param {{match(req: Request): Promise<Response | undefined>, put(req: Request, res: Response): Promise<void>}} cache
 * @param {{limit?: number, periodSeconds?: number, now?: () => number}} [opts]
 * @returns {{limit(o: {key: string}): Promise<{success: boolean}>}}
 */
export function createCacheLimiter(cache, opts = {}) {
  const max = opts.limit ?? 30;
  const period = opts.periodSeconds ?? 60;
  const now = opts.now ?? Date.now;
  return {
    async limit({ key }) {
      const nowSec = Math.floor(now() / 1000);
      const bucket = Math.floor(nowSec / period);
      const req = new Request(`https://ratelimit.internal/${encodeURIComponent(key)}/${bucket}`);
      const hit = await cache.match(req);
      const count = hit ? Number(await hit.text()) || 0 : 0;
      if (count >= max) return { success: false };
      const ttl = Math.max(1, (bucket + 1) * period - nowSec);
      await cache.put(req, new Response(String(count + 1), { headers: { 'cache-control': `public, max-age=${ttl}` } }));
      return { success: true };
    },
  };
}
