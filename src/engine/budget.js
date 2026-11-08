// Scan budgets (spec section 6) and a bounded-concurrency pool.

export const DEFAULT_LIMITS = Object.freeze({ pages: 7, scripts: 4, invocations: 11, parallel: 3, deadlineMs: 45000 });

/**
 * @param {Partial<typeof DEFAULT_LIMITS>} [limits]
 * @param {() => number} [now]
 */
export function createBudget(limits = {}, now = Date.now) {
  const L = { ...DEFAULT_LIMITS, ...limits };
  const started = now();
  let pages = 0, scripts = 0, invocations = 0;
  return {
    /** @param {'page' | 'script'} kind */
    tryAcquire(kind) {
      if (invocations >= L.invocations) return false;
      if (kind === 'page') { if (pages >= L.pages) return false; pages++; }
      else { if (scripts >= L.scripts) return false; scripts++; }
      invocations++;
      return true;
    },
    stats: () => ({ pages, scripts, invocations }),
    deadlineReached: () => now() - started >= L.deadlineMs,
    remainingMs: () => Math.max(0, L.deadlineMs - (now() - started)),
  };
}

/**
 * Runs thunks with at most `limit` in flight; results keep input order. If any
 * thunk throws, all others still run and the first error is rethrown.
 * @template T
 * @param {(() => Promise<T>)[]} thunks
 * @param {number} limit
 * @returns {Promise<T[]>}
 */
export async function runPool(thunks, limit) {
  const results = new Array(thunks.length);
  let next = 0;
  let firstError;
  let failed = false;
  async function worker() {
    while (next < thunks.length) {
      const i = next++;
      try { results[i] = await thunks[i](); } catch (err) { if (!failed) { failed = true; firstError = err; } }
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, thunks.length)) }, worker));
  if (failed) throw firstError;
  return results;
}
