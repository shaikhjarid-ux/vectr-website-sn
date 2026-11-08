import { describe, it, expect } from 'vitest';
import { createBudget, runPool, DEFAULT_LIMITS } from '../../src/engine/budget.js';

describe('createBudget', () => {
  it('has the spec defaults', () => {
    expect(DEFAULT_LIMITS).toEqual({ pages: 7, scripts: 4, invocations: 11, parallel: 3, deadlineMs: 45000 });
  });
  it('refuses the 8th page', () => {
    const b = createBudget();
    for (let i = 0; i < 7; i++) expect(b.tryAcquire('page')).toBe(true);
    expect(b.tryAcquire('page')).toBe(false);
    expect(b.stats()).toEqual({ pages: 7, scripts: 0, invocations: 7 });
  });
  it('refuses the 5th script', () => {
    const b = createBudget();
    for (let i = 0; i < 4; i++) expect(b.tryAcquire('script')).toBe(true);
    expect(b.tryAcquire('script')).toBe(false);
  });
  it('refuses the 12th invocation across kinds', () => {
    const b = createBudget({ pages: 20, scripts: 20 });
    for (let i = 0; i < 11; i++) expect(b.tryAcquire(i % 2 ? 'script' : 'page')).toBe(true);
    expect(b.tryAcquire('page')).toBe(false);
    expect(b.tryAcquire('script')).toBe(false);
    expect(b.stats().invocations).toBe(11);
  });
  it('7 pages plus 4 scripts use exactly the 11 invocations', () => {
    const b = createBudget();
    for (let i = 0; i < 7; i++) b.tryAcquire('page');
    for (let i = 0; i < 4; i++) expect(b.tryAcquire('script')).toBe(true);
    expect(b.tryAcquire('script')).toBe(false);
  });
  it('reports the 45 s deadline from a fake clock', () => {
    let t = 1000;
    const b = createBudget({}, () => t);
    expect(b.deadlineReached()).toBe(false);
    expect(b.remainingMs()).toBe(45000);
    t += 44999;
    expect(b.deadlineReached()).toBe(false);
    t += 1;
    expect(b.deadlineReached()).toBe(true);
    expect(b.remainingMs()).toBe(0);
  });
});

describe('runPool', () => {
  it('never exceeds the concurrency limit and preserves order', async () => {
    let active = 0, peak = 0;
    const thunks = Array.from({ length: 12 }, (_, i) => async () => {
      active++; peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 2 + (i % 3)));
      active--;
      return i;
    });
    const out = await runPool(thunks, 3);
    expect(out).toEqual(Array.from({ length: 12 }, (_, i) => i));
    expect(peak).toBe(3);
  });
  it('handles empty input and limits above the item count', async () => {
    expect(await runPool([], 3)).toEqual([]);
    expect(await runPool([async () => 1], 3)).toEqual([1]);
  });
  it('rejects with the first error after all thunks settle', async () => {
    const ran = [];
    const thunks = [async () => { ran.push(0); throw new Error('boom'); }, async () => { ran.push(1); return 1; }];
    await expect(runPool(thunks, 1)).rejects.toThrow('boom');
    expect(ran).toEqual([0, 1]);
  });
});
