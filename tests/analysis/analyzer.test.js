import { describe, it, expect, vi } from 'vitest';
import { createAnalyzer } from '../../src/analysis/analyzer.js';
import { analyzeScript } from '../../src/analysis/fold.js';

/** Fake Worker: `behavior(msg, worker)` decides how to answer a posted message. */
function fakeWorkerFactory(behaviors) {
  const workers = [];
  const factory = vi.fn(() => {
    const index = workers.length;
    const behavior = behaviors[Math.min(index, behaviors.length - 1)];
    const w = {
      index, terminated: false, onmessage: null, onerror: null, messages: [],
      postMessage(msg) { this.messages.push(msg); behavior(msg, this); },
      terminate: vi.fn(function () { this.terminated = true; }),
    };
    workers.push(w);
    return w;
  });
  factory.workers = workers;
  return factory;
}

const echo = (msg, w) => queueMicrotask(() => w.onmessage?.({ data: { id: msg.id, result: analyzeScript(msg.source) } }));
const silent = () => {};

describe('createAnalyzer', () => {
  it('resolves a normal reply with the analysis plus source and url', async () => {
    const a = createAnalyzer({ workerFactory: fakeWorkerFactory([echo]) });
    const r = await a.analyze("location = 'ht'+'tps://x.com/a.exe';", { source: 'external', url: 'https://x.com/a.js' });
    expect(r).toMatchObject({ status: 'ok', source: 'external', url: 'https://x.com/a.js' });
    expect(r.navigations[0].value).toBe('https://x.com/a.exe');
    const inline = await a.analyze('var a = 1;', { source: 'inline' });
    expect(inline).toMatchObject({ status: 'ok', source: 'inline' });
    expect('url' in inline).toBe(false);
  });

  it('reuses one worker across calls', async () => {
    const f = fakeWorkerFactory([echo]);
    const a = createAnalyzer({ workerFactory: f });
    await a.analyze('1', { source: 'inline' });
    await a.analyze('2', { source: 'inline' });
    expect(f).toHaveBeenCalledTimes(1);
  });

  it('terminates a silent worker after the timeout and uses a fresh one next time', async () => {
    const f = fakeWorkerFactory([silent, echo]);
    const a = createAnalyzer({ workerFactory: f, timeoutMs: 20 });
    const t = await a.analyze('while(1){}', { source: 'inline' });
    expect(t).toMatchObject({ status: 'unknown', reason: 'script_analysis_timeout', navigations: [], urls: [], source: 'inline' });
    expect(f.workers[0].terminate).toHaveBeenCalledTimes(1);
    const ok = await a.analyze('var b = 2;', { source: 'inline' });
    expect(ok.status).toBe('ok');
    expect(f).toHaveBeenCalledTimes(2);
    expect(f.workers[1].terminated).toBe(false);
  });

  it('defaults the timeout to 3000 ms', async () => {
    vi.useFakeTimers();
    try {
      const f = fakeWorkerFactory([silent]);
      const a = createAnalyzer({ workerFactory: f });
      const p = a.analyze('x', { source: 'inline' });
      await vi.advanceTimersByTimeAsync(2999);
      expect(f.workers[0].terminate).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(2);
      expect((await p).reason).toBe('script_analysis_timeout');
    } finally { vi.useRealTimers(); }
  });

  it('maps a worker error to unknown / script_parse_failed and replaces the worker', async () => {
    const crash = (msg, w) => queueMicrotask(() => w.onerror?.({ message: 'boom' }));
    const f = fakeWorkerFactory([crash, echo]);
    const a = createAnalyzer({ workerFactory: f });
    expect(await a.analyze('x', { source: 'inline' })).toMatchObject({ status: 'unknown', reason: 'script_parse_failed' });
    expect(f.workers[0].terminate).toHaveBeenCalled();
    expect((await a.analyze('y', { source: 'inline' })).status).toBe('ok');
    expect(f).toHaveBeenCalledTimes(2);
  });

  it('ignores replies for other ids', async () => {
    const wrongId = (msg, w) => { queueMicrotask(() => w.onmessage?.({ data: { id: msg.id + 99, result: { status: 'ok', navigations: [], urls: [] } } })); };
    const a = createAnalyzer({ workerFactory: fakeWorkerFactory([wrongId]), timeoutMs: 20 });
    expect((await a.analyze('x', { source: 'inline' })).reason).toBe('script_analysis_timeout');
  });

  it('serializes concurrent calls so one timeout does not discard another result', async () => {
    const f = fakeWorkerFactory([(msg, w) => { if (msg.source === 'hang') return; echo(msg, w); }, echo]);
    const a = createAnalyzer({ workerFactory: f, timeoutMs: 20 });
    const [r1, r2] = await Promise.all([a.analyze('hang', { source: 'inline' }), a.analyze('var z = 1;', { source: 'inline' })]);
    expect(r1.reason).toBe('script_analysis_timeout');
    expect(r2.status).toBe('ok');
  });

  it('dispose() terminates the current worker and later calls still work', async () => {
    const f = fakeWorkerFactory([echo]);
    const a = createAnalyzer({ workerFactory: f });
    await a.analyze('1', { source: 'inline' });
    a.dispose();
    expect(f.workers[0].terminate).toHaveBeenCalledTimes(1);
    a.dispose(); // idempotent
    expect(f.workers[0].terminate).toHaveBeenCalledTimes(1);
    expect((await a.analyze('2', { source: 'inline' })).status).toBe('ok');
    expect(f).toHaveBeenCalledTimes(2);
  });
});
