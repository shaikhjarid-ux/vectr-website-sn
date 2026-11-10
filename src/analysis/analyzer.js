// Runs script analysis in a terminable Web Worker so a pathological script can
// never freeze the page. Calls are serialized; a timeout terminates the worker
// and the next call gets a fresh one.

const DEFAULT_TIMEOUT_MS = 3000;

/**
 * @typedef {import('./fold.js').ScriptAnalysis & {source: 'inline' | 'external', url?: string}} AnalyzedScript
 */

/**
 * @param {{workerFactory: () => Worker, timeoutMs?: number}} opts
 */
export function createAnalyzer(opts) {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let worker = null;
  let nextId = 1;
  let queue = Promise.resolve();

  const drop = () => {
    if (worker) {
      try { worker.terminate(); } catch { /* already gone */ }
      worker = null;
    }
  };

  /** @returns {Promise<import('./fold.js').ScriptAnalysis>} */
  function runOnce(source) {
    return new Promise((resolve) => {
      const id = nextId++;
      const w = worker ?? (worker = opts.workerFactory());
      let timer;
      const finish = (result, discardWorker) => {
        clearTimeout(timer);
        w.onmessage = null;
        w.onerror = null;
        if (discardWorker && worker === w) drop();
        resolve(result);
      };
      const unknown = (reason) => ({ status: 'unknown', reason, navigations: [], urls: [] });
      timer = setTimeout(() => finish(unknown('script_analysis_timeout'), true), timeoutMs);
      w.onmessage = (event) => {
        const data = event?.data;
        if (!data || data.id !== id) return;
        finish(data.result ?? unknown('script_parse_failed'), false);
      };
      w.onerror = () => finish(unknown('script_parse_failed'), true);
      try {
        w.postMessage({ id, source });
      } catch {
        finish(unknown('script_parse_failed'), true);
      }
    });
  }

  return {
    /**
     * @param {string} source
     * @param {{source: 'inline' | 'external', url?: string}} meta
     * @returns {Promise<AnalyzedScript>}
     */
    analyze(source, meta) {
      const job = queue.then(() => runOnce(source));
      queue = job.catch(() => {});
      return job.then((analysis) => {
        const out = { ...analysis, source: meta.source };
        if (meta.url !== undefined) out.url = meta.url;
        return out;
      });
    },
    dispose() { drop(); },
  };
}
