// Web Worker entry: analyzes one script per message. Never executes target code.
import { analyzeScript } from './fold.js';

self.onmessage = (event) => {
  const { id, source } = event.data ?? {};
  let result;
  try {
    result = analyzeScript(source);
  } catch {
    result = { status: 'unknown', reason: 'script_parse_failed', navigations: [], urls: [] };
  }
  self.postMessage({ id, result });
};
