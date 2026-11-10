// Fake client / analyzer for scan-engine tests.
import { analyzeScript } from '../../src/analysis/fold.js';

export const analyzer = {
  analyze: async (src, meta) => ({ ...analyzeScript(src), ...meta }),
};

export const htmlDoc = (finalUrl, html, extra = {}) => {
  const doc = {
    finalUrl, chain: [{ url: finalUrl, status: extra.status ?? 200 }], status: 200, contentType: 'text/html; charset=utf-8',
    bytesRead: html.length, truncated: false, cache: 'miss', text: html, charset: 'utf-8', fellBack: false, isHtml: true, isBinary: false, ...extra,
  };
  // The Worker always returns the allowlisted Content-Type header alongside the decoded metadata.
  doc.headers = { 'content-type': doc.contentType, ...extra.headers };
  return doc;
};

export const scriptDoc = (finalUrl, js, extra = {}) => htmlDoc(finalUrl, js, { contentType: 'application/javascript', isHtml: false, ...extra });

export const binaryDoc = (finalUrl, contentType, extra = {}) => htmlDoc(finalUrl, '', { contentType, isHtml: false, isBinary: true, bytesRead: 0, ...extra });

/** routes: url -> doc | failure | (url, kind) => doc | failure. Unrouted URLs fail with upstream_error. */
export function fakeClient(routes) {
  const calls = [];
  return {
    calls,
    async fetchDoc(url, kind) {
      calls.push({ url, kind });
      const r = routes[url];
      if (r === undefined) return { error: 'upstream_error', detail: 'unrouted' };
      return typeof r === 'function' ? r(url, kind) : r;
    },
  };
}
