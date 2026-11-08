// Browser-side client for the Worker's POST /api/fetch.
import { decodeMeta } from '../worker/headers.js';
import { ERROR_CODES } from '../shared/codes.js';
import { decodeBody } from './decode.js';

const JS_TYPES = new Set(['application/javascript', 'text/javascript', 'application/x-javascript', 'application/ecmascript', 'text/ecmascript']);

/**
 * @typedef {{finalUrl: string, chain: import('../schema/report.js').ChainEntry[], status: number, contentType: string, bytesRead: number, truncated: boolean, cache: string, headers: Record<string, string>, text: string, charset: string, fellBack: boolean, isHtml: boolean, isBinary: boolean}} FetchedDoc
 * @typedef {{error: string, detail: string, chain?: import('../schema/report.js').ChainEntry[]}} FetchFailure
 */

/** @param {{fetchFn?: typeof fetch}} [opts] */
export function createFetchClient(opts = {}) {
  const fetchFn = opts.fetchFn ?? ((input, init) => fetch(input, init));

  return {
    /**
     * @param {string} url
     * @param {'page' | 'script'} kind
     * @param {AbortSignal} [signal]
     * @returns {Promise<FetchedDoc | FetchFailure>}
     */
    async fetchDoc(url, kind, signal) {
      let res;
      try {
        res = await fetchFn('/api/fetch', {
          method: 'POST',
          credentials: 'omit',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url, kind }),
          signal,
        });
      } catch (err) {
        if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) return { error: 'timeout', detail: 'request aborted' };
        return { error: 'upstream_error', detail: 'could not reach the fetch service' };
      }

      if (!res.ok) {
        let body = null;
        try { body = await res.json(); } catch { /* not JSON */ }
        const known = body && ERROR_CODES.includes(body.error);
        const error = known ? body.error : res.status === 429 ? 'rate_limited' : 'upstream_error';
        /** @type {FetchFailure} */
        const failure = { error, detail: typeof body?.detail === 'string' ? body.detail : `fetch service returned ${res.status}` };
        if (known && Array.isArray(body.chain)) failure.chain = body.chain;
        return failure;
      }

      let meta;
      try {
        const header = res.headers.get('x-audit-meta');
        if (!header) throw new Error('missing');
        meta = decodeMeta(header);
      } catch {
        return { error: 'upstream_error', detail: 'malformed fetch service response' };
      }

      let bytes;
      try { bytes = new Uint8Array(await res.arrayBuffer()); } catch { return { error: 'upstream_error', detail: 'could not read response body' }; }

      const contentType = typeof meta.contentType === 'string' ? meta.contentType : '';
      const mime = contentType.split(';')[0].trim().toLowerCase();
      const textual = mime.startsWith('text/') || mime === 'application/xhtml+xml' || JS_TYPES.has(mime);
      const { text, charset, fellBack } = decodeBody(bytes, contentType);
      const isHtml = mime === 'text/html' || mime === 'application/xhtml+xml' || (mime === '' && kind === 'page' && bytes.length > 0);
      return {
        finalUrl: meta.finalUrl, chain: meta.chain ?? [], status: meta.status, contentType,
        bytesRead: meta.bytesRead ?? bytes.length, truncated: Boolean(meta.truncated), cache: meta.cache ?? 'miss',
        headers: meta.headers ?? {}, text, charset, fellBack, isHtml, isBinary: mime !== '' && !textual,
      };
    },
  };
}
