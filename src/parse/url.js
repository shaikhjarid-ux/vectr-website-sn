// URL helpers. Percent-decoding is bounded (3 passes) so layered encodings are
// seen through without unbounded work.

export const PAYLOAD_EXTENSIONS = new Set('exe msi zip rar 7z iso apk dmg scr bat cmd ps1 jar vbs lnk pkg deb appimage'.split(' '));

const MAX_PASSES = 3;
const MAX_VALUE = 256;
const FILENAME_PARAMS = new Set(['file', 'filename', 'fname', 'name', 'download', 'dl', 'attachment', 'path', 'f']);

/** @param {string} raw @param {string} base @returns {string | null} */
export function resolveUrl(raw, base) {
  try { return new URL(raw, base).href; } catch { return null; }
}

function decodeOnce(s) {
  try { return decodeURIComponent(s); } catch {
    // Malformed sequence somewhere: decode only the ASCII escapes.
    return s.replace(/%([0-7][0-9a-f])/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
}

/**
 * Percent-decode up to 3 passes and drop the fragment.
 * @param {string} url
 * @returns {{url: string, passes: number, truncated: boolean}}
 */
export function normalizeForMatch(url) {
  let cur = String(url);
  const hash = cur.indexOf('#');
  if (hash >= 0) cur = cur.slice(0, hash);
  let passes = 0;
  for (let i = 0; i < MAX_PASSES; i++) {
    const next = decodeOnce(cur);
    if (next === cur) break;
    cur = next;
    passes++;
  }
  return { url: cur, passes, truncated: passes === MAX_PASSES && decodeOnce(cur) !== cur };
}

/** Extension of a bare file name: last path-like segment, no path parameters, trailing dots/spaces trimmed. */
export function extensionOfFilename(name) {
  if (typeof name !== 'string') return null;
  let seg = name.split(/[/\\]/).pop() ?? '';
  seg = seg.split(';')[0].replace(/[. ]+$/, '');
  const dot = seg.lastIndexOf('.');
  if (dot < 0 || dot === seg.length - 1) return null;
  return seg.slice(dot + 1).toLowerCase() || null;
}

/**
 * Extension from the URL's pathname only; query strings are never considered.
 * @param {string} url
 * @returns {string | null}
 */
export function extensionOf(url) {
  let pathname;
  try { pathname = new URL(url, 'http://placeholder.invalid/').pathname; } catch { return null; }
  const decoded = normalizeForMatch(pathname).url;
  return extensionOfFilename(decoded.split('/').pop() ?? '');
}

const URL_ATTR_NAME = /(?:^|[-_])(?:url|href|src|link|uri|download|file|path|target|redirect|dest|destination)$/i;
const SCHEME_URL = /^[a-z][a-z0-9+.-]+:\S/i;
const PATH_START = /^(?:\/|\.{1,2}\/)/;

/**
 * Whether an arbitrary attribute value is worth treating as a URL reference.
 * @param {string} attrName
 * @param {string} value
 */
export function looksUrlLike(attrName, value) {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v === '' || v.length > 4096) return false;
  if (SCHEME_URL.test(v) || PATH_START.test(v)) return true;
  if (/\s/.test(v)) return false;
  return URL_ATTR_NAME.test(attrName) && (v.includes('/') || v.includes('.'));
}

/**
 * Values (bounded-decoded, capped at 256 characters) of query parameters that usually carry file names.
 * @param {string} url
 * @returns {string[]}
 */
export function queryFilenames(url) {
  let params;
  try { params = new URL(url, 'http://placeholder.invalid/').searchParams; } catch { return []; }
  const out = [];
  for (const [name, value] of params) {
    if (FILENAME_PARAMS.has(name.toLowerCase())) out.push(normalizeForMatch(value).url.slice(0, MAX_VALUE));
  }
  return out;
}
