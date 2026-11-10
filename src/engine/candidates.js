// User-input normalization and ranking of pages worth following (depth 1).
import { extensionOf } from '../parse/url.js';
import { classifyPayloadUrl } from '../detectors/payload-links.js';
import { withoutFragment } from '../detectors/util.js';

const MAX_CANDIDATES = 100;
const MAX_URL = 4096;
const OTHER_SCHEMES = /^(?:view-source|javascript|file|data|ftp|mailto|about|blob):/i;
const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * @param {string} input
 * @returns {string}
 */
export function normalizeUserInput(input) {
  const s = String(input ?? '').trim();
  if (s === '') throw new Error('empty_input');
  if (HAS_SCHEME.test(s)) {
    if (!/^https?:\/\//i.test(s)) throw new Error('unsupported_scheme');
    return s;
  }
  if (OTHER_SCHEMES.test(s)) throw new Error('unsupported_scheme');
  return `https://${s}`;
}

const ASSET_EXTENSIONS = new Set('png jpg jpeg gif svg webp avif ico bmp css js mjs map woff woff2 ttf otf eot json xml rss atom mp3 mp4 webm ogg'.split(' '));
const TEXT_KEYWORDS = /\b(?:download|mirror|get|installers?|install|link|redirect)\b/i;
const PATH_KEYWORDS = /(?:^|[/_.-])(?:download|mirror|get|install|installer|redirect|link|go|out)(?:[/_.-]|$)/i;

/**
 * @param {import('../parse/html.js').UrlRef[]} refs
 * @param {import('../detectors/index.js').Candidate[]} detectorCandidates
 * @param {string} pageUrl
 * @returns {import('../detectors/index.js').Candidate[]}
 */
export function rankCandidates(refs, detectorCandidates, pageUrl) {
  const pageKey = withoutFragment(pageUrl);
  let pageOrigin = '';
  try { pageOrigin = new URL(pageUrl).origin; } catch { /* no origin: everything is off-origin */ }

  /** @type {Map<string, {candidate: import('../detectors/index.js').Candidate, index: number}>} */
  const best = new Map();
  let index = 0;
  const offer = (candidate) => {
    const key = withoutFragment(candidate.url);
    if (key.length > MAX_URL || key === pageKey || !/^https?:/i.test(key)) return;
    const existing = best.get(key);
    if (!existing || candidate.priority < existing.candidate.priority) best.set(key, { candidate: { ...candidate, url: key }, index: existing?.index ?? index });
    index++;
  };

  for (const c of detectorCandidates) offer(c);

  for (const ref of refs) {
    if (!ref.resolved || !/^https?:/i.test(ref.resolved)) continue;
    const evidence = {
      snippet: `${ref.tag} ${ref.attribute}=${ref.raw}`.slice(0, 200),
      sourceUrl: pageUrl,
      location: { type: /** @type {const} */ ('html_attribute'), tag: ref.tag, attribute: ref.attribute, ...(ref.line !== null ? { line: ref.line } : {}), ...(ref.column !== null ? { column: ref.column } : {}) },
      matchedValue: ref.raw.slice(0, 256),
      normalizedValue: ref.resolved.slice(0, 2048),
      context: ref.text ?? '',
    };
    const make = (reason, priority) => ({ url: ref.resolved, reason, priority, sourceEvidence: evidence, depth: /** @type {const} */ (1) });
    let url;
    try { url = new URL(ref.resolved); } catch { continue; }

    if (ref.source === 'meta-refresh') { offer(make('meta-refresh', 1)); continue; }
    if (classifyPayloadUrl(ref.resolved)) { offer(make('download-link', 1)); continue; }
    if ((ref.attribute === 'action' || ref.attribute === 'formaction') && /download/i.test(url.pathname)) { offer(make('download-form', 1)); continue; }

    if (ref.attribute !== 'href' || (ref.tag !== 'a' && ref.tag !== 'area')) continue;
    const ext = extensionOf(ref.resolved);
    if (ext && ASSET_EXTENSIONS.has(ext)) continue;
    const text = ref.text ?? '';
    const sameOrigin = url.origin === pageOrigin;
    const keywordText = TEXT_KEYWORDS.test(text);
    const keywordPath = PATH_KEYWORDS.test(url.pathname);
    if (sameOrigin && (keywordText || keywordPath)) offer(make('same-origin-hint', 2));
    else if (!sameOrigin && (keywordText || keywordPath)) offer(make('off-origin-hint', 3));
  }

  return [...best.values()]
    .sort((a, b) => a.candidate.priority - b.candidate.priority || a.index - b.index)
    .slice(0, MAX_CANDIDATES)
    .map((x) => x.candidate);
}
