// Shared helpers for detectors.
import { snippetAround } from '../parse/html.js';

/** Maps 1-based line / column to an offset in `html`; line starts are computed once, lazily. */
export function makeLocator(html) {
  let starts = null;
  return (line, column) => {
    if (!line) return null;
    if (!starts) {
      starts = [0];
      for (let i = 0; i < html.length; i++) if (html.charCodeAt(i) === 10) starts.push(i + 1);
    }
    const base = starts[line - 1];
    return base === undefined ? null : base + Math.max(0, (column ?? 1) - 1);
  };
}

/**
 * Build Evidence for a UrlRef.
 * @param {import('./index.js').DetectorContext} ctx
 * @param {import('../parse/html.js').UrlRef} ref
 * @param {(line: number | null, column: number | null) => number | null} locate
 * @returns {import('../schema/report.js').Evidence}
 */
export function evidenceFromRef(ctx, ref, locate) {
  const offset = locate(ref.line, ref.column);
  const snippet = offset === null ? `${ref.tag} ${ref.attribute}=${ref.raw}`.slice(0, 200) : snippetAround(ctx.html, offset);
  /** @type {import('../schema/report.js').Evidence['location']} */
  const location = { type: 'html_attribute', tag: ref.tag, attribute: ref.attribute };
  if (ref.line !== null) location.line = ref.line;
  if (ref.column !== null) location.column = ref.column;
  return {
    snippet,
    sourceUrl: ctx.finalUrl,
    location,
    matchedValue: ref.raw,
    normalizedValue: ref.resolved ?? ref.raw,
    context: ref.text ?? '',
  };
}

/** The URL without its fragment: the grouping key for findings. */
export const withoutFragment = (url) => {
  const i = url.indexOf('#');
  return i < 0 ? url : url.slice(0, i);
};
