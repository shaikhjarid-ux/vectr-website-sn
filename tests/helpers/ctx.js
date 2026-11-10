// Builds a DetectorContext from an HTML string the same way the scan engine will.
import { parseHtml, effectiveBase, extractUrlRefs } from '../../src/parse/html.js';

export function makeCtx(html, { finalUrl = 'https://x.com/page/', headers = {}, chain = [], scripts = [] } = {}) {
  const tree = parseHtml(html);
  const baseUrl = effectiveBase(tree, finalUrl);
  return {
    pageUrl: finalUrl, finalUrl, baseUrl, html, tree, headers,
    chain: chain.length ? chain : [{ url: finalUrl, status: 200 }],
    refs: extractUrlRefs(tree, baseUrl),
    scripts,
  };
}
