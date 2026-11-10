// Non-loading HTML tree and URL references. parse5 builds a plain object tree:
// nothing is fetched, no script runs, no element is attached to a live DOM.
import { parse } from 'parse5';
import { resolveUrl, looksUrlLike } from './url.js';
import { parseSrcset } from './srcset.js';
import { extractCssUrls } from './css.js';

/** @typedef {import('parse5').DefaultTreeAdapterMap['document']} HtmlTree */
/** @typedef {{raw: string, resolved: string | null, tag: string, attribute: string, text?: string, line: number | null, column: number | null, source: 'attribute' | 'style' | 'srcset' | 'srcdoc' | 'meta-refresh'}} UrlRef */

const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'poster', 'background']);
const TEXT_MAX = 100;

/** @param {string} html @returns {HtmlTree} */
export function parseHtml(html) {
  return parse(String(html), { sourceCodeLocationInfo: true });
}

/** Iterative pre-order walk (deep nesting cannot overflow the stack); descends into <template> content. */
function* walk(root) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    yield node;
    const kids = node.childNodes ? [...node.childNodes] : [];
    if (node.content?.childNodes) kids.push(...node.content.childNodes);
    for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
  }
}

const isElement = (n) => typeof n.tagName === 'string';

/** Every element node in document order (including <template> content). */
export function* walkElements(tree) {
  for (const n of walk(tree)) if (isElement(n)) yield n;
}

/** First `<base href>` wins; an unusable one is ignored. */
export function effectiveBase(tree, finalUrl) {
  for (const n of walk(tree)) {
    if (isElement(n) && n.tagName === 'base') {
      const href = n.attrs.find((a) => a.name === 'href');
      if (href) {
        const resolved = resolveUrl(href.value, finalUrl);
        return resolved ?? finalUrl;
      }
    }
  }
  return finalUrl;
}

function directText(node) {
  let out = '';
  for (const c of node.childNodes ?? []) if (c.nodeName === '#text') out += c.value;
  return out;
}

function allText(node) {
  let out = '';
  for (const n of walk(node)) if (n.nodeName === '#text') out += `${n.value} `;
  return out;
}

const collapse = (s) => s.replace(/\s+/g, ' ').trim();

function metaRefreshUrl(content) {
  const m = /^\s*\d*\.?\d*\s*[;,]?\s*(?:u\s*r\s*l\s*=\s*)?(['"]?)(.*?)\1\s*$/is.exec(content);
  if (!m) return null;
  const hasTime = /^\s*\d/.test(content);
  const url = m[2].trim();
  if (!url || (!hasTime && !/url\s*=/i.test(content))) return null;
  return url;
}

function attrLocation(node, attrName) {
  const loc = node.sourceCodeLocation;
  const a = loc?.attrs?.[attrName];
  if (a) return { line: a.startLine ?? null, column: a.startCol ?? null };
  if (loc) return { line: loc.startLine ?? null, column: loc.startCol ?? null };
  return { line: null, column: null };
}

function collect(tree, baseUrl, depth) {
  /** @type {UrlRef[]} */
  const out = [];
  for (const node of walk(tree)) {
    if (!isElement(node)) continue;
    const tag = node.tagName;
    if (tag === 'base') continue; // sets the base URL; it is not a link to follow
    const push = (raw, attribute, source, loc, text) => {
      const value = String(raw).trim();
      if (!value) return;
      /** @type {UrlRef} */
      const ref = { raw: value, resolved: resolveUrl(value, baseUrl), tag, attribute, line: loc.line, column: loc.column, source };
      if (text !== undefined) ref.text = text;
      out.push(ref);
    };

    if (tag === 'style') {
      const loc = node.sourceCodeLocation ? { line: node.sourceCodeLocation.startLine ?? null, column: node.sourceCodeLocation.startCol ?? null } : { line: null, column: null };
      for (const u of extractCssUrls(directText(node))) push(u, '#text', 'style', loc);
    }

    const anchorText = tag === 'a' ? collapse(allText(node)).slice(0, TEXT_MAX) : undefined;
    let httpEquiv = '';
    let content = null;

    for (const a of node.attrs) {
      const name = a.prefix ? `${a.prefix}:${a.name}` : a.name;
      const loc = attrLocation(node, name);
      if (URL_ATTRS.has(a.name) || (a.name === 'data' && tag === 'object')) {
        push(a.value, name, 'attribute', loc, anchorText);
      } else if (a.name === 'srcset' || a.name === 'imagesrcset') {
        for (const u of parseSrcset(a.value)) push(u, name, 'srcset', loc);
      } else if (a.name === 'style') {
        for (const u of extractCssUrls(a.value)) push(u, name, 'style', loc);
      } else if (a.name === 'srcdoc' && tag === 'iframe') {
        if (depth === 0) {
          const nested = collect(parseHtml(a.value), baseUrl, depth + 1);
          for (const r of nested) out.push({ ...r, source: 'srcdoc', line: loc.line, column: loc.column });
        }
      } else if (a.name === 'http-equiv') httpEquiv = a.value.trim().toLowerCase();
      else if (a.name === 'content') content = { value: a.value, loc };
      else if (a.name.startsWith('data-') && looksUrlLike(a.name, a.value)) {
        push(a.value, name, 'attribute', loc, anchorText);
      }
    }
    if (tag === 'meta' && httpEquiv === 'refresh' && content) {
      const u = metaRefreshUrl(content.value);
      if (u) push(u, 'content', 'meta-refresh', content.loc);
    }
  }
  return out;
}

/**
 * @param {HtmlTree} tree
 * @param {string} baseUrl
 * @returns {UrlRef[]}
 */
export function extractUrlRefs(tree, baseUrl) {
  return collect(tree, baseUrl, 0);
}

/** Collapsed visible text; script, style and template content excluded. */
export function textContentOf(tree) {
  let out = '';
  const stack = [tree];
  while (stack.length) {
    const node = stack.pop();
    if (node.nodeName === '#text') { out = `${node.value} ${out}`; continue; }
    if (isElement(node) && (node.tagName === 'script' || node.tagName === 'style' || node.tagName === 'template')) continue;
    const kids = node.childNodes ?? [];
    for (const k of kids) stack.push(k);
  }
  return collapse(out);
}

/** A window of the source around an offset, whitespace-collapsed, never longer than 200 characters. */
export function snippetAround(html, offset, max = 200) {
  const limit = Math.max(1, Math.min(200, max));
  const start = Math.max(0, Math.min(offset - Math.floor(limit / 2), html.length));
  return html.slice(start, start + limit).replace(/\s+/g, ' ');
}
