// hidden-overlays: static markup and style heuristics for invisible iframes,
// click-capture layers and off-screen links.
//
// Limits: computed styles are NOT evaluated. Only inline `style` attributes and
// simple `.class` / `#id` rules from <style> blocks are read; rules inside
// at-rules (such as @media) and any other selector are ignored, and CSS
// specificity is not modelled (inline wins). Confidence is therefore capped at
// "medium" for every rule.
import { crossesRegistrableDomain } from '../net/psl.js';
import { walkElements, snippetAround } from '../parse/html.js';
import { makeLocator, withoutFragment, escapeControlChars } from './util.js';

function stripComments(css) { return css.replace(/\/\*[\s\S]*?(?:\*\/|$)/g, ''); }

/** Remove @-rule blocks (balanced braces) so conditional rules are not applied unconditionally. */
function removeAtBlocks(css) {
  let out = '';
  let i = 0;
  while (i < css.length) {
    if (css[i] === '@') {
      const open = css.indexOf('{', i);
      const semi = css.indexOf(';', i);
      if (open === -1 || (semi !== -1 && semi < open)) { i = semi === -1 ? css.length : semi + 1; continue; }
      let depth = 0;
      let j = open;
      for (; j < css.length; j++) {
        if (css[j] === '{') depth++;
        else if (css[j] === '}' && --depth === 0) break;
      }
      i = j + 1;
    } else { out += css[i]; i++; }
  }
  return out;
}

function parseDecls(text) {
  const d = new Map();
  for (const part of text.split(';')) {
    const idx = part.indexOf(':');
    if (idx < 0) continue;
    const prop = part.slice(0, idx).trim().toLowerCase();
    const val = part.slice(idx + 1).replace(/!important/i, '').trim().toLowerCase();
    if (prop) d.set(prop, val);
  }
  return d;
}

function collectRules(tree) {
  const byClass = new Map();
  const byId = new Map();
  for (const el of walkElements(tree)) {
    if (el.tagName !== 'style') continue;
    const css = removeAtBlocks(stripComments((el.childNodes ?? []).filter((c) => c.nodeName === '#text').map((c) => c.value).join('')));
    for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const decls = parseDecls(m[2]);
      for (const sel of m[1].split(',')) {
        const s = sel.trim();
        const cm = /^\.([a-z0-9_-]+)$/i.exec(s);
        const im = /^#([a-z0-9_-]+)$/i.exec(s);
        const target = cm ? byClass : im ? byId : null;
        if (!target) continue;
        const key = (cm ?? im)[1];
        target.set(key, new Map([...(target.get(key) ?? []), ...decls]));
      }
    }
  }
  return { byClass, byId };
}

const attr = (el, name) => el.attrs.find((a) => a.name === name)?.value;

function effectiveStyle(el, rules) {
  const d = new Map();
  for (const c of (attr(el, 'class') ?? '').split(/\s+/)) for (const [k, v] of rules.byClass.get(c) ?? []) d.set(k, v);
  const id = attr(el, 'id');
  if (id) for (const [k, v] of rules.byId.get(id) ?? []) d.set(k, v);
  for (const [k, v] of parseDecls(attr(el, 'style') ?? '')) d.set(k, v);
  return d;
}

const px = (v) => {
  if (v === undefined) return null;
  const m = /^(-?\d*\.?\d+)(px)?$/.exec(v.trim());
  return m ? Number(m[1]) : null;
};
const isZeroish = (v) => { const n = px(v); return n !== null && n >= 0 && n <= 1; };
const opacityZero = (d) => { const o = d.get('opacity'); return o !== undefined && Number.isFinite(Number(o)) && Number(o) <= 0.05; };
const isFull = (v, unit) => v !== undefined && (v === '100%' || v === `100${unit}`);

function hiddenBy(el, rules) {
  const d = effectiveStyle(el, rules);
  if (d.get('display') === 'none') return 'display:none';
  if (d.get('visibility') === 'hidden') return 'visibility:hidden';
  if (opacityZero(d)) return 'opacity:0';
  if (el.attrs.some((a) => a.name === 'hidden')) return 'hidden attribute';
  const w = attr(el, 'width'), h = attr(el, 'height');
  if (el.tagName === 'iframe') {
    if (w !== undefined && isZeroish(w)) return `width=${w}`;
    if (h !== undefined && isZeroish(h)) return `height=${h}`;
    if (isZeroish(d.get('width'))) return `width:${d.get('width')}`;
    if (isZeroish(d.get('height'))) return `height:${d.get('height')}`;
  }
  return null;
}

function hiddenReason(el, rules) {
  let cur = el;
  for (let i = 0; cur && i < 10 && typeof cur.tagName === 'string'; i++, cur = cur.parentNode) {
    const own = cur === el ? hiddenBy(cur, rules) : (() => { const d = effectiveStyle(cur, rules); return d.get('display') === 'none' ? 'ancestor display:none' : d.get('visibility') === 'hidden' ? 'ancestor visibility:hidden' : null; })();
    if (own) return own;
  }
  return null;
}

function* descendants(el, cap = 200) {
  const stack = [...(el.childNodes ?? [])].reverse();
  let n = 0;
  while (stack.length && n++ < cap) {
    const node = stack.pop();
    yield node;
    if (node.childNodes) stack.push(...[...node.childNodes].reverse());
  }
}

function coversViewport(d) {
  const pos = d.get('position');
  if (pos !== 'fixed' && pos !== 'absolute') return false;
  const sized = isFull(d.get('width'), 'vw') && isFull(d.get('height'), 'vh');
  const inset = ['top', 'right', 'bottom', 'left'].every((s) => px(d.get(s)) === 0) || px(d.get('inset')) === 0;
  return sized || inset;
}

function offscreen(d) {
  const pos = d.get('position');
  if (pos !== 'absolute' && pos !== 'fixed') return false;
  return ['left', 'top', 'right', 'bottom'].some((s) => { const n = px(d.get(s)); return n !== null && n <= -1000; });
}

/** @type {import('./index.js').Detector} */
export const hiddenOverlays = {
  id: 'hidden-overlays',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const rules = collectRules(ctx.tree);
    const locate = makeLocator(ctx.html);
    let pageHost = null;
    try { pageHost = new URL(ctx.finalUrl).hostname; } catch { /* no host: cross-site checks are skipped */ }

    const evidence = (el, attribute, matched, normalized, context) => {
      const loc = el.sourceCodeLocation;
      const location = { type: 'html_attribute', tag: el.tagName, attribute };
      if (loc?.startLine) location.line = loc.startLine;
      if (loc?.startCol) location.column = loc.startCol;
      const offset = locate(loc?.startLine ?? null, loc?.startCol ?? null);
      return {
        snippet: escapeControlChars(offset === null ? `<${el.tagName}>` : snippetAround(ctx.html, offset)).slice(0, 200),
        sourceUrl: ctx.finalUrl, location,
        matchedValue: escapeControlChars(matched).slice(0, 256), normalizedValue: escapeControlChars(normalized).slice(0, 2048), context: context.slice(0, 200),
      };
    };
    const resolve = (href) => { try { return new URL(href, ctx.baseUrl).href; } catch { return null; } };
    const add = (ruleId, severity, confidence, title, target, ev) => {
      findings.push({ detector: 'hidden-overlays', ruleId, category: 'interface', proposedSeverity: severity, confidence, title, target, evidence: ev });
    };

    for (const el of walkElements(ctx.tree)) {
      if (el.tagName === 'iframe') {
        const src = attr(el, 'src');
        const resolved = src ? resolve(src) : null;
        if (resolved && /^https?:/i.test(resolved) && pageHost) {
          const reason = hiddenReason(el, rules);
          let host = null;
          try { host = new URL(resolved).hostname; } catch { /* skip */ }
          if (reason && host && crossesRegistrableDomain(pageHost, host)) {
            add('overlay.hidden-iframe', 'medium', 'medium', 'Hidden iframe loads another site', withoutFragment(resolved), evidence(el, 'src', src, resolved, `hidden by ${reason}`));
          }
        }
      }

      const d = effectiveStyle(el, rules);
      if (coversViewport(d)) {
        const transparent = opacityZero(d);
        let linkTarget = null;
        let interactive = el.tagName === 'a' || el.attrs.some((a) => a.name === 'onclick');
        if (el.tagName === 'a' && attr(el, 'href')) linkTarget = resolve(attr(el, 'href'));
        for (const n of descendants(el)) {
          if (n.tagName === 'a' && attr(n, 'href')) { interactive = true; linkTarget ??= resolve(attr(n, 'href')); }
        }
        if (transparent && interactive) {
          const t = linkTarget && /^https?:/i.test(linkTarget) ? withoutFragment(linkTarget) : withoutFragment(ctx.finalUrl);
          add('overlay.fullscreen-capture', 'medium', 'low', 'Invisible full-page layer captures clicks', t, evidence(el, 'style', attr(el, 'style') ?? attr(el, 'class') ?? '', linkTarget ?? ctx.finalUrl, 'full-viewport, opacity 0'));
        }
      }

      if (el.tagName === 'a') {
        const href = attr(el, 'href');
        if (href && !href.trim().startsWith('#') && !/^javascript:/i.test(href.trim())) {
          let cur = el;
          let hit = false;
          for (let i = 0; cur && i < 5 && typeof cur.tagName === 'string'; i++, cur = cur.parentNode) {
            if (offscreen(effectiveStyle(cur, rules))) { hit = true; break; }
          }
          if (hit) {
            const resolved = resolve(href);
            add('overlay.offscreen-link', 'low', 'low', 'Link positioned off-screen', withoutFragment(resolved ?? ctx.finalUrl), evidence(el, 'style', attr(el, 'style') ?? '', resolved ?? href, 'positioned far outside the viewport'));
          }
        }
      }
    }
    return { findings };
  },
};
