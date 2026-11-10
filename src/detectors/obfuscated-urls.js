// obfuscated-urls: URLs that were hidden by script obfuscation (split strings,
// base64, escapes, fromCharCode) and recovered by the static constant folder,
// plus base64 blobs in HTML attributes that decode to http(s) URLs. A decoded
// payload-looking URL is an observation, not a verdict.
import { walkElements, snippetAround } from '../parse/html.js';
import { classifyPayloadUrl } from './payload-links.js';
import { makeLocator, escapeControlChars, withoutFragment } from './util.js';

const DECODERS = new Set(['atob', 'unescape', 'decodeURIComponent', 'decodeURI', 'String.fromCharCode', 'String.fromCodePoint', 'join']);
const BLOB = /[A-Za-z0-9+/_-]{24,4096}={0,2}/g;
const URL_IN_TEXT = /https?:\/\/[^\s"'<>\\]+/gi;
const MAX_PER_VALUE = 5;

/** Candidate URLs inside a decoded string: the whole value if it is one URL, else embedded http(s) URLs. */
function urlsIn(value) {
  const v = value.trim();
  if (/^(?:https?:)?\/\/\S+$/i.test(v) || (!/\s/.test(v) && !v.includes('://') && v.length > 0)) return [v];
  return (v.match(URL_IN_TEXT) ?? []).slice(0, MAX_PER_VALUE);
}

function decodeBase64(token) {
  try {
    const b64 = token.replace(/-/g, '+').replace(/_/g, '/');
    return atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  } catch { return null; }
}

function classify(raw, baseUrl) {
  let resolved;
  try { resolved = new URL(raw, baseUrl).href; } catch { return null; }
  if (!/^https?:/i.test(resolved)) return null;
  const hit = classifyPayloadUrl(resolved);
  return {
    target: withoutFragment(resolved),
    normalized: resolved,
    payload: Boolean(hit),
  };
}

const RULES = {
  'obfuscation.decoded-payload-url': { severity: 'medium', confidence: 'medium', title: 'Executable-looking URL hidden by obfuscation' },
  'obfuscation.decoded-url': { severity: 'info', confidence: 'low', title: 'URL recovered from obfuscated script' },
};

/** @type {import('./index.js').Detector} */
export const obfuscatedUrls = {
  id: 'obfuscated-urls',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const coverage = [];
    const locate = makeLocator(ctx.html);
    const push = (ruleId, target, evidence) => {
      const r = RULES[ruleId];
      findings.push({ detector: 'obfuscated-urls', ruleId, category: 'obfuscation', proposedSeverity: r.severity, confidence: r.confidence, title: r.title, target, evidence });
    };

    for (const s of ctx.scripts) {
      if (s.status !== 'ok') coverage.push({ check: 'obfuscated-urls', page: s.url ?? ctx.pageUrl, state: 'unknown', reason: s.reason });
      for (const u of s.urls ?? []) {
        const decoded = u.via.some((v) => DECODERS.has(v));
        for (const cand of urlsIn(u.value)) {
          const c = classify(cand, ctx.baseUrl);
          if (!c) continue;
          if (!c.payload && !decoded) continue; // benign split strings are not worth reporting
          push(c.payload ? 'obfuscation.decoded-payload-url' : 'obfuscation.decoded-url', c.target, {
            snippet: escapeControlChars(`${u.via.join(' > ')}: ${cand}`).slice(0, 200),
            sourceUrl: s.source === 'external' && s.url ? s.url : ctx.finalUrl,
            location: { type: 'script_range' },
            matchedValue: escapeControlChars(cand).slice(0, 256),
            normalizedValue: escapeControlChars(c.normalized).slice(0, 2048),
            context: `${s.source} script, offset ${u.start}-${u.end}`,
          });
        }
      }
    }

    for (const el of walkElements(ctx.tree)) {
      for (const a of el.attrs) {
        if (a.value.length < 24) continue;
        let n = 0;
        for (const m of a.value.matchAll(BLOB)) {
          if (++n > MAX_PER_VALUE) break;
          const text = decodeBase64(m[0]);
          if (!text || !/^\s*https?:\/\/[\x21-\x7e]+/i.test(text)) continue;
          const cand = text.trim().split(/\s/)[0];
          const c = classify(cand, ctx.baseUrl);
          if (!c) continue;
          const loc = el.sourceCodeLocation?.attrs?.[a.name] ?? el.sourceCodeLocation;
          const location = { type: 'html_attribute', tag: el.tagName, attribute: a.name };
          if (loc?.startLine) location.line = loc.startLine;
          if (loc?.startCol) location.column = loc.startCol;
          const offset = locate(loc?.startLine ?? null, loc?.startCol ?? null);
          push(c.payload ? 'obfuscation.decoded-payload-url' : 'obfuscation.decoded-url', c.target, {
            snippet: escapeControlChars(offset === null ? `${el.tagName} ${a.name}=${m[0]}` : snippetAround(ctx.html, offset)).slice(0, 200),
            sourceUrl: ctx.finalUrl,
            location,
            matchedValue: escapeControlChars(m[0]).slice(0, 256),
            normalizedValue: escapeControlChars(c.normalized).slice(0, 2048),
            context: 'base64 in attribute',
          });
        }
      }
    }
    return { findings, coverage };
  },
};
