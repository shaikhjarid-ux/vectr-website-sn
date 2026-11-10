// Scan engine: fetch the root through the guarded proxy, analyze it statically,
// follow a small ranked set of candidates one level deep, and assemble a Report.
// Original URLs live only in this transient state; the returned report is
// passed through sanitizeReport before it leaves this module.
import { parseHtml, effectiveBase, extractUrlRefs, textContentOf, walkElements } from '../parse/html.js';
import { runDetectors, finalizeFindings } from '../detectors/index.js';
import { payloadLinks, classifyPayloadUrl } from '../detectors/payload-links.js';
import { disguisedFilenames } from '../detectors/disguised-filenames.js';
import { obfuscatedUrls } from '../detectors/obfuscated-urls.js';
import { redirects } from '../detectors/redirects.js';
import { hiddenOverlays } from '../detectors/hidden-overlays.js';
import { offOriginForms, uriSchemes } from '../detectors/forms-and-schemes.js';
import { headerHints } from '../detectors/header-hints.js';
import { createBudget, runPool, DEFAULT_LIMITS } from './budget.js';
import { rankCandidates } from './candidates.js';
import { sanitizeReport } from '../shared/url-safety.js';
import { escapeControlChars } from '../detectors/util.js';

export const ENGINE_VERSION = '0.1.0';
export const DEFAULT_DETECTORS = [payloadLinks, disguisedFilenames, obfuscatedUrls, redirects, hiddenOverlays, offOriginForms, uriSchemes, headerHints];

const MAX_FOLLOW = 6;
const MAX_EXTERNAL_SCRIPTS = 4;
const MAX_INLINE_SCRIPTS = 30;
const SKIP_SCRIPT_NAMES = /jquery|bootstrap|react|vue|angular|lodash/i;
const JS_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module', 'application/x-javascript', 'text/ecmascript', 'application/ecmascript']);
const CHALLENGE = /just a moment\.\.\.|captcha/i;

const attr = (el, name) => el.attrs.find((a) => a.name === name)?.value;
const textOf = (el) => (el.childNodes ?? []).filter((c) => c.nodeName === '#text').map((c) => c.value).join('');

/**
 * @param {string} url
 * @param {{client: {fetchDoc: Function}, analyzer: {analyze: Function}, detectors?: import('../detectors/index.js').Detector[], budget?: ReturnType<typeof createBudget>, now?: () => number, onProgress?: (state: {phase: string, detail?: string}) => void}} deps
 * @returns {Promise<import('../schema/report.js').Report>}
 */
export async function scan(url, deps) {
  const now = deps.now ?? Date.now;
  const started = now();
  const budget = deps.budget ?? createBudget({}, now);
  const detectors = deps.detectors ?? DEFAULT_DETECTORS;
  const progress = (phase, detail) => { try { deps.onProgress?.({ phase, detail }); } catch { /* UI errors never affect a scan */ } };

  const stats = { attempted: 0, successful: 0, cached: 0, failed: 0 };
  const coverage = [];
  const seenCoverage = new Set();
  const raws = [];
  const pages = [];
  let rootHeaders = {};
  let rootFinalUrl = null;

  const addCoverage = (entry) => {
    const key = `${entry.check}|${entry.page ?? ''}|${entry.state}|${entry.reason ?? ''}`;
    if (seenCoverage.has(key)) return;
    seenCoverage.add(key);
    coverage.push(entry);
  };
  let deadlineNoted = false;
  const noteDeadline = () => {
    if (deadlineNoted) return;
    deadlineNoted = true;
    addCoverage({ check: 'scan', state: 'skipped', reason: 'scan_deadline_reached' });
  };

  /** Fetch one document under the budget and deadline; null when skipped or failed (coverage records why). */
  async function fetchOne(kind, target) {
    if (budget.deadlineReached()) { noteDeadline(); return null; }
    if (!budget.tryAcquire(kind)) {
      addCoverage({ check: 'budget', page: target, state: 'skipped', reason: 'resource_budget_exhausted' });
      return null;
    }
    stats.attempted++;
    const signal = typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(Math.max(1, budget.remainingMs())) : undefined;
    let result;
    try {
      result = await deps.client.fetchDoc(target, kind, signal);
    } catch {
      result = { error: 'upstream_error', detail: 'fetch failed' };
    }
    if (result && 'error' in result) {
      stats.failed++;
      addCoverage({ check: 'fetch', page: target, state: 'unknown', reason: result.error });
      return null;
    }
    stats.successful++;
    if (result.cache === 'hit') stats.cached++;
    return result;
  }

  const emptyCtx = (doc) => ({
    pageUrl: doc.finalUrl, finalUrl: doc.finalUrl, baseUrl: doc.finalUrl, html: '', tree: parseHtml(''),
    headers: doc.headers, chain: doc.chain, refs: [], scripts: [],
  });

  async function runHeaderHintsOnly(doc) {
    const only = detectors.filter((d) => d.id === 'header-hints');
    if (only.length === 0) return;
    const out = await runDetectors(emptyCtx(doc), only);
    raws.push(...out.raw);
    out.coverage.forEach(addCoverage);
  }

  /** Analyze one fetched document. Returns refs and candidates for ranking (root only uses them). */
  async function processPage(doc, { isRoot }) {
    const pageUrl = doc.finalUrl;
    pages.push({ url: pageUrl, status: doc.status, contentType: doc.contentType, bytesRead: doc.bytesRead, truncated: doc.truncated, redirectChain: doc.chain });
    if (doc.truncated) addCoverage({ check: 'fetch', page: pageUrl, state: 'unknown', reason: 'response_truncated' });
    const none = { refs: [], candidates: [] };

    if (doc.status === 403 || doc.status === 503) {
      addCoverage({ check: 'fetch', page: pageUrl, state: 'unknown', reason: 'fetch_blocked_or_challenge' });
      return none;
    }
    if (doc.status >= 400) {
      addCoverage({ check: 'fetch', page: pageUrl, state: 'unknown', reason: 'upstream_error' });
      return none;
    }

    if (doc.isBinary) {
      addCoverage({ check: 'binary-content', page: pageUrl, state: 'skipped', reason: 'binary_not_inspected' });
      if (isRoot) {
        const hit = classifyPayloadUrl(pageUrl);
        if (hit) {
          raws.push({
            detector: 'payload-links', ruleId: hit.ruleId, category: 'payload', proposedSeverity: hit.severity, confidence: 'medium',
            title: hit.ruleId === 'payload.link.archive' ? 'Archive link' : 'Executable-looking link', target: pageUrl,
            evidence: {
              snippet: escapeControlChars(`root response ${doc.contentType}`).slice(0, 200), sourceUrl: pageUrl,
              location: { type: 'response_header', attribute: 'content-type' }, matchedValue: pageUrl.slice(0, 256), normalizedValue: pageUrl.slice(0, 2048), context: 'the scanned URL itself returned a binary response',
            },
          });
        }
      }
      await runHeaderHintsOnly(doc);
      return none;
    }
    if (!doc.isHtml) {
      await runHeaderHintsOnly(doc);
      return none;
    }

    if (CHALLENGE.test(doc.text)) addCoverage({ check: 'fetch', page: pageUrl, state: 'unknown', reason: 'fetch_blocked_or_challenge' });

    progress('parsing', pageUrl);
    const tree = parseHtml(doc.text);
    const baseUrl = effectiveBase(tree, pageUrl);
    const refs = extractUrlRefs(tree, baseUrl);
    const elements = [...walkElements(tree)];
    const scriptEls = elements.filter((e) => e.tagName === 'script');

    progress('analyzing', pageUrl);
    const analyzed = [];
    const inline = scriptEls.filter((e) => attr(e, 'src') === undefined && JS_TYPES.has((attr(e, 'type') ?? '').trim().toLowerCase()) && textOf(e).trim() !== '');
    for (const el of inline.slice(0, MAX_INLINE_SCRIPTS)) analyzed.push(await deps.analyzer.analyze(textOf(el), { source: 'inline' }));
    if (inline.length > MAX_INLINE_SCRIPTS) addCoverage({ check: 'javascript', page: pageUrl, state: 'skipped', reason: 'resource_budget_exhausted' });

    if (isRoot) {
      let origin = '';
      try { origin = new URL(pageUrl).origin; } catch { /* no origin: no same-origin scripts */ }
      const seen = new Set();
      const wanted = [];
      for (const r of refs) {
        if (r.tag !== 'script' || r.attribute !== 'src' || !r.resolved) continue;
        let u;
        try { u = new URL(r.resolved); } catch { continue; }
        const key = u.origin + u.pathname + u.search;
        if (u.origin !== origin || seen.has(key) || SKIP_SCRIPT_NAMES.test(u.pathname.split('/').pop() ?? '')) continue;
        seen.add(key);
        wanted.push(r.resolved);
      }
      const thunks = wanted.slice(0, MAX_EXTERNAL_SCRIPTS).map((u) => async () => {
        const d = await fetchOne('script', u);
        if (!d) return null;
        if (d.truncated) addCoverage({ check: 'fetch', page: d.finalUrl, state: 'unknown', reason: 'response_truncated' });
        return deps.analyzer.analyze(d.text, { source: 'external', url: d.finalUrl });
      });
      for (const a of await runPool(thunks, DEFAULT_LIMITS.parallel)) if (a) analyzed.push(a);
    }

    if (elements.some((e) => e.tagName === 'link' && /(?:^|\s)stylesheet(?:\s|$)/i.test(attr(e, 'rel') ?? '') && attr(e, 'href'))) {
      addCoverage({ check: 'stylesheets', page: pageUrl, state: 'skipped', reason: 'external_stylesheet_skipped' });
    }
    if (scriptEls.length >= 1 && textContentOf(tree).length < 200) {
      addCoverage({ check: 'static-coverage', page: pageUrl, state: 'unknown', reason: 'unsupported_runtime_behavior' });
    }

    const ctx = { pageUrl, finalUrl: pageUrl, baseUrl, html: doc.text, tree, headers: doc.headers, chain: doc.chain, refs, scripts: analyzed };
    const out = await runDetectors(ctx, detectors);
    raws.push(...out.raw);
    out.coverage.forEach(addCoverage);
    return { refs, candidates: out.candidates };
  }

  async function safeProcess(doc, opts) {
    try { return await processPage(doc, opts); } catch {
      addCoverage({ check: 'scan', page: doc.finalUrl, state: 'unknown', reason: 'detector_failed' });
      return { refs: [], candidates: [] };
    }
  }

  progress('fetching', url);
  const root = await fetchOne('page', url);
  if (root) {
    rootFinalUrl = root.finalUrl;
    rootHeaders = root.headers;
    const rootResult = await safeProcess(root, { isRoot: true });

    progress('following');
    const ranked = rankCandidates(rootResult.refs, rootResult.candidates, root.finalUrl).slice(0, MAX_FOLLOW);
    const thunks = ranked.map((c) => async () => {
      const d = await fetchOne('page', c.url);
      if (d) await safeProcess(d, { isRoot: false });
    });
    await runPool(thunks, DEFAULT_LIMITS.parallel);
  }

  const findings = await finalizeFindings(raws);
  progress('done');
  /** @type {import('../schema/report.js').Report} */
  const report = {
    v: 1,
    engineVersion: ENGINE_VERSION,
    detectorVersions: Object.fromEntries(detectors.map((d) => [d.id, d.version])),
    scannedAt: new Date(started).toISOString(),
    durationMs: Math.max(0, now() - started),
    target: url,
    finalUrl: rootFinalUrl,
    pagesScanned: pages,
    findings,
    coverage,
    fetchStats: stats,
    headers: rootHeaders,
  };
  return sanitizeReport(report);
}
