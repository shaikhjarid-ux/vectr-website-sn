// redirects: meta refresh, script navigation and HTTP chain hops that cross
// registrable domains (Public Suffix List based). Observations, not verdicts.
import { crossesRegistrableDomain, registrableDomain } from '../net/psl.js';
import { makeLocator, evidenceFromRef, withoutFragment, escapeControlChars } from './util.js';

const NAV_KINDS = new Set(['location', 'open', 'anchor-download']);

const hostOf = (url) => { try { return new URL(url).hostname; } catch { return null; } };
const stripWww = (h) => h.replace(/^www\./, '');

/** @type {import('./index.js').Detector} */
export const redirects = {
  id: 'redirects',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const followCandidates = [];
    const coverage = [];
    const locate = makeLocator(ctx.html);

    for (const ref of ctx.refs) {
      if (ref.source !== 'meta-refresh' || !ref.resolved || !/^https?:/i.test(ref.resolved)) continue;
      const evidence = evidenceFromRef(ctx, ref, locate);
      findings.push({
        detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'low', confidence: 'high',
        title: 'Page redirects automatically with a meta refresh', target: withoutFragment(ref.resolved), evidence, autoTriggered: true,
      });
      followCandidates.push({ url: ref.resolved, reason: 'meta-refresh', priority: 1, sourceEvidence: evidence, depth: 1 });
    }

    for (const s of ctx.scripts) {
      for (const nav of s.navigations ?? []) {
        if (!NAV_KINDS.has(nav.kind)) continue;
        if (nav.value === null) {
          if (!coverage.some((c) => c.reason === 'unsupported_runtime_behavior')) {
            coverage.push({ check: 'redirects', page: ctx.pageUrl, state: 'unknown', reason: 'unsupported_runtime_behavior' });
          }
          continue;
        }
        let resolved;
        try { resolved = new URL(nav.value.trim(), ctx.baseUrl).href; } catch { continue; }
        if (!/^https?:/i.test(resolved)) continue;
        const evidence = {
          snippet: escapeControlChars(`${nav.kind}: ${nav.value}`).slice(0, 200),
          sourceUrl: s.source === 'external' && s.url ? s.url : ctx.finalUrl,
          location: { type: 'script_range' },
          matchedValue: escapeControlChars(nav.value).slice(0, 256),
          normalizedValue: escapeControlChars(resolved).slice(0, 2048),
          context: `${s.source} script, offset ${nav.start}-${nav.end}, ${nav.topLevel ? 'top level' : 'inside a function'}`,
        };
        findings.push({
          detector: 'redirects', ruleId: 'redirect.script-navigation', category: 'redirect', proposedSeverity: 'low', confidence: 'medium',
          title: 'Script navigates to another URL', target: withoutFragment(resolved), evidence, autoTriggered: nav.topLevel,
        });
        followCandidates.push({ url: resolved, reason: 'script-navigation', priority: 1, sourceEvidence: evidence, depth: 1 });
      }
    }

    const hosts = ctx.chain.map((e) => hostOf(e.url)).filter(Boolean);
    if (hosts.length >= 2) {
      const chainEvidence = (matched) => ({
        snippet: escapeControlChars(hosts.join(' -> ')).slice(0, 200),
        sourceUrl: ctx.chain[0].url,
        location: { type: 'response_header' },
        matchedValue: escapeControlChars(matched).slice(0, 256),
        normalizedValue: escapeControlChars(ctx.finalUrl).slice(0, 2048),
        context: `${ctx.chain.length} responses`,
      });
      let crossings = 0;
      for (let i = 1; i < hosts.length; i++) if (crossesRegistrableDomain(hosts[i - 1], hosts[i])) crossings++;
      const distinct = new Set(hosts.map((h) => registrableDomain(h) ?? h));
      if (crossings > 0) {
        findings.push({
          detector: 'redirects', ruleId: 'redirect.chain-cross-domain', category: 'redirect',
          proposedSeverity: distinct.size >= 3 ? 'medium' : 'low', confidence: 'high',
          title: 'HTTP redirects cross registrable domains', target: withoutFragment(ctx.finalUrl), evidence: chainEvidence(`${crossings} domain crossing(s)`),
        });
      } else if (stripWww(hosts[0]) !== stripWww(hosts[hosts.length - 1])) {
        findings.push({
          detector: 'redirects', ruleId: 'redirect.final-host-differs', category: 'redirect', proposedSeverity: 'info', confidence: 'high',
          title: 'Final host differs from the requested host', target: withoutFragment(ctx.finalUrl), evidence: chainEvidence(hosts[hosts.length - 1]),
        });
      }
    }

    return { findings, followCandidates, coverage };
  },
};
