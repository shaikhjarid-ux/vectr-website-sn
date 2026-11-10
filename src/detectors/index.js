// Detector framework: run detectors defensively, then group raw detections
// into findings and apply the severity rules (spec section 13).
import { makeFingerprint } from '../shared/url-safety.js';
import { SEVERITIES, CONFIDENCES } from '../schema/report.js';
import { extensionOf, extensionOfFilename, queryFilenames, PAYLOAD_EXTENSIONS } from '../parse/url.js';

/**
 * @typedef {import('../schema/report.js').Evidence} Evidence
 * @typedef {import('../schema/report.js').Finding} Finding
 * @typedef {import('../schema/report.js').ChainEntry} ChainEntry
 * @typedef {import('../schema/report.js').CoverageEntry} CoverageEntry
 * @typedef {import('../schema/report.js').Severity} Severity
 * @typedef {import('../schema/report.js').Confidence} Confidence
 * @typedef {import('../schema/report.js').Category} Category
 * @typedef {import('../parse/html.js').UrlRef} UrlRef
 * @typedef {import('../parse/html.js').HtmlTree} HtmlTree
 * @typedef {{pageUrl: string, finalUrl: string, baseUrl: string, html: string, tree: HtmlTree, headers: Record<string, string>, chain: ChainEntry[], refs: UrlRef[], scripts: (import('../analysis/fold.js').ScriptAnalysis & {source: 'inline' | 'external', url?: string})[]}} DetectorContext
 * @typedef {{detector: string, ruleId: string, category: Category, proposedSeverity: Severity, confidence: Confidence, title: string, target: string, evidence: Evidence, autoTriggered?: boolean}} RawFinding
 * @typedef {{url: string, reason: string, priority: 1 | 2 | 3, sourceEvidence: Evidence, depth: 1}} Candidate
 * @typedef {{id: string, version: string, run(ctx: DetectorContext): {findings: RawFinding[], followCandidates?: Candidate[], coverage?: CoverageEntry[]} | Promise<{findings: RawFinding[], followCandidates?: Candidate[], coverage?: CoverageEntry[]}>}} Detector
 */

const MAX_OBSERVATIONS = 20;
const WEAK_RULES = new Set(['uri.blob-reference', 'uri.javascript-href', 'filename.homoglyph']);
const isWeak = (ruleId) => ruleId.startsWith('payload.link.') || WEAK_RULES.has(ruleId);
const sevRank = (s) => SEVERITIES.indexOf(s);
const confRank = (c) => CONFIDENCES.indexOf(c);
const atLeastMedium = (s) => sevRank(s) >= sevRank('medium');

/**
 * @param {DetectorContext} ctx
 * @param {Detector[]} detectors
 * @returns {Promise<{raw: RawFinding[], candidates: Candidate[], coverage: CoverageEntry[]}>}
 */
export async function runDetectors(ctx, detectors) {
  /** @type {RawFinding[]} */
  const raw = [];
  /** @type {Candidate[]} */
  const candidates = [];
  /** @type {CoverageEntry[]} */
  const coverage = [];
  for (const d of detectors) {
    try {
      const out = await d.run(ctx);
      raw.push(...(out?.findings ?? []));
      candidates.push(...(out?.followCandidates ?? []));
      const own = out?.coverage ?? [];
      coverage.push(...own);
      if (!own.some((c) => c.check === d.id)) coverage.push({ check: d.id, page: ctx.pageUrl, state: 'ok' });
    } catch {
      coverage.push({ check: d.id, page: ctx.pageUrl, state: 'unknown', reason: 'detector_failed' });
    }
  }
  return { raw, candidates, coverage };
}

function hasPayloadExtension(target) {
  const ext = extensionOf(target);
  if (ext && PAYLOAD_EXTENSIONS.has(ext)) return true;
  return queryFilenames(target).some((n) => PAYLOAD_EXTENSIONS.has(extensionOfFilename(n) ?? ''));
}

/**
 * Group raw detections by (ruleId, target) and apply the severity rules.
 * @param {RawFinding[]} raw
 * @returns {Promise<Finding[]>}
 */
export async function finalizeFindings(raw) {
  const groups = new Map();
  for (const r of raw) {
    const fingerprint = await makeFingerprint(r.ruleId, r.target);
    let g = groups.get(fingerprint);
    if (!g) {
      g = { fingerprint, ruleId: r.ruleId, detector: r.detector, category: r.category, title: r.title, target: r.target, raws: [], observations: [], maxProposed: r.proposedSeverity };
      groups.set(fingerprint, g);
    }
    g.raws.push(r);
    if (sevRank(r.proposedSeverity) > sevRank(g.maxProposed)) g.maxProposed = r.proposedSeverity;
    if (g.observations.length < MAX_OBSERVATIONS) g.observations.push({ evidence: r.evidence });
  }

  const byTarget = new Map();
  for (const g of groups.values()) {
    const list = byTarget.get(g.target) ?? [];
    list.push(g);
    byTarget.set(g.target, list);
  }

  /** @type {Finding[]} */
  const findings = [];
  for (const g of groups.values()) {
    const siblings = (byTarget.get(g.target) ?? []).filter((o) => o !== g);
    let severity = g.maxProposed;
    if (isWeak(g.ruleId) && siblings.length === 0 && sevRank(severity) > sevRank('low')) severity = 'low';
    if (severity === 'high') {
      const autoTrigger = g.raws.some((r) => r.autoTriggered) && hasPayloadExtension(g.target);
      const corroborated = atLeastMedium(g.maxProposed)
        && siblings.some((o) => o.detector !== g.detector && atLeastMedium(o.maxProposed));
      if (!autoTrigger && !corroborated) severity = 'medium';
    }
    const atSeverity = g.raws.filter((r) => r.proposedSeverity === severity);
    const pool = atSeverity.length > 0 ? atSeverity : g.raws;
    const confidence = pool.reduce((best, r) => (confRank(r.confidence) > confRank(best) ? r.confidence : best), pool[0].confidence);
    findings.push({
      id: `${g.ruleId}:${g.fingerprint.slice(0, 12)}`,
      fingerprint: g.fingerprint,
      detector: g.detector,
      ruleId: g.ruleId,
      category: g.category,
      severity,
      confidence,
      title: g.title,
      observations: g.observations,
      observationCount: g.raws.length,
    });
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.ruleId.localeCompare(b.ruleId) || a.id.localeCompare(b.id));
  return findings;
}
