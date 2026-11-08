// Report schema (spec section 13): typedefs, constants and a dependency-free validator.

export const SEVERITIES = ['info', 'low', 'medium', 'high'];
export const CONFIDENCES = ['low', 'medium', 'high'];
export const CATEGORIES = ['payload', 'obfuscation', 'redirect', 'filename', 'interface', 'credential', 'distribution', 'infrastructure'];
export const COVERAGE_STATES = ['ok', 'unknown', 'skipped'];

/** @typedef {'info'|'low'|'medium'|'high'} Severity */
/** @typedef {'low'|'medium'|'high'} Confidence */
/** @typedef {'payload'|'obfuscation'|'redirect'|'filename'|'interface'|'credential'|'distribution'|'infrastructure'} Category */
/** @typedef {{url: string, status: number, location?: string, note?: string}} ChainEntry */
/** @typedef {{snippet: string, sourceUrl: string, location: {type: 'html_attribute'|'script_range'|'response_header', tag?: string, attribute?: string, line?: number, column?: number}, matchedValue: string, normalizedValue: string, context: string}} Evidence */
/** @typedef {{check: string, page?: string, state: 'ok'|'unknown'|'skipped', reason?: string}} CoverageEntry */
/** @typedef {{id: string, fingerprint: string, detector: string, ruleId: string, category: Category, severity: Severity, confidence: Confidence, title: string, observations: {evidence: Evidence}[], observationCount: number}} Finding */
/** @typedef {{v: 1, engineVersion: string, detectorVersions: Record<string, string>, scannedAt: string, durationMs: number, target: string, finalUrl: string|null, pagesScanned: {url: string, status: number|null, contentType: string, bytesRead: number, truncated: boolean, redirectChain: ChainEntry[]}[], findings: Finding[], coverage: CoverageEntry[], fetchStats: {attempted: number, successful: number, cached: number, failed: number}, headers: Record<string, string>}} Report */

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/**
 * @param {unknown} report
 * @returns {{ok: boolean, errors: string[]}}
 */
export function validateReport(report) {
  const errors = [];
  const need = (cond, msg) => { if (!cond) errors.push(msg); };
  if (!isObj(report)) return { ok: false, errors: ['report must be an object'] };
  const r = /** @type {Record<string, any>} */ (report);

  need(r.v === 1, 'v must be 1');
  need(typeof r.engineVersion === 'string', 'engineVersion must be a string');
  need(isObj(r.detectorVersions), 'detectorVersions must be an object');
  need(typeof r.scannedAt === 'string', 'scannedAt must be a string');
  need(typeof r.durationMs === 'number', 'durationMs must be a number');
  need(typeof r.target === 'string', 'target must be a string');
  need(r.finalUrl === null || typeof r.finalUrl === 'string', 'finalUrl must be a string or null');
  need(isObj(r.headers), 'headers must be an object');

  if (Array.isArray(r.pagesScanned)) {
    r.pagesScanned.forEach((p, i) => {
      need(isObj(p) && typeof p.url === 'string', `pagesScanned[${i}].url must be a string`);
      need(isObj(p) && Array.isArray(p.redirectChain), `pagesScanned[${i}].redirectChain must be an array`);
    });
  } else errors.push('pagesScanned must be an array');

  if (Array.isArray(r.findings)) {
    r.findings.forEach((f, i) => {
      const at = `findings[${i}]`;
      if (!isObj(f)) { errors.push(`${at} must be an object`); return; }
      for (const k of ['id', 'fingerprint', 'detector', 'ruleId', 'title']) need(typeof f[k] === 'string', `${at}.${k} must be a string`);
      need(CATEGORIES.includes(f.category), `${at}.category invalid`);
      need(SEVERITIES.includes(f.severity), `${at}.severity invalid`);
      need(CONFIDENCES.includes(f.confidence), `${at}.confidence invalid`);
      need(Array.isArray(f.observations), `${at}.observations must be an array`);
      need(Number.isInteger(f.observationCount), `${at}.observationCount must be an integer`);
    });
  } else errors.push('findings must be an array');

  if (Array.isArray(r.coverage)) {
    r.coverage.forEach((c, i) => {
      need(isObj(c) && typeof c.check === 'string', `coverage[${i}].check must be a string`);
      need(isObj(c) && COVERAGE_STATES.includes(c.state), `coverage[${i}].state invalid`);
    });
  } else errors.push('coverage must be an array');

  const fs = r.fetchStats;
  need(isObj(fs) && ['attempted', 'successful', 'cached', 'failed'].every((k) => typeof fs[k] === 'number'), 'fetchStats must hold numeric attempted, successful, cached, failed');

  return { ok: errors.length === 0, errors };
}
