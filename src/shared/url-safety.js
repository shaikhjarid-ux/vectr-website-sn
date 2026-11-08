// Redaction, defanging and fingerprinting. Every report field, export and
// display passes through these helpers; original URLs live only in transient
// scan state needed to perform fetches.

const SECRET_NAMES = new Set([
  'token', 'key', 'auth', 'session', 'signature',
  'access_token', 'apikey', 'api_key', 'password', 'secret',
]);

// A parameter is `name=value` preceded by ? & ; or # (fragment parameters such
// as OAuth `#access_token=` carry secrets too).
const PARAM = /([?&;#])([^=&#;\s"'<>]*)=([^&#;\s"'<>]*)/g;

function redactParams(s) {
  return s.replace(PARAM, (m, lead, name) => {
    let decoded = name;
    try { decoded = decodeURIComponent(name); } catch { /* keep raw name */ }
    return SECRET_NAMES.has(decoded.toLowerCase()) ? `${lead}${name}=REDACTED` : m;
  });
}

/** @param {string} url */
export function redactUrl(url) {
  if (typeof url !== 'string') return url;
  try { new URL(url); } catch { return url; }
  return redactParams(url);
}

/** @param {string} text */
export function redactText(text) {
  return typeof text === 'string' ? redactParams(text) : text;
}

/** @param {string} url */
export function defang(url) {
  if (typeof url !== 'string') return url;
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(url);
  if (!m) return url;
  const scheme = m[1].replace(/^http/i, 'hxxp');
  return `${scheme}://${m[2].replace(/\./g, '[.]')}${m[3]}`;
}

/** @param {string} url */
export function displayUrl(url) {
  return defang(redactUrl(url));
}

/**
 * @param {string} ruleId
 * @param {string} normalizedTarget
 * @returns {Promise<string>} hex SHA-256 of ruleId + "\n" + redactUrl(normalizedTarget)
 */
export async function makeFingerprint(ruleId, normalizedTarget) {
  const data = new TextEncoder().encode(`${ruleId}\n${redactUrl(normalizedTarget)}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const mapIf = (obj, key, fn) => {
  if (obj && typeof obj[key] === 'string') obj[key] = fn(obj[key]);
};

function sanitizeChainEntry(e) {
  if (typeof e === 'string') return redactUrl(e);
  if (e && typeof e === 'object') {
    mapIf(e, 'url', redactUrl);
    mapIf(e, 'location', redactUrl);
    mapIf(e, 'note', redactText);
  }
  return e;
}

function sanitizeEvidence(ev) {
  if (!ev || typeof ev !== 'object') return;
  mapIf(ev, 'sourceUrl', redactUrl);
  for (const k of ['snippet', 'matchedValue', 'normalizedValue', 'context']) mapIf(ev, k, redactText);
}

/**
 * Deep copy of a report with every URL-bearing field redacted.
 * @param {object} report
 */
export function sanitizeReport(report) {
  const r = structuredClone(report);
  mapIf(r, 'target', redactUrl);
  mapIf(r, 'finalUrl', redactUrl);
  for (const p of Array.isArray(r.pagesScanned) ? r.pagesScanned : []) {
    mapIf(p, 'url', redactUrl);
    if (Array.isArray(p.redirectChain)) p.redirectChain = p.redirectChain.map(sanitizeChainEntry);
  }
  for (const f of Array.isArray(r.findings) ? r.findings : []) {
    mapIf(f, 'title', redactText);
    mapIf(f, 'target', redactUrl);
    for (const o of Array.isArray(f.observations) ? f.observations : []) {
      if (o && typeof o === 'object') sanitizeEvidence(o.evidence ?? o);
    }
  }
  for (const c of Array.isArray(r.coverage) ? r.coverage : []) mapIf(c, 'page', redactUrl);
  if (r.headers && typeof r.headers === 'object') {
    for (const k of Object.keys(r.headers)) {
      if (typeof r.headers[k] === 'string') r.headers[k] = redactText(r.headers[k]);
    }
  }
  return r;
}
