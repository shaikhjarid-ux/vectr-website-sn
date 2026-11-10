// header-hints: Content-Disposition and executable Content-Type hints on a
// response. The engine runs this on the root response and on every followed
// response with that response's own headers. Observations, not verdicts.
import { extensionOfFilename, PAYLOAD_EXTENSIONS } from '../parse/url.js';
import { withoutFragment, escapeControlChars } from './util.js';

const EXECUTABLE_TYPES = new Set([
  'application/x-msdownload', 'application/vnd.microsoft.portable-executable', 'application/x-dosexec',
  'application/x-msdos-program', 'application/java-archive',
]);

/** Split on semicolons that are not inside a quoted string. */
function splitParams(value) {
  const parts = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (quoted && c === '\\' && i + 1 < value.length) { cur += c + value[++i]; continue; }
    if (c === '"') quoted = !quoted;
    if (c === ';' && !quoted) { parts.push(cur); cur = ''; } else cur += c;
  }
  parts.push(cur);
  return parts;
}

function unquote(v) {
  const t = v.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) return t.slice(1, -1).replace(/\\(.)/g, '$1');
  return t;
}

/** RFC 5987 `charset'lang'percent-encoded`; null when malformed. */
function decodeExtValue(v) {
  const m = /^([^']*)'[^']*'(.*)$/s.exec(v.trim());
  if (!m) return null;
  const charset = (m[1] || 'utf-8').toLowerCase();
  if (/%(?![0-9a-f]{2})/i.test(m[2])) return null;
  const bytes = [];
  for (let i = 0; i < m[2].length; i++) {
    if (m[2][i] === '%') { bytes.push(parseInt(m[2].slice(i + 1, i + 3), 16)); i += 2; } else bytes.push(m[2].charCodeAt(i) & 0xff);
  }
  try {
    return new TextDecoder(charset === 'iso-8859-1' ? 'windows-1252' : charset, { fatal: true }).decode(Uint8Array.from(bytes));
  } catch { return null; }
}

/**
 * @param {string} value
 * @returns {{type: string, filename: string | null}}
 */
export function parseContentDisposition(value) {
  const parts = splitParams(String(value ?? ''));
  const type = parts[0].trim().toLowerCase();
  let plain = null;
  let ext = null;
  for (const p of parts.slice(1)) {
    const eq = p.indexOf('=');
    if (eq < 0) continue;
    const name = p.slice(0, eq).trim().toLowerCase();
    const val = p.slice(eq + 1);
    if (name === 'filename*') ext = decodeExtValue(val) ?? ext;
    else if (name === 'filename') plain = unquote(val);
  }
  return { type, filename: ext ?? plain };
}

const header = (headers, name) => {
  for (const [k, v] of Object.entries(headers ?? {})) if (k.toLowerCase() === name) return v;
  return undefined;
};

/** @type {import('./index.js').Detector} */
export const headerHints = {
  id: 'header-hints',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const target = withoutFragment(ctx.finalUrl);
    const evidence = (name, raw, matched, context) => ({
      snippet: escapeControlChars(`${name}: ${raw}`).slice(0, 200),
      sourceUrl: ctx.finalUrl,
      location: { type: 'response_header', attribute: name },
      matchedValue: escapeControlChars(matched).slice(0, 256),
      normalizedValue: escapeControlChars(matched).slice(0, 256),
      context,
    });

    const cd = header(ctx.headers, 'content-disposition');
    if (cd) {
      const { type, filename } = parseContentDisposition(cd);
      if (type === 'attachment') {
        const ext = filename ? extensionOfFilename(filename) : null;
        const payload = Boolean(ext && PAYLOAD_EXTENSIONS.has(ext));
        findings.push({
          detector: 'header-hints', ruleId: 'header.content-disposition-attachment', category: 'distribution',
          proposedSeverity: payload ? 'low' : 'info', confidence: 'medium',
          title: payload ? 'Response is served as a download with an executable-looking file name' : 'Response is served as a download',
          target, evidence: evidence('content-disposition', cd, filename ?? cd, filename ? 'filename from Content-Disposition' : 'no filename given'),
        });
      }
    }

    const ct = header(ctx.headers, 'content-type');
    const mime = ct ? ct.split(';')[0].trim().toLowerCase() : '';
    if (EXECUTABLE_TYPES.has(mime)) {
      findings.push({
        detector: 'header-hints', ruleId: 'header.executable-content-type', category: 'distribution', proposedSeverity: 'low', confidence: 'medium',
        title: 'Response declares an executable content type', target, evidence: evidence('content-type', ct, mime, 'declared content type'),
      });
    }
    return { findings };
  },
};
