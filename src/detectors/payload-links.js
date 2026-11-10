// payload-links: executable-looking and archive links in HTML, CSS and srcset
// references. A weak indicator: it means an executable-looking link was found,
// not that the file is malicious.
import { extensionOf, extensionOfFilename, queryFilenames, PAYLOAD_EXTENSIONS } from '../parse/url.js';
import { makeLocator, evidenceFromRef, withoutFragment } from './util.js';

const ARCHIVES = new Set(['zip', 'rar', '7z']);

const RULES = {
  'payload.link.executable': { title: 'Executable-looking link', confidence: 'medium' },
  'payload.link.archive': { title: 'Archive link', confidence: 'medium' },
  'payload.link.query-filename': { title: 'Link with an executable-looking filename parameter', confidence: 'low' },
};

/**
 * @param {string} url
 * @returns {{ruleId: 'payload.link.executable' | 'payload.link.archive' | 'payload.link.query-filename', severity: 'info' | 'low', extension: string} | null}
 */
export function classifyPayloadUrl(url) {
  const ext = extensionOf(url);
  if (ext && PAYLOAD_EXTENSIONS.has(ext)) {
    return ARCHIVES.has(ext)
      ? { ruleId: 'payload.link.archive', severity: 'info', extension: ext }
      : { ruleId: 'payload.link.executable', severity: 'low', extension: ext };
  }
  for (const name of queryFilenames(url)) {
    const e = extensionOfFilename(name);
    if (e && PAYLOAD_EXTENSIONS.has(e)) return { ruleId: 'payload.link.query-filename', severity: 'low', extension: e };
  }
  return null;
}

/** @type {import('./index.js').Detector} */
export const payloadLinks = {
  id: 'payload-links',
  version: '1.0.0',
  run(ctx) {
    const locate = makeLocator(ctx.html);
    const findings = [];
    for (const ref of ctx.refs) {
      if (!ref.resolved || !/^https?:/i.test(ref.resolved)) continue;
      const hit = classifyPayloadUrl(ref.resolved);
      if (!hit) continue;
      const rule = RULES[hit.ruleId];
      findings.push({
        detector: 'payload-links',
        ruleId: hit.ruleId,
        category: 'payload',
        proposedSeverity: hit.severity,
        confidence: rule.confidence,
        title: rule.title,
        target: withoutFragment(ref.resolved),
        evidence: evidenceFromRef(ctx, ref, locate),
      });
    }
    return { findings };
  },
};
