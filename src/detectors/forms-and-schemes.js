// off-origin-forms and uri-schemes. Weak indicators: an off-origin form means
// it posts elsewhere, not that credentials are stolen; a data: or ms-* link
// means a download or handler launch path exists, not that it is malicious.
import { crossesRegistrableDomain } from '../net/psl.js';
import { walkElements, snippetAround } from '../parse/html.js';
import { makeLocator, evidenceFromRef, withoutFragment, escapeControlChars } from './util.js';

const attr = (el, name) => el.attrs.find((a) => a.name === name)?.value;

function* descendantElements(el, cap = 2000) {
  const stack = [...(el.childNodes ?? [])].reverse();
  let n = 0;
  while (stack.length && n++ < cap) {
    const node = stack.pop();
    if (typeof node.tagName === 'string') yield node;
    if (node.childNodes) stack.push(...[...node.childNodes].reverse());
  }
}

/** @type {import('./index.js').Detector} */
export const offOriginForms = {
  id: 'off-origin-forms',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const locate = makeLocator(ctx.html);
    let pageHost;
    try { pageHost = new URL(ctx.finalUrl).hostname; } catch { return { findings }; }

    for (const form of walkElements(ctx.tree)) {
      if (form.tagName !== 'form') continue;
      const action = attr(form, 'action');
      if (!action || !action.trim()) continue;
      let resolved;
      try { resolved = new URL(action.trim(), ctx.baseUrl); } catch { continue; }
      if (!/^https?:$/.test(resolved.protocol) || !crossesRegistrableDomain(pageHost, resolved.hostname)) continue;

      const loc = form.sourceCodeLocation?.attrs?.action ?? form.sourceCodeLocation;
      const location = { type: 'html_attribute', tag: 'form', attribute: 'action' };
      if (loc?.startLine) location.line = loc.startLine;
      if (loc?.startCol) location.column = loc.startCol;
      const offset = locate(loc?.startLine ?? null, loc?.startCol ?? null);
      const evidence = {
        snippet: escapeControlChars(offset === null ? `<form action="${action}">` : snippetAround(ctx.html, offset)).slice(0, 200),
        sourceUrl: ctx.finalUrl, location,
        matchedValue: escapeControlChars(action).slice(0, 256), normalizedValue: escapeControlChars(resolved.href).slice(0, 2048), context: '',
      };
      const target = withoutFragment(resolved.href);
      findings.push({ detector: 'off-origin-forms', ruleId: 'form.off-origin-action', category: 'credential', proposedSeverity: 'low', confidence: 'medium', title: 'Form posts to another site', target, evidence });
      const hasPassword = [...descendantElements(form)].some((e) => e.tagName === 'input' && (attr(e, 'type') ?? '').trim().toLowerCase() === 'password');
      if (hasPassword) {
        findings.push({ detector: 'off-origin-forms', ruleId: 'form.password-off-origin', category: 'credential', proposedSeverity: 'medium', confidence: 'medium', title: 'Password field in a form that posts to another site', target, evidence: { ...evidence, context: 'form contains a password input' } });
      }
    }
    return { findings };
  },
};

const DATA_DOWNLOAD_TYPES = new Set([
  'application/x-msdownload', 'application/vnd.microsoft.portable-executable', 'application/x-dosexec', 'application/x-msdos-program',
  'application/java-archive', 'application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed', 'application/vnd.rar',
  'application/x-7z-compressed', 'application/x-apple-diskimage', 'application/vnd.android.package-archive', 'application/x-iso9660-image',
  'application/x-msi', 'application/x-sh', 'application/x-bat',
]);
const MS_HANDLERS = new Set(['ms-appinstaller:', 'ms-msdt:']);

/** @type {import('./index.js').Detector} */
export const uriSchemes = {
  id: 'uri-schemes',
  version: '1.0.0',
  run(ctx) {
    const findings = [];
    const coverage = [];
    const locate = makeLocator(ctx.html);

    const downloadAnchors = new Set();
    for (const el of walkElements(ctx.tree)) {
      if ((el.tagName === 'a' || el.tagName === 'area') && el.attrs.some((a) => a.name === 'download')) {
        const l = el.sourceCodeLocation?.attrs?.href;
        if (l) downloadAnchors.add(`${l.startLine}:${l.startCol}`);
      }
    }

    const add = (ruleId, category, severity, confidence, title, target, ref) => {
      const evidence = evidenceFromRef(ctx, ref, locate);
      evidence.matchedValue = evidence.matchedValue.slice(0, 256);
      evidence.normalizedValue = evidence.normalizedValue.slice(0, 256);
      findings.push({ detector: 'uri-schemes', ruleId, category, proposedSeverity: severity, confidence, title, target, evidence });
    };

    let blobSeen = false;
    for (const ref of ctx.refs) {
      if (!ref.resolved) continue;
      let protocol;
      try { protocol = new URL(ref.resolved).protocol; } catch { continue; }
      const target = ref.resolved.slice(0, 80);

      if (protocol === 'data:') {
        const mime = (/^data:([^;,]*)/i.exec(ref.resolved)?.[1] ?? '').trim().toLowerCase();
        const download = downloadAnchors.has(`${ref.line}:${ref.column}`);
        if (DATA_DOWNLOAD_TYPES.has(mime) || download) {
          add('uri.data-download', 'distribution', 'medium', 'medium', 'data: URL used for a file download', target, ref);
        }
      } else if (protocol === 'blob:') {
        add('uri.blob-reference', 'distribution', 'info', 'medium', 'blob: reference to a runtime resource that was not inspected', ref.resolved.slice(0, 200), ref);
        if (!blobSeen) {
          blobSeen = true;
          coverage.push({ check: 'uri-schemes', page: ctx.pageUrl, state: 'skipped', reason: 'blob_not_inspected' });
        }
      } else if (protocol === 'javascript:' && ref.attribute === 'href') {
        add('uri.javascript-href', 'interface', 'info', 'medium', 'javascript: link', target, ref);
      } else if (MS_HANDLERS.has(protocol)) {
        add('uri.ms-handler', 'distribution', 'medium', 'medium', 'Windows protocol handler link that can launch an installer or tool', target, ref);
      }
    }
    return { findings, coverage };
  },
};
