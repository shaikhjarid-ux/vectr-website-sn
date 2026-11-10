// disguised-filenames: file names that try to look like something they are not.
// Weak indicators: a double extension means the name is built to mislead, not
// that the file is malicious.
import { walkElements } from '../parse/html.js';
import { normalizeForMatch, queryFilenames } from '../parse/url.js';
import { makeLocator, evidenceFromRef, withoutFragment, escapeControlChars } from './util.js';

const DOC_MEDIA = new Set('pdf doc docx xls xlsx txt jpg jpeg png gif mp3 mp4'.split(' '));
const EXECUTABLE = new Set('exe msi scr bat cmd ps1 jar vbs lnk pkg deb appimage apk dmg iso'.split(' '));
const ARCHIVE = new Set(['zip', 'rar', '7z']);
const BIDI_OR_CONTROL = /[\u202a-\u202e\u2066-\u2069]/;
const LATIN = /\p{Script=Latin}/u;
const NON_LATIN_LOOKALIKE = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

const RULES = {
  'filename.double-extension': { severity: 'medium', confidence: 'medium', title: 'Document or media extension followed by an executable one' },
  'filename.control-chars': { severity: 'medium', confidence: 'medium', title: 'Right-to-left override or control characters in a file name' },
  'filename.archive-executable': { severity: 'medium', confidence: 'medium', title: 'Archive and executable extensions combined in one file name' },
  'filename.homoglyph': { severity: 'low', confidence: 'low', title: 'Latin and look-alike letters mixed in one file name' },
};

/** @param {string} name a decoded file name; returns the rule ids it triggers */
function rulesFor(name) {
  const out = [];
  if (BIDI_OR_CONTROL.test(name)) out.push('filename.control-chars');
  const parts = name.split('.').map((p) => p.trim().toLowerCase());
  if (parts.length >= 3) {
    const last = parts[parts.length - 1];
    const prev = parts[parts.length - 2];
    if (DOC_MEDIA.has(prev) && EXECUTABLE.has(last)) out.push('filename.double-extension');
    if ((EXECUTABLE.has(prev) && ARCHIVE.has(last)) || (ARCHIVE.has(prev) && EXECUTABLE.has(last))) out.push('filename.archive-executable');
  } else if (parts.length === 2 && ((EXECUTABLE.has(parts[0]) && ARCHIVE.has(parts[1])) || (ARCHIVE.has(parts[0]) && EXECUTABLE.has(parts[1])))) {
    out.push('filename.archive-executable');
  }
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  if (LATIN.test(stem) && NON_LATIN_LOOKALIKE.test(stem)) out.push('filename.homoglyph');
  return out;
}

const lastSegment = (s) => s.split(/[/\\]/).pop() ?? '';

/** @type {import('./index.js').Detector} */
export const disguisedFilenames = {
  id: 'disguised-filenames',
  version: '1.0.0',
  run(ctx) {
    const locate = makeLocator(ctx.html);
    const findings = [];
    const emit = (ruleId, name, target, evidence) => {
      const rule = RULES[ruleId];
      findings.push({
        detector: 'disguised-filenames', ruleId, category: 'filename', proposedSeverity: rule.severity, confidence: rule.confidence,
        title: rule.title, target, evidence: { ...evidence, context: escapeControlChars(`filename: ${name}`).slice(0, 200) },
      });
    };

    for (const ref of ctx.refs) {
      if (!ref.resolved || !/^https?:/i.test(ref.resolved)) continue;
      const target = withoutFragment(ref.resolved);
      const evidence = evidenceFromRef(ctx, ref, locate);
      let pathname;
      try { pathname = new URL(ref.resolved).pathname; } catch { continue; }
      const names = [lastSegment(normalizeForMatch(pathname).url), ...queryFilenames(ref.resolved).map(lastSegment)];
      const seen = new Set();
      for (const name of names) {
        for (const ruleId of rulesFor(name)) {
          if (seen.has(`${ruleId}\n${name}`)) continue;
          seen.add(`${ruleId}\n${name}`);
          emit(ruleId, name, target, evidence);
        }
      }
    }

    for (const el of walkElements(ctx.tree)) {
      if (el.tagName !== 'a' && el.tagName !== 'area') continue;
      const dl = el.attrs.find((a) => a.name === 'download');
      if (!dl || !dl.value.trim()) continue;
      const name = lastSegment(dl.value);
      const href = el.attrs.find((a) => a.name === 'href');
      let target = name;
      if (href) { try { target = withoutFragment(new URL(href.value, ctx.baseUrl).href); } catch { /* keep the file name */ } }
      const loc = el.sourceCodeLocation?.attrs?.download ?? el.sourceCodeLocation;
      const location = { type: 'html_attribute', tag: el.tagName, attribute: 'download' };
      if (loc?.startLine) location.line = loc.startLine;
      if (loc?.startCol) location.column = loc.startCol;
      const evidence = {
        snippet: escapeControlChars(`<${el.tagName} download="${dl.value}">`).slice(0, 200),
        sourceUrl: ctx.finalUrl, location,
        matchedValue: escapeControlChars(dl.value).slice(0, 256), normalizedValue: escapeControlChars(name).slice(0, 256), context: '',
      };
      for (const ruleId of rulesFor(name)) emit(ruleId, name, target, evidence);
    }
    return { findings };
  },
};
