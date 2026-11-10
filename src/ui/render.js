// Safe rendering. Every target-controlled string enters the DOM through
// textContent only; elements are created with createElement. No element is
// given an href, src or style derived from report content, so displaying a URL
// can never make the browser fetch it. Payload URLs are defanged and
// non-clickable. Every path runs sanitizeReport first.
import { sanitizeReport, defang, displayUrl, redactText } from '../shared/url-safety.js';
import { escapeControlChars } from '../detectors/util.js';

export const DISCLAIMER = 'No detected findings does not establish that a website is safe. This scanner performs static analysis only; it cannot observe all runtime behavior or determine whether a downloaded file is malicious. An incomplete scan is shown as incomplete, not clean.';

const SEVERITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const SEVERITY_CLASS = {
  high: 'border-red-800 bg-red-50 text-red-900',
  medium: 'border-amber-800 bg-amber-50 text-amber-950',
  low: 'border-sky-800 bg-sky-50 text-sky-950',
  info: 'border-slate-600 bg-slate-100 text-slate-900',
};
const PHASE_TEXT = {
  fetching: 'Fetching the page…',
  parsing: 'Reading the page…',
  following: 'Checking linked pages…',
  analyzing: 'Analyzing scripts and links…',
  done: 'Scan finished.',
};
const FOCUS = 'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-800';

const wellFormed = (s) => (typeof s.toWellFormed === 'function' ? s.toWellFormed() : s);
const URL_IN_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)]+/gi;

/** Text safe to show: URLs defanged, lone surrogates replaced, control and bidi-override characters made visible. */
function t(value) {
  const s = wellFormed(String(value ?? ''));
  return escapeControlChars(s.replace(URL_IN_TEXT, (m) => (/^hxxps?:/i.test(m) ? m : defang(m))));
}

function el(doc, tag, props = {}, children = []) {
  const node = doc.createElement(tag);
  if (props.class) node.className = props.class;
  if (props.text !== undefined) node.textContent = props.text;
  if (props.id) node.id = props.id;
  if (props.role) node.setAttribute('role', props.role);
  if (props.labelledby) node.setAttribute('aria-labelledby', props.labelledby);
  if (props.type) node.setAttribute('type', props.type);
  for (const c of children) node.append(c);
  return node;
}

function row(doc, label, value) {
  return [el(doc, 'dt', { class: 'font-semibold text-slate-700', text: label }), el(doc, 'dd', { class: 'break-words', text: value })];
}

function dl(doc, rows) {
  const list = el(doc, 'dl', { class: 'grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[10rem_1fr]' });
  for (const [label, value] of rows) list.append(...row(doc, label, value));
  return list;
}

const isComplete = (report) => report.finalUrl !== null && report.pagesScanned.length > 0 && report.coverage.every((c) => c.state === 'ok');

function copyButton(doc, label, text) {
  const b = el(doc, 'button', { class: `rounded border border-slate-700 px-2 py-1 text-sm ${FOCUS}`, text: label, type: 'button' });
  b.addEventListener('click', () => {
    const nav = doc.defaultView?.navigator;
    if (nav?.clipboard?.writeText) nav.clipboard.writeText(text).catch(() => {});
  });
  return b;
}

function locationText(loc) {
  if (!loc) return 'unknown';
  const parts = [];
  if (loc.tag) parts.push(`<${loc.tag}>`);
  if (loc.attribute) parts.push(loc.attribute);
  if (parts.length === 0) parts.push(loc.type ?? 'unknown');
  if (loc.line) parts.push(`line ${loc.line}${loc.column ? `, column ${loc.column}` : ''}`);
  return parts.join(' ');
}

function renderObservation(doc, ev) {
  const li = el(doc, 'li', { class: 'rounded border border-slate-300 p-2' });
  li.append(dl(doc, [
    ['Where', t(locationText(ev.location))],
    ['Source page', t(ev.sourceUrl)],
    ['Matched value', t(ev.matchedValue)],
    ['Normalized value', t(ev.normalizedValue)],
    ...(ev.context ? [['Why it matched', t(ev.context)]] : []),
  ]));
  li.append(el(doc, 'pre', { class: 'mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-100 p-2 text-sm' }, [el(doc, 'code', { text: t(ev.snippet) })]));
  if (/^https?:\/\//i.test(ev.normalizedValue ?? '')) {
    li.append(el(doc, 'div', { class: 'mt-2' }, [copyButton(doc, 'Copy URL (secrets redacted)', ev.normalizedValue)]));
  }
  return li;
}

function renderFinding(doc, f, index) {
  const id = `finding-${index}`;
  const card = el(doc, 'details', { class: 'rounded-lg border border-slate-400 bg-white p-3' });
  const label = SEVERITY_LABEL[f.severity] ?? f.severity;
  const summary = el(doc, 'summary', { class: `cursor-pointer font-semibold ${FOCUS}` });
  summary.append(
    el(doc, 'span', { class: `mr-2 inline-block rounded border px-2 py-0.5 text-sm ${SEVERITY_CLASS[f.severity] ?? SEVERITY_CLASS.info}`, text: label }),
    el(doc, 'span', { id, text: t(f.title) }),
  );
  card.append(summary);
  const first = f.observations[0]?.evidence;
  card.append(dl(doc, [
    ['Severity', label],
    ['Confidence', t(f.confidence)],
    ['Category', t(f.category)],
    ['Rule', t(f.ruleId)],
    ['Source page', t(first ? first.sourceUrl : 'unknown')],
    ['Element and attribute', t(first ? locationText(first.location) : 'unknown')],
    ['Observations', f.observationCount > f.observations.length ? `${f.observationCount} (showing ${f.observations.length})` : String(f.observationCount)],
  ]));
  const list = el(doc, 'ul', { class: 'mt-3 space-y-2' });
  for (const o of f.observations) list.append(renderObservation(doc, o.evidence));
  card.append(list);
  return card;
}

function coverageSection(doc, report) {
  const section = el(doc, 'section', { class: 'rounded-lg border border-amber-800 bg-amber-50 p-3', labelledby: 'coverage-heading' });
  section.append(el(doc, 'h2', { id: 'coverage-heading', class: 'text-lg font-semibold', text: 'Scan coverage: incomplete' }));
  section.append(el(doc, 'p', { class: 'mt-1', text: 'Some checks did not run or could not reach a reliable conclusion. Findings below cover only what was inspected.' }));
  const list = el(doc, 'ul', { class: 'mt-2 list-disc space-y-1 pl-5' });
  if (report.finalUrl === null) list.append(el(doc, 'li', { text: 'The page could not be fetched, so nothing was inspected.' }));
  for (const c of report.coverage) {
    const parts = [t(c.check), t(c.state)];
    if (c.reason) parts.push(t(c.reason));
    if (c.page) parts.push(t(c.page));
    list.append(el(doc, 'li', { text: parts.join(' — ') }));
  }
  section.append(list);
  return section;
}

/**
 * @param {import('../schema/report.js').Report} report
 * @param {HTMLElement} root
 */
export function renderReport(report, root) {
  const r = sanitizeReport(report);
  const doc = root.ownerDocument;
  root.replaceChildren();

  const complete = isComplete(r);
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of r.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const overview = el(doc, 'section', { class: 'rounded-lg border border-slate-400 bg-white p-3', labelledby: 'overview-heading' });
  overview.append(el(doc, 'h2', { id: 'overview-heading', class: 'text-lg font-semibold', text: 'Scan overview' }));
  overview.append(dl(doc, [
    ['Scanned address', t(r.target)],
    ['Final address', r.finalUrl ? t(r.finalUrl) : 'not reached'],
    ['Findings', `${r.findings.length} (${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info)`],
    ['Scan coverage', complete ? 'Complete for the pages and checks listed' : 'Incomplete — see the coverage panel'],
    ['Pages inspected', String(r.pagesScanned.length)],
  ]));
  root.append(overview);

  if (!complete) root.append(coverageSection(doc, r));

  const findings = el(doc, 'section', { class: 'space-y-3', labelledby: 'findings-heading' });
  findings.append(el(doc, 'h2', { id: 'findings-heading', class: 'text-lg font-semibold', text: 'Findings' }));
  if (r.findings.length === 0) findings.append(el(doc, 'p', { text: 'No findings were detected in the scanned scope.' }));
  r.findings.forEach((f, i) => findings.append(renderFinding(doc, f, i)));
  root.append(findings);

  root.append(el(doc, 'p', { class: 'rounded border border-slate-500 bg-slate-100 p-3 text-sm', id: 'disclaimer', text: DISCLAIMER }));
}

/**
 * @param {{phase: 'fetching' | 'parsing' | 'following' | 'analyzing' | 'done', detail?: string}} state
 * @param {HTMLElement} root an element with aria-live="polite"
 */
export function renderProgress(state, root) {
  const doc = root.ownerDocument;
  root.replaceChildren(el(doc, 'p', { text: PHASE_TEXT[state.phase] ?? 'Working…' }));
}

/** @param {import('../schema/report.js').Report} report */
export function reportToSummaryText(report) {
  const r = sanitizeReport(report);
  const lines = [
    `Scan of ${displayUrl(r.target)}`,
    `Scanned at ${r.scannedAt}`,
    `Scan coverage: ${isComplete(r) ? 'complete for the pages and checks listed' : 'INCOMPLETE'}`,
    `Findings: ${r.findings.length}`,
  ];
  for (const f of r.findings) {
    const first = f.observations[0]?.evidence;
    lines.push(`- [${SEVERITY_LABEL[f.severity] ?? f.severity}] ${f.title} (${f.ruleId}, ${f.confidence} confidence)${first ? ` — ${displayUrl(first.sourceUrl)}` : ''}`);
  }
  const gaps = r.coverage.filter((c) => c.state !== 'ok');
  if (gaps.length) {
    lines.push('Coverage gaps:');
    for (const c of gaps) lines.push(`- ${c.check}: ${c.state}${c.reason ? ` (${c.reason})` : ''}${c.page ? ` — ${displayUrl(c.page)}` : ''}`);
  }
  lines.push('', DISCLAIMER);
  return lines.map((l) => escapeControlChars(wellFormed(redactText(l)))).join('\n');
}

/** @param {import('../schema/report.js').Report} report */
export function exportReportJson(report) {
  return JSON.stringify(sanitizeReport(report), null, 2);
}
