// startApp: form handling, friendly errors, progress and result actions.
import { normalizeUserInput } from '../engine/candidates.js';
import { createFetchClient } from '../engine/fetchClient.js';
import { createAnalyzer } from '../analysis/analyzer.js';
import { createWorkerFactory } from './trusted-worker.js';
import { renderReport, renderProgress, reportToSummaryText, exportReportJson } from './render.js';

const FRIENDLY = {
  empty_input: 'Enter a web address to scan.',
  unsupported_scheme: 'Only http and https addresses can be scanned.',
};
const BUTTON = 'rounded border border-slate-700 bg-white px-3 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-800';

/**
 * @param {Document} doc
 * @param {{scan: typeof import('../engine/scan.js').scan, client?: object, analyzer?: object}} deps
 */
export function startApp(doc, deps) {
  const form = doc.getElementById('scan-form');
  const input = doc.getElementById('url-input');
  const button = doc.getElementById('scan-button');
  const errorEl = doc.getElementById('error');
  const progressEl = doc.getElementById('progress');
  const actionsEl = doc.getElementById('actions');
  const resultsEl = doc.getElementById('results');
  if (!form || !input || !button || !errorEl || !progressEl || !actionsEl || !resultsEl) return;
  const win = doc.defaultView;

  const showError = (message) => { errorEl.textContent = message; };
  const setBusy = (busy) => {
    button.disabled = busy;
    if (busy) button.setAttribute('aria-busy', 'true'); else button.removeAttribute('aria-busy');
  };

  function showActions(report) {
    actionsEl.replaceChildren();
    const mk = (label, onClick) => {
      const b = doc.createElement('button');
      b.type = 'button';
      b.className = BUTTON;
      b.textContent = label;
      b.addEventListener('click', onClick);
      actionsEl.append(b);
    };
    mk('Copy summary', () => { win.navigator?.clipboard?.writeText(reportToSummaryText(report)).catch(() => {}); });
    mk('Download JSON', () => {
      if (!win.URL?.createObjectURL) return;
      const blob = new win.Blob([exportReportJson(report)], { type: 'application/json' });
      const href = win.URL.createObjectURL(blob);
      const a = doc.createElement('a');
      a.href = href;
      a.download = 'vectr-website-sn-report.json';
      doc.body.append(a);
      a.click();
      a.remove();
      win.URL.revokeObjectURL(href);
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    let url;
    try {
      url = normalizeUserInput(input.value);
    } catch (err) {
      showError(FRIENDLY[err?.message] ?? 'That does not look like a web address.');
      input.focus();
      return;
    }

    setBusy(true);
    actionsEl.replaceChildren();
    resultsEl.replaceChildren();
    const client = deps.client ?? createFetchClient();
    const analyzer = deps.analyzer ?? createAnalyzer({ workerFactory: createWorkerFactory(win) });
    try {
      const report = await deps.scan(url, { client, analyzer, onProgress: (s) => renderProgress(s, progressEl) });
      renderReport(report, resultsEl);
      showActions(report);
      resultsEl.focus();
    } catch {
      showError('The scan could not be completed. Please try again.');
    } finally {
      if (!deps.analyzer) analyzer.dispose();
      setBusy(false);
    }
  });
}
