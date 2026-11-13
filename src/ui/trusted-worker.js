// Trusted Types support for creating the analysis Web Worker.
//
// The page's CSP includes `require-trusted-types-for 'script'` (report-only), so
// `new Worker(string)` is a Trusted Types sink. The policy below can mint a
// TrustedScriptURL for exactly one URL: the same-origin analysis Worker script,
// with no query string or fragment. Any other input throws, so the policy never
// widens what the page can load.

export const WORKER_PATH = '/js-worker.js';
export const WORKER_POLICY_NAME = 'vectr-worker-url';

const policies = new WeakMap();

/**
 * Validate that `input` is exactly the approved Worker URL for this page's origin.
 * @param {string} input
 * @param {{origin: string, href: string}} location
 * @returns {string} the normalized absolute URL
 */
export function approveWorkerUrl(input, location) {
  let url;
  try {
    url = new URL(String(input), location.href);
  } catch {
    throw new TypeError('Worker URL is not valid');
  }
  if (url.origin !== location.origin || url.pathname !== WORKER_PATH || url.search !== '' || url.hash !== '') {
    throw new TypeError('Worker URL is not the approved same-origin analysis script');
  }
  return url.href;
}

/**
 * The page's Trusted Types policy for the analysis Worker, or null when the
 * browser does not support Trusted Types. Created once per window.
 * @param {Window} win
 */
export function getWorkerUrlPolicy(win) {
  const tt = win.trustedTypes;
  if (!tt || typeof tt.createPolicy !== 'function') return null;
  if (policies.has(win)) return policies.get(win);
  const policy = tt.createPolicy(WORKER_POLICY_NAME, {
    createScriptURL: (input) => approveWorkerUrl(input, win.location),
  });
  policies.set(win, policy);
  return policy;
}

/**
 * A factory for the analysis Worker that passes a TrustedScriptURL where the
 * browser supports Trusted Types and the plain approved URL where it does not.
 * @param {Window} win
 * @returns {() => Worker}
 */
export function createWorkerFactory(win) {
  return () => {
    const policy = getWorkerUrlPolicy(win);
    const source = policy ? policy.createScriptURL(WORKER_PATH) : approveWorkerUrl(WORKER_PATH, win.location);
    return new win.Worker(source);
  };
}
