// Response metadata encoding and the security headers set on every /api/* response.
// Static `_headers` rules only apply to asset responses, so the Worker sets its own.

/** @returns {Record<string, string>} */
export function securityHeaders() {
  return {
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    'cross-origin-resource-policy': 'same-origin',
    'cache-control': 'no-store',
  };
}

/**
 * base64url(JSON) so arbitrary header values survive the HTTP header channel.
 * @param {object} meta
 * @returns {string}
 */
export function encodeMeta(meta) {
  const bytes = new TextEncoder().encode(JSON.stringify(meta));
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @param {string} value
 * @returns {any}
 */
export function decodeMeta(value) {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}
