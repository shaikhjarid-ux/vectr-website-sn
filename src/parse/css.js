// Extract url() and @import references from CSS text. Comments are stripped first.

const REF = /@import\s*(?:"([^"]*)"|'([^']*)')|url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']*))\s*\)/gi;

/** @param {string} css @returns {string[]} */
export function extractCssUrls(css) {
  const clean = String(css).replace(/\/\*[\s\S]*?(?:\*\/|$)/g, '');
  const out = [];
  for (const m of clean.matchAll(REF)) {
    const v = (m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5] ?? '').trim();
    if (v) out.push(v);
  }
  return out;
}
