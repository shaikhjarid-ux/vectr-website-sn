// srcset parsing following the HTML spec: a candidate URL ends at whitespace, so commas inside a URL are kept.

const isWs = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f';

/** @param {string} value @returns {string[]} */
export function parseSrcset(value) {
  const s = String(value);
  const out = [];
  let pos = 0;
  while (pos < s.length) {
    while (pos < s.length && (isWs(s[pos]) || s[pos] === ',')) pos++;
    if (pos >= s.length) break;
    const start = pos;
    while (pos < s.length && !isWs(s[pos])) pos++;
    let url = s.slice(start, pos);
    if (url.endsWith(',')) {
      url = url.replace(/,+$/, '');
    } else {
      let depth = 0;
      while (pos < s.length) {
        const c = s[pos];
        if (c === '(') depth++;
        else if (c === ')') depth = Math.max(0, depth - 1);
        else if (c === ',' && depth === 0) { pos++; break; }
        pos++;
      }
    }
    if (url) out.push(url);
  }
  return out;
}
