// Generates src/worker/ranges.js and src/worker/special-domains.js from the
// IANA CSV tables in data/. Run: node scripts/gen-ranges.mjs
//
// Non-global ranges = every entry whose "Globally Reachable" value is not
// True, minus the more specific entries that ARE True (for example 192.0.0.9
// inside 192.0.0.0/24). IPv6 additionally treats everything outside 2000::/3
// as non-global at lookup time (see src/worker/ip.js).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else inQ = false; } else cell += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some((x) => x !== '')) rows.push(row);
      row = [];
    } else cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

/** Ranges that are not global but are not rows of the IANA special-purpose registries. */
export const SUPPLEMENTARY_NON_GLOBAL_V4 = ['224.0.0.0/4']; // multicast (IANA IPv4 address space registry)

const canon = (h) => String(h).toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Parse registry CSV text into objects keyed by the canonical column names in `required`.
 * Fails with a clear message when the text is not a CSV with those columns (for example an HTML error page).
 * @param {string} text
 * @param {string} name used in error messages
 * @param {string[]} required column names, matched ignoring case, spaces and punctuation
 */
export function parseTable(text, name, required) {
  const body = text.replace(/^\uFEFF/, '');
  if (/^\s*</.test(body)) {
    throw new Error(`${name} looks like HTML, not CSV (a wrong or moved download URL). First line: ${JSON.stringify(body.trim().split('\n')[0].slice(0, 80))}. Download it again from the URL in data/README.md.`);
  }
  const [header, ...rows] = parseCsv(body);
  const found = (header ?? []).map(canon);
  const index = {};
  for (const col of required) {
    index[col] = found.indexOf(canon(col));
    if (index[col] < 0) throw new Error(`${name}: expected a column named "${col}" but the columns are: ${JSON.stringify(header ?? [])}`);
  }
  return rows.map((r) => Object.fromEntries(required.map((col) => [col, (r[index[col]] ?? '').trim()])));
}

const table = (file, required) => parseTable(readFileSync(join(root, 'data', file), 'utf8'), file, required);

/** Domain names from the special-use registry: lowercase, any "(DEPRECATED)"-style suffix removed, no trailing dot. */
export function cleanDomains(rows) {
  const out = rows
    .map((r) => r.Name.toLowerCase().replace(/\s.*$/, '').replace(/\.$/, ''))
    .filter((n) => /^[a-z0-9_.-]+$/.test(n) && n !== '');
  return [...new Set(out)].sort();
}

function v4Range(cidr) {
  const [addr, len] = cidr.split('/');
  const n = addr.split('.').reduce((a, o) => a * 256 + Number(o), 0);
  const size = 2 ** (32 - Number(len));
  const start = Math.floor(n / size) * size;
  return [start, start + size - 1];
}

function v6ToBigInt(addr) {
  let [head, tail] = addr.split('::');
  const parse = (s) => (s ? s.split(':') : []);
  let h = parse(head), t = tail === undefined ? [] : parse(tail);
  const expandV4 = (arr) => arr.flatMap((g) => (g.includes('.') ? g.split('.').reduce((a, o) => a * 256 + Number(o), 0).toString(16).padStart(8, '0').match(/.{4}/g) : [g]));
  h = expandV4(h); t = expandV4(t);
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  if (groups.length !== 8) throw new Error(`bad IPv6 ${addr}`);
  return groups.reduce((a, g) => (a << 16n) + BigInt(parseInt(g, 16)), 0n);
}

function v6Range(cidr) {
  const [addr, len] = cidr.split('/');
  const size = 1n << (128n - BigInt(len));
  const start = (v6ToBigInt(addr) / size) * size;
  return [start, start + size - 1n];
}

function merge(ranges) {
  const s = [...ranges].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out = [];
  for (const r of s) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + (typeof r[0] === 'bigint' ? 1n : 1)) { if (r[1] > last[1]) last[1] = r[1]; } else out.push([...r]);
  }
  return out;
}

function subtract(ranges, holes) {
  const one = typeof ranges[0]?.[0] === 'bigint' ? 1n : 1;
  let out = merge(ranges);
  for (const [hs, he] of merge(holes)) {
    const next = [];
    for (const [s, e] of out) {
      if (he < s || hs > e) { next.push([s, e]); continue; }
      if (hs > s) next.push([s, hs - one]);
      if (he < e) next.push([he + one, e]);
    }
    out = next;
  }
  return out;
}

export function build(rows, toRange, extra = []) {
  // A cell may hold footnote markers ("[2]") or several comma-separated blocks.
  const blocks = (r) => (r['Address Block'].match(/[0-9a-f:.]+\/\d+/gi) ?? []).map(toRange);
  const isTrue = (r) => /^true/i.test(r['Globally Reachable']);
  const bad = rows.filter((r) => !isTrue(r)).flatMap(blocks);
  const good = rows.filter(isTrue).flatMap(blocks);
  return subtract([...bad, ...extra.map(toRange)], good);
}

export { v4Range, v6Range };

function main() {
  const cols = ['Address Block', 'Globally Reachable'];
  const v4 = build(table('iana-ipv4-special.csv', cols), v4Range, SUPPLEMENTARY_NON_GLOBAL_V4);
  const v6 = build(table('iana-ipv6-special.csv', cols), v6Range);
  const domains = cleanDomains(table('iana-special-use-domains.csv', ['Name']));
  if (v4.length === 0 || v6.length === 0 || domains.length === 0) throw new Error('A registry produced no entries; refusing to write empty tables.');

  const banner = '// GENERATED by scripts/gen-ranges.mjs from data/*.csv. Do not edit by hand.\n';
  writeFileSync(
    join(root, 'src/worker/ranges.js'),
    `${banner}export const RANGES = {\n  v4: ${JSON.stringify(v4)},\n  v6: [${v6.map(([s, e]) => `[0x${s.toString(16)}n, 0x${e.toString(16)}n]`).join(', ')}],\n};\n`,
  );
  writeFileSync(join(root, 'src/worker/special-domains.js'), `${banner}export const SPECIAL_DOMAINS = ${JSON.stringify(domains, null, 2)};\n`);
  console.log(`ranges: ${v4.length} IPv4, ${v6.length} IPv6; special-use domains: ${domains.length}`);
}

// Run only when executed directly (the tests import the functions above).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (err) { console.error(`gen-ranges: ${err.message}`); process.exit(1); }
}
