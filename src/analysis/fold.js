// Static JavaScript analysis: Acorn parses the source (it is never executed,
// eval'd or loaded) and a bounded constant folder evaluates only
// literal-derived values: string literals, `+`, template literals, single-
// assignment const/var strings in the file, `.join` on literal arrays, and
// atob / unescape / decodeURIComponent / String.fromCharCode on literals.
// Everything else is unknown.
import { parse } from 'acorn';
import { PAYLOAD_EXTENSIONS } from '../parse/url.js';

export const DEFAULT_SCRIPT_LIMITS = Object.freeze({
  maxSourceBytes: 262144,
  maxPasses: 3,
  maxOutputBytes: 524288,
  maxSteps: 10000,
  maxDepth: 50,
});

/**
 * @typedef {typeof DEFAULT_SCRIPT_LIMITS} ScriptLimits
 * @typedef {{kind: 'location' | 'open' | 'write' | 'anchor-download', value: string | null, topLevel: boolean, start: number, end: number}} Navigation
 * @typedef {{value: string, via: string[], start: number, end: number}} FoldedUrl
 * @typedef {{status: 'ok' | 'partial' | 'unknown', reason?: string, navigations: Navigation[], urls: FoldedUrl[]}} ScriptAnalysis
 */

const UNKNOWN = Symbol('unknown');
const U = Object.freeze({ v: UNKNOWN, layers: 0, via: Object.freeze([]) });
// Backstops for the whole script (each root also has its own maxSteps budget).
const MAX_ROOTS = 20000;
const MAX_TOTAL_STEPS = 2000000;
const WINDOWS = new Set(['window', 'self', 'top', 'parent', 'globalThis', 'frames']);
const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

class LimitError extends Error {
  constructor(kind) { super(kind); this.kind = kind; }
}

const known = (v, layers = 0, via = []) => ({ v, layers, via });

function parseSource(source) {
  const base = { ecmaVersion: 'latest', allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true };
  try { return parse(source, { ...base, sourceType: 'script' }); } catch { /* try module syntax */ }
  try { return parse(source, { ...base, sourceType: 'module' }); } catch { return null; }
}

function* children(node) {
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end') continue;
    const v = node[key];
    if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string') yield c; }
    else if (v && typeof v.type === 'string') yield v;
  }
}

function patternNames(p, out = []) {
  if (!p) return out;
  switch (p.type) {
    case 'Identifier': out.push(p.name); break;
    case 'ObjectPattern': for (const prop of p.properties) patternNames(prop.value ?? prop.argument, out); break;
    case 'ArrayPattern': for (const e of p.elements) patternNames(e, out); break;
    case 'AssignmentPattern': patternNames(p.left, out); break;
    case 'RestElement': patternNames(p.argument, out); break;
    default: break;
  }
  return out;
}

/** Names declared exactly once, never reassigned, with an initializer: the only identifiers the folder resolves. */
function findConstants(ast) {
  const decl = new Map(), assign = new Map(), init = new Map();
  const inc = (m, n) => m.set(n, (m.get(n) ?? 0) + 1);
  const stack = [ast];
  while (stack.length) {
    const n = stack.pop();
    switch (n.type) {
      case 'VariableDeclarator':
        for (const name of patternNames(n.id)) inc(decl, name);
        if (n.id.type === 'Identifier' && n.init) init.set(n.id.name, n.init);
        break;
      case 'FunctionDeclaration': case 'FunctionExpression': case 'ArrowFunctionExpression':
        if (n.id) inc(decl, n.id.name);
        for (const p of n.params) for (const name of patternNames(p)) inc(decl, name);
        break;
      case 'ClassDeclaration': case 'ClassExpression': if (n.id) inc(decl, n.id.name); break;
      case 'CatchClause': for (const name of patternNames(n.param)) inc(decl, name); break;
      case 'ImportSpecifier': case 'ImportDefaultSpecifier': case 'ImportNamespaceSpecifier': inc(decl, n.local.name); break;
      case 'AssignmentExpression': for (const name of patternNames(n.left)) inc(assign, name); break;
      case 'UpdateExpression': if (n.argument.type === 'Identifier') inc(assign, n.argument.name); break;
      case 'ForInStatement': case 'ForOfStatement': if (n.left.type !== 'VariableDeclaration') for (const name of patternNames(n.left)) inc(assign, name); break;
      default: break;
    }
    for (const c of children(n)) stack.push(c);
  }
  const consts = new Map();
  for (const [name, node] of init) if (decl.get(name) === 1 && !assign.has(name)) consts.set(name, node);
  return consts;
}

const propName = (m) => (!m.computed && m.property.type === 'Identifier' ? m.property.name : m.computed && m.property.type === 'Literal' && typeof m.property.value === 'string' ? m.property.value : null);

/** Name of a global function reference: `atob`, `window.atob`, `String.fromCharCode`. */
function calleeName(callee) {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression') {
    const p = propName(callee);
    if (p && callee.object.type === 'Identifier') {
      if (WINDOWS.has(callee.object.name)) return p;
      if (callee.object.name === 'String') return `String.${p}`;
    }
  }
  return null;
}

const DECODERS = new Set(['atob', 'unescape', 'decodeURIComponent', 'decodeURI', 'String.fromCharCode', 'String.fromCodePoint']);
const isJoinCall = (n) => n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && propName(n.callee) === 'join';
const isFoldCall = (n) => n.type === 'CallExpression' && (DECODERS.has(calleeName(n.callee) ?? '') || isJoinCall(n));
const isFoldRootType = (n) => (n.type === 'BinaryExpression' && n.operator === '+') || n.type === 'TemplateLiteral' || isFoldCall(n);

function mergeVia(...lists) {
  const out = [];
  for (const l of lists) for (const x of l) if (!out.includes(x)) out.push(x);
  return out;
}

function makeFolder(consts, L) {
  const st = { steps: 0, memo: new Map(), resolving: new Set() };

  const checkOut = (s) => { if (s.length > L.maxOutputBytes) throw new LimitError('output'); return s; };
  const layer = (r, name) => {
    const layers = r.layers + 1;
    if (layers > L.maxPasses) throw new LimitError('passes');
    return { layers, via: mergeVia(r.via, [name]) };
  };

  function ev(node, depth) {
    if (++st.steps > L.maxSteps) throw new LimitError('steps');
    if (depth > L.maxDepth) throw new LimitError('depth');
    switch (node.type) {
      case 'Literal':
        if (typeof node.value === 'string') return known(checkOut(node.value));
        if (typeof node.value === 'number') return known(node.value);
        return U;
      case 'TemplateLiteral': {
        let out = '', layers = 0, via = ['template'];
        for (let i = 0; i < node.quasis.length; i++) {
          out += node.quasis[i].value.cooked ?? '';
          if (i < node.expressions.length) {
            const r = ev(node.expressions[i], depth + 1);
            if (typeof r.v !== 'string' && typeof r.v !== 'number') return U;
            out += String(r.v);
            layers = Math.max(layers, r.layers);
            via = mergeVia(via, r.via);
          }
        }
        return known(checkOut(out), layers, via);
      }
      case 'Identifier': {
        const init = consts.get(node.name);
        if (!init) return U;
        if (st.memo.has(node.name)) return st.memo.get(node.name);
        if (st.resolving.has(node.name)) return U;
        st.resolving.add(node.name);
        try {
          const r = ev(init, depth + 1);
          const res = r.v === UNKNOWN ? U : known(r.v, r.layers, mergeVia(r.via, ['const']));
          st.memo.set(node.name, res);
          return res;
        } finally { st.resolving.delete(node.name); }
      }
      case 'BinaryExpression': {
        if (node.operator !== '+') return U;
        const operands = [];
        let cur = node;
        while (cur.type === 'BinaryExpression' && cur.operator === '+') { operands.push(cur.right); cur = cur.left; }
        operands.push(cur);
        operands.reverse();
        let acc = null, layers = 0, via = ['concat'];
        for (const op of operands) {
          const r = ev(op, depth + 1);
          if (r.v === UNKNOWN || Array.isArray(r.v)) return U;
          layers = Math.max(layers, r.layers);
          via = mergeVia(via, r.via);
          if (acc === null) acc = r.v;
          else if (typeof acc === 'number' && typeof r.v === 'number') acc += r.v;
          else acc = checkOut(String(acc) + String(r.v));
        }
        return known(acc, layers, via);
      }
      case 'ArrayExpression': {
        const items = [];
        let layers = 0, via = [];
        for (const e of node.elements) {
          if (!e || e.type === 'SpreadElement') return U;
          const r = ev(e, depth + 1);
          if (r.v === UNKNOWN) return U;
          items.push(r.v);
          layers = Math.max(layers, r.layers);
          via = mergeVia(via, r.via);
        }
        return known(items, layers, via);
      }
      case 'CallExpression': return call(node, depth);
      default: return U;
    }
  }

  function call(node, depth) {
    if (isJoinCall(node)) {
      const arr = ev(node.callee.object, depth + 1);
      if (!Array.isArray(arr.v) || arr.v.some((x) => typeof x !== 'string' && typeof x !== 'number')) return U;
      let sep = ',', layers = arr.layers, via = mergeVia(arr.via, ['join']);
      if (node.arguments.length > 0) {
        const s = ev(node.arguments[0], depth + 1);
        if (typeof s.v !== 'string') return U;
        sep = s.v; layers = Math.max(layers, s.layers); via = mergeVia(via, s.via);
      }
      return known(checkOut(arr.v.join(sep)), layers, via);
    }
    const name = calleeName(node.callee);
    if (!name || !DECODERS.has(name)) return U;
    const args = [];
    let layers = 0, via = [];
    for (const a of node.arguments) {
      if (a.type === 'SpreadElement') return U;
      const r = ev(a, depth + 1);
      if (r.v === UNKNOWN) return U;
      args.push(r.v);
      layers = Math.max(layers, r.layers);
      via = mergeVia(via, r.via);
    }
    const meta = layer({ layers, via }, name);
    let out;
    try {
      if (name === 'String.fromCharCode' || name === 'String.fromCodePoint') {
        if (args.some((x) => typeof x !== 'number')) return U;
        out = name === 'String.fromCharCode' ? String.fromCharCode(...args) : String.fromCodePoint(...args);
      } else {
        if (typeof args[0] !== 'string') return U;
        if (name === 'atob') out = atob(args[0]);
        else if (name === 'unescape') out = globalThis.unescape(args[0]);
        else if (name === 'decodeURIComponent') out = decodeURIComponent(args[0]);
        else out = decodeURI(args[0]);
      }
    } catch (err) {
      if (err instanceof LimitError) throw err;
      return U;
    }
    return known(checkOut(out), meta.layers, meta.via);
  }

  return {
    /** Fold one expression with a fresh step budget; limit errors propagate. */
    fold(node) { st.steps = 0; return ev(node, 0); },
    stepsUsed: () => st.steps,
  };
}

const isLocationExpr = (n) => (n.type === 'Identifier' && n.name === 'location')
  || (n.type === 'MemberExpression' && propName(n) === 'location' && n.object.type === 'Identifier' && (WINDOWS.has(n.object.name) || n.object.name === 'document'));
const isLocationTarget = (n) => isLocationExpr(n) || (n.type === 'MemberExpression' && propName(n) === 'href' && isLocationExpr(n.object));
const isDocument = (n) => (n.type === 'Identifier' && n.name === 'document')
  || (n.type === 'MemberExpression' && propName(n) === 'document' && n.object.type === 'Identifier' && WINDOWS.has(n.object.name));
const isCreateAnchor = (n) => n && n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && propName(n.callee) === 'createElement'
  && isDocument(n.callee.object) && n.arguments[0]?.type === 'Literal' && String(n.arguments[0].value).toLowerCase() === 'a';

/** True when `node` is an operand of a foldable `parent`, so the parent (not the operand) is the maximal fold root. */
function foldedInto(parent, node) {
  if ((parent.type === 'BinaryExpression' && parent.operator === '+') || parent.type === 'TemplateLiteral') return true;
  return isFoldCall(parent) && (parent.arguments.includes(node) || parent.callee.object === node);
}

function looksUrlish(v) {
  if (v.includes('://') || v.startsWith('//')) return true;
  const m = /\.([a-z0-9]{1,8})(?:[?#]\S*)?$/i.exec(v.slice(-300));
  return Boolean(m) && PAYLOAD_EXTENSIONS.has(m[1].toLowerCase());
}

/**
 * @param {string} source
 * @param {Partial<ScriptLimits>} [opts]
 * @returns {ScriptAnalysis}
 */
export function analyzeScript(source, opts = {}) {
  const L = { ...DEFAULT_SCRIPT_LIMITS, ...opts };
  const empty = (status, reason) => ({ status, reason, navigations: [], urls: [] });
  const text = typeof source === 'string' ? source : '';
  if (text.length > L.maxSourceBytes || new TextEncoder().encode(text).length > L.maxSourceBytes) {
    return empty('unknown', 'script_parse_limit_reached');
  }
  const ast = parseSource(text);
  if (!ast) return empty('unknown', 'script_parse_failed');

  const folder = makeFolder(findConstants(ast), L);
  /** @type {Navigation[]} */
  const navigations = [];
  /** @type {FoldedUrl[]} */
  const urls = [];
  const seenUrls = new Set();
  const rootCache = new Map();
  let limitHit = false;
  let unresolved = false;
  let roots = 0;
  let totalSteps = 0;

  function foldNode(node) {
    if (rootCache.has(node)) return rootCache.get(node);
    let r = U;
    if (++roots > MAX_ROOTS || totalSteps > MAX_TOTAL_STEPS) limitHit = true;
    else {
      try { r = folder.fold(node); } catch (err) {
        if (err instanceof LimitError) limitHit = true; else throw err;
      }
      totalSteps += folder.stepsUsed();
    }
    rootCache.set(node, r);
    return r;
  }

  const valueOf = (node) => {
    const r = foldNode(node);
    return typeof r.v === 'string' ? r.v : typeof r.v === 'number' ? String(r.v) : null;
  };

  const anchors = new Set();
  const anchorHref = new Map(); // name -> {node, valueNode, topLevel}
  const anchorDownload = new Set();

  const addNav = (kind, node, value, topLevel, markUnresolved) => {
    navigations.push({ kind, value, topLevel, start: node.start, end: node.end });
    if (value === null && markUnresolved) unresolved = true;
  };

  const stack = [{ node: ast, fnDepth: 0, parent: null }];
  while (stack.length) {
    const { node, fnDepth, parent } = stack.pop();
    const topLevel = fnDepth === 0;

    if (isFoldRootType(node) && !(parent && foldedInto(parent, node))) {
      const r = foldNode(node);
      if (typeof r.v === 'string' && r.via.length > 0 && looksUrlish(r.v)) {
        const key = `${node.start}:${node.end}:${r.v}`;
        if (!seenUrls.has(key)) {
          seenUrls.add(key);
          urls.push({ value: r.v.slice(0, 4096), via: [...r.via], start: node.start, end: node.end });
        }
      }
    }

    if (node.type === 'AssignmentExpression') {
      if (node.operator === '=' && isLocationTarget(node.left)) addNav('location', node, valueOf(node.right), topLevel, true);
      else if (isLocationTarget(node.left)) addNav('location', node, null, topLevel, true);
      else if (node.left.type === 'MemberExpression' && node.left.object.type === 'Identifier' && anchors.has(node.left.object.name)) {
        const p = propName(node.left);
        if (p === 'href') anchorHref.set(node.left.object.name, { node, valueNode: node.right, topLevel });
        else if (p === 'download') anchorDownload.add(node.left.object.name);
      } else if (node.left.type === 'Identifier' && isCreateAnchor(node.right)) anchors.add(node.left.name);
    } else if (node.type === 'VariableDeclarator') {
      if (node.id.type === 'Identifier' && isCreateAnchor(node.init)) anchors.add(node.id.name);
    } else if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const p = propName(node.callee);
      const obj = node.callee.object;
      const arg0 = node.arguments[0];
      if ((p === 'assign' || p === 'replace') && isLocationExpr(obj) && arg0) addNav('location', node, valueOf(arg0), topLevel, true);
      else if (p === 'open' && obj.type === 'Identifier' && WINDOWS.has(obj.name) && arg0) addNav('open', node, valueOf(arg0), topLevel, true);
      else if ((p === 'write' || p === 'writeln') && isDocument(obj) && arg0) addNav('write', node, valueOf(arg0), topLevel, false);
      else if (p === 'setAttribute' && obj.type === 'Identifier' && anchors.has(obj.name) && arg0?.type === 'Literal') {
        const attr = String(arg0.value).toLowerCase();
        if (attr === 'href' && node.arguments[1]) anchorHref.set(obj.name, { node, valueNode: node.arguments[1], topLevel });
        else if (attr === 'download') anchorDownload.add(obj.name);
      }
    } else if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'open' && node.arguments[0]) {
      addNav('open', node, valueOf(node.arguments[0]), topLevel, true);
    }

    const nextDepth = FUNCTION_TYPES.has(node.type) ? fnDepth + 1 : fnDepth;
    const kids = [...children(node)];
    for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i], fnDepth: nextDepth, parent: node });
  }

  for (const name of anchorDownload) {
    const h = anchorHref.get(name);
    if (h) addNav('anchor-download', h.node, valueOf(h.valueNode), h.topLevel, true);
  }
  navigations.sort((a, b) => a.start - b.start);

  if (limitHit) return { status: 'partial', reason: 'script_parse_limit_reached', navigations, urls };
  if (unresolved) return { status: 'partial', reason: 'unsupported_runtime_behavior', navigations, urls };
  return { status: 'ok', navigations, urls };
}
