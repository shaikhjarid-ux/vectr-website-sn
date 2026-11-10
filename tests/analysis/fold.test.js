import { describe, it, expect } from 'vitest';
import { analyzeScript, DEFAULT_SCRIPT_LIMITS } from '../../src/analysis/fold.js';

const nav = (src, opts) => analyzeScript(src, opts).navigations;
const URL_EXE = 'https://x.com/a.exe';

describe('limits', () => {
  it('match the spec', () => {
    expect(DEFAULT_SCRIPT_LIMITS).toEqual({ maxSourceBytes: 262144, maxPasses: 3, maxOutputBytes: 524288, maxSteps: 10000, maxDepth: 50 });
  });
});

describe('navigation detection and folding', () => {
  it('folds split-string concatenation into a top-level location navigation', () => {
    const r = analyzeScript("window.location = 'ht'+'tps://x.com/a.exe';");
    expect(r.status).toBe('ok');
    expect(r.navigations).toEqual([expect.objectContaining({ kind: 'location', value: URL_EXE, topLevel: true })]);
    expect(r.navigations[0].end).toBeGreaterThan(r.navigations[0].start);
  });
  it('folds atob and records the via chain on the folded url', () => {
    const r = analyzeScript("location.href = atob('aHR0cHM6Ly94LmNvbS9hLmV4ZQ==');");
    expect(r.navigations[0]).toMatchObject({ kind: 'location', value: URL_EXE });
    expect(r.urls.find((u) => u.value === URL_EXE).via).toContain('atob');
  });
  it('folds String.fromCharCode', () => {
    const codes = [...URL_EXE].map((c) => c.charCodeAt(0)).join(',');
    expect(nav(`location = String.fromCharCode(${codes});`)[0].value).toBe(URL_EXE);
  });
  it('folds unescape and decodeURIComponent', () => {
    const esc = [...URL_EXE].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
    expect(nav(`location = unescape('${esc}');`)[0].value).toBe(URL_EXE);
    expect(nav(`location = decodeURIComponent('${esc}');`)[0].value).toBe(URL_EXE);
  });
  it('folds a template literal over a const', () => {
    expect(nav('const h = "x.com"; location = `https://${h}/a.exe`;')[0].value).toBe(URL_EXE);
  });
  it('folds .join on literal arrays', () => {
    expect(nav("location = ['ht','tp://x.com/a.exe'].join('');")[0].value).toBe('http://x.com/a.exe');
  });
  it('resolves single-assignment consts and var strings', () => {
    expect(nav("const base='https://x.com'; window.open(base + '/a.exe');")[0]).toMatchObject({ kind: 'open', value: URL_EXE, topLevel: true });
    expect(nav("var b='https://x.com'; self.location.href = b + '/a.exe';")[0].value).toBe(URL_EXE);
  });
  it('does not resolve a reassigned or redeclared name', () => {
    const r = analyzeScript("var u='https://a.com/'; u='https://b.com/'; location = u + 'x.exe';");
    expect(r.navigations[0].value).toBeNull();
    expect(r.status).toBe('partial');
    const r2 = analyzeScript("var u='https://a.com/'; function f(u){ location = u; }");
    expect(r2.navigations[0].value).toBeNull();
  });
  it('marks navigations inside functions as not top level', () => {
    const n = nav("function go(){ window.open('https://x.com/a.exe'); } const f = () => { location = 'https://x.com/b.exe'; };");
    expect(n).toHaveLength(2);
    expect(n.every((x) => x.topLevel === false)).toBe(true);
  });
  it('detects assign, replace, document.write and bare open', () => {
    const n = nav("location.assign('https://x.com/1'); top.location.replace('https://x.com/2'); document.write('<a href=https://x.com/3>'); open('https://x.com/4');");
    expect(n.map((x) => x.kind)).toEqual(['location', 'location', 'write', 'open']);
    expect(n[2].value).toBe('<a href=https://x.com/3>');
  });
  it('detects an anchor download', () => {
    const n = nav("const a = document.createElement('a'); a.href = 'ht'+'tps://x.com/a.exe'; a.download = 'a.exe'; a.click();");
    expect(n).toEqual([expect.objectContaining({ kind: 'anchor-download', value: URL_EXE, topLevel: true })]);
    expect(nav("const a = document.createElement('a'); a.setAttribute('href','https://x.com/a.exe'); a.setAttribute('download','');")[0].kind).toBe('anchor-download');
    expect(nav("const a = document.createElement('a'); a.href = 'https://x.com/a.html';")).toEqual([]);
  });
  it('ignores document.open and unrelated assignments', () => {
    expect(nav("document.open(); const location2 = 'x'; foo.location = 'y'; var obj = {href: 'z'};")).toEqual([]);
  });
  it('folds long concatenation chains without hitting the depth limit', () => {
    const src = `location = ${Array.from({ length: 200 }, (_, i) => `'${i % 10}'`).join(' + ')};`;
    const r = analyzeScript(src);
    expect(r.navigations[0].value).toHaveLength(200);
    expect(r.status).toBe('ok');
  });
});

describe('status and limits', () => {
  it('an unresolvable variable gives value null and partial', () => {
    const r = analyzeScript("location = foo + '/a.exe';");
    expect(r.status).toBe('partial');
    expect(r.reason).toBe('unsupported_runtime_behavior');
    expect(r.navigations[0]).toMatchObject({ kind: 'location', value: null });
  });
  it('a syntax error gives unknown / script_parse_failed', () => {
    expect(analyzeScript('var = ;;; {')).toMatchObject({ status: 'unknown', reason: 'script_parse_failed', navigations: [], urls: [] });
  });
  it('source over 256 KiB gives unknown / script_parse_limit_reached', () => {
    const r = analyzeScript(`var x = "${'a'.repeat(262145)}";`);
    expect(r).toMatchObject({ status: 'unknown', reason: 'script_parse_limit_reached' });
  });
  it('three nested atob layers fold; four stop at 3 passes as partial', () => {
    let s = URL_EXE;
    const layers = [];
    for (let i = 0; i < 4; i++) { s = btoa(s); layers.push(s); }
    const three = `location = atob(atob(atob('${layers[2]}')));`;
    expect(nav(three)[0].value).toBe(URL_EXE);
    const four = analyzeScript(`location = atob(atob(atob(atob('${layers[3]}'))));`);
    expect(four.status).toBe('partial');
    expect(four.reason).toBe('script_parse_limit_reached');
    expect(four.navigations[0].value).toBeNull();
  });
  it('honours the output limit and the step limit', () => {
    const big = analyzeScript("var a='" + 'x'.repeat(300) + "'; location = a + a + a;", { maxOutputBytes: 500 });
    expect(big.status).toBe('partial');
    expect(big.reason).toBe('script_parse_limit_reached');
    const many = analyzeScript(`location = ${Array.from({ length: 50 }, () => "'a'").join('+')};`, { maxSteps: 10 });
    expect(many.status).toBe('partial');
    expect(many.reason).toBe('script_parse_limit_reached');
  });
  it('honours the depth limit on deep nesting', () => {
    const deep = `location = ${'['.repeat(60)}'a'${']'.repeat(60)}.join('');`;
    const r = analyzeScript(deep, { maxDepth: 10 });
    expect(r.navigations[0].value).toBeNull();
    expect(r.reason).toBe('script_parse_limit_reached');
  });
  it('never throws on pathological input', () => {
    expect(() => analyzeScript('('.repeat(200000))).not.toThrow();
    expect(() => analyzeScript('\u0000\u0001garbage')).not.toThrow();
    expect(analyzeScript('').status).toBe('ok');
    expect(analyzeScript('#!/usr/bin/env node\nlocation = "https://x.com/a.exe"').navigations).toHaveLength(1);
  });
  it('parses module syntax', () => {
    expect(nav("import x from './y.js'; location = 'https://x.com/a.exe';")).toHaveLength(1);
  });
});

describe('FoldedUrl records', () => {
  it('reports non-trivial folded url-like strings with offsets', () => {
    const src = "var u = 'ht' + 'tps://x.com/a.exe';";
    const r = analyzeScript(src);
    expect(r.urls).toHaveLength(1);
    const u = r.urls[0];
    expect(u.value).toBe(URL_EXE);
    expect(src.slice(u.start, u.end)).toBe("'ht' + 'tps://x.com/a.exe'");
    expect(u.via).toContain('concat');
  });
  it('does not report folded strings that are not url-like', () => {
    expect(analyzeScript("var s = 'hello' + ' ' + 'world';").urls).toEqual([]);
  });
});

describe('safety', () => {
  it('never executes target code (eval and Function stubbed to throw)', () => {
    const origEval = globalThis.eval;
    const origFn = globalThis.Function;
    const boom = function boom() { throw new Error('executed target code'); };
    globalThis.eval = boom;
    globalThis.Function = boom;
    try {
      const r = analyzeScript("eval('alert(1)'); new Function('return 1')(); location = ('ht'+'tps://x.com/a.exe');");
      expect(r.navigations[0].value).toBe(URL_EXE);
    } finally {
      globalThis.eval = origEval;
      globalThis.Function = origFn;
    }
  });
});
