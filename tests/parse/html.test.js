import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { parseHtml, effectiveBase, extractUrlRefs, textContentOf, snippetAround } from '../../src/parse/html.js';

const refs = (html, base = 'https://x.com/p/') => extractUrlRefs(parseHtml(html), effectiveBase(parseHtml(html), base));
const rawOf = (list) => list.map((r) => r.raw);

describe('base handling', () => {
  it('uses the first <base href> and keeps raw as written', () => {
    const html = '<base href="/d/"><base href="/ignored/"><a href="f.exe">dl</a>';
    const tree = parseHtml(html);
    expect(effectiveBase(tree, 'https://x.com/p/q')).toBe('https://x.com/d/');
    const [ref] = extractUrlRefs(tree, effectiveBase(tree, 'https://x.com/p/q'));
    expect(ref).toMatchObject({ raw: 'f.exe', resolved: 'https://x.com/d/f.exe', tag: 'a', attribute: 'href', source: 'attribute', text: 'dl' });
  });
  it('falls back to the final URL without or with an invalid base', () => {
    expect(effectiveBase(parseHtml('<p>x</p>'), 'https://x.com/a')).toBe('https://x.com/a');
    expect(effectiveBase(parseHtml('<base href="http://">'), 'https://x.com/a')).toBe('https://x.com/a');
  });
});

describe('extractUrlRefs', () => {
  it('never treats event handlers as refs', () => {
    expect(rawOf(refs('<img src=x onerror=alert(1)>'))).toEqual(['x']);
  });
  it('uses data-* attributes only when they look like URLs', () => {
    expect(refs('<div data-id="123"></div>')).toEqual([]);
    expect(rawOf(refs('<div data-url="https://x.com/a.exe"></div>'))).toEqual(['https://x.com/a.exe']);
  });
  it('covers the element and attribute list from the spec', () => {
    const html = `
      <a href="a1.exe"></a><area href="a2.exe"><link href="a3.css" rel="stylesheet">
      <iframe src="a4.html"></iframe><embed src="a5.swf"><object data="a6.bin"></object>
      <video poster="a7.png" src="a8.mp4"><source src="a9.mp4" srcset="b1.png 1x, b2.png 2x"></video>
      <form action="b3.php"></form><button formaction="b4.php"></button><script src="b5.js"></script>
      <svg><a xlink:href="b6.exe"><use href="b7.svg"/></a></svg>`;
    const got = new Set(rawOf(refs(html)));
    for (const x of ['a1.exe', 'a2.exe', 'a3.css', 'a4.html', 'a5.swf', 'a6.bin', 'a7.png', 'a8.mp4', 'a9.mp4', 'b1.png', 'b2.png', 'b3.php', 'b4.php', 'b5.js', 'b6.exe', 'b7.svg']) expect(got.has(x), x).toBe(true);
    const svgRef = refs(html).find((r) => r.raw === 'b6.exe');
    expect(svgRef.attribute).toBe('xlink:href');
    expect(refs(html).find((r) => r.raw === 'b2.png').source).toBe('srcset');
  });
  it('extracts url() from style attributes and <style> blocks', () => {
    const html = '<div style="background:url(a.png)"></div><style>@import "b.css"; p{background:url(c.png)}</style>';
    const list = refs(html);
    expect(rawOf(list)).toEqual(['a.png', 'b.css', 'c.png']);
    expect(list.every((r) => r.source === 'style')).toBe(true);
    expect(list[0]).toMatchObject({ tag: 'div', attribute: 'style' });
    expect(list[1].tag).toBe('style');
  });
  it('parses iframe srcdoc one level deep only', () => {
    const inner = '<a href="in.exe">x</a><iframe srcdoc="<a href=deep.exe>y</a>"></iframe>';
    const html = `<iframe srcdoc="${inner.replace(/"/g, '&quot;')}"></iframe>`;
    const list = refs(html);
    expect(rawOf(list)).toContain('in.exe');
    expect(rawOf(list)).not.toContain('deep.exe');
    expect(list.find((r) => r.raw === 'in.exe').source).toBe('srcdoc');
  });
  it('turns meta refresh into a meta-refresh ref', () => {
    const list = refs('<meta http-equiv="refresh" content="0;url=https://d.net/f">');
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ raw: 'https://d.net/f', resolved: 'https://d.net/f', tag: 'meta', attribute: 'content', source: 'meta-refresh' });
    expect(rawOf(refs('<meta http-equiv="Refresh" content="5; URL=\'next.html\'">'))).toEqual(['next.html']);
    expect(refs('<meta http-equiv="refresh" content="5">')).toEqual([]);
  });
  it('reports line and column from source locations', () => {
    const [r] = refs('<p>one</p>\n<a\n  href="x.zip">t</a>');
    expect(r.line).toBe(3);
    expect(r.column).toBe(3);
  });
  it('collapses and truncates anchor text to 100 characters', () => {
    const [r] = refs(`<a href="x.zip">  hello \n   world ${'z'.repeat(200)}</a>`);
    expect(r.text.startsWith('hello world zzz')).toBe(true);
    expect(r.text.length).toBe(100);
  });
  it('resolved is null for unparsable URLs', () => {
    expect(refs('<a href="http://">x</a>')[0]).toMatchObject({ raw: 'http://', resolved: null });
  });
  it('ignores empty values', () => {
    expect(refs('<a href=""></a><img src="  ">')).toEqual([]);
  });
});

describe('textContentOf', () => {
  it('returns collapsed visible text without scripts and styles', () => {
    expect(textContentOf(parseHtml('<p>Hello   <b>there</b></p><script>var x=1</script><style>p{}</style>'))).toBe('Hello there');
  });
});

describe('snippetAround', () => {
  it('is never longer than 200 characters', () => {
    const html = 'a'.repeat(5000);
    for (const [off, max] of [[0, 50], [2500, 200], [4999, 1000], [10, undefined]]) expect(snippetAround(html, off, max).length).toBeLessThanOrEqual(200);
    expect(snippetAround('<a href=x>', 3)).toBe('<a href=x>');
  });
});

describe('robustness', () => {
  it('parses a 1 MiB single-line document in under 2 seconds', () => {
    const html = '<a href="/f/1.exe">link</a>'.repeat(Math.ceil(1048576 / 27)).slice(0, 1048576);
    const t = Date.now();
    const tree = parseHtml(html);
    const list = extractUrlRefs(tree, 'https://x.com/');
    expect(Date.now() - t).toBeLessThan(2000);
    expect(list.length).toBeGreaterThan(1000);
    expect(snippetAround(html, 500000).length).toBeLessThanOrEqual(200);
  });
  it('survives deep nesting', () => {
    const html = '<div>'.repeat(20000);
    expect(() => extractUrlRefs(parseHtml(html), 'https://x.com/')).not.toThrow();
  });
  it('never throws on random input (property)', () => {
    fc.assert(fc.property(fc.oneof(fc.string({ maxLength: 400 }), fc.uint8Array({ maxLength: 400 }).map((b) => String.fromCharCode(...b))), (s) => {
      const tree = parseHtml(s);
      effectiveBase(tree, 'https://x.com/');
      extractUrlRefs(tree, 'https://x.com/');
      textContentOf(tree);
    }), { numRuns: 500, seed: 20261108 });
  });
});
