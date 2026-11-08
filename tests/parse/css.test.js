import { describe, it, expect } from 'vitest';
import { extractCssUrls } from '../../src/parse/css.js';

describe('extractCssUrls', () => {
  it('finds @import and url() references, ignoring comments', () => {
    expect(extractCssUrls('@import url("a.css"); .x{background:url( \'b.png\' )} /* url(c.png) */')).toEqual(['a.css', 'b.png']);
  });
  it('handles unquoted urls, string @import and several per rule', () => {
    expect(extractCssUrls('@import "x.css"; a{background:url(i.png),url(j.png)}')).toEqual(['x.css', 'i.png', 'j.png']);
  });
  it('handles an unterminated comment', () => {
    expect(extractCssUrls('a{background:url(a.png)} /* url(b.png)')).toEqual(['a.png']);
  });
  it('skips empty urls', () => {
    expect(extractCssUrls('a{background:url()}')).toEqual([]);
  });
});
