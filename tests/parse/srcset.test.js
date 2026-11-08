import { describe, it, expect } from 'vitest';
import { parseSrcset } from '../../src/parse/srcset.js';

describe('parseSrcset', () => {
  it('keeps commas inside URLs', () => {
    expect(parseSrcset('a.jpg 1x, data:image/png;base64,AAA,BBB 2x')).toEqual(['a.jpg', 'data:image/png;base64,AAA,BBB']);
  });
  it('handles widths, no descriptors and trailing commas', () => {
    expect(parseSrcset('a.jpg 100w, b.jpg 200w')).toEqual(['a.jpg', 'b.jpg']);
    expect(parseSrcset('a.jpg, b.jpg')).toEqual(['a.jpg', 'b.jpg']);
    expect(parseSrcset('  a.jpg,,  b.jpg  ')).toEqual(['a.jpg', 'b.jpg']);
  });
  it('returns [] for empty input', () => {
    expect(parseSrcset('')).toEqual([]);
    expect(parseSrcset('  , ')).toEqual([]);
  });
});
