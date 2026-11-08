import { describe, it, expect } from 'vitest';
import { decodeBody } from '../../src/engine/decode.js';

const enc = (s) => new TextEncoder().encode(s);

describe('decodeBody', () => {
  it('decodes windows-1252 via header charset', () => {
    const bytes = Uint8Array.from([0x63, 0x61, 0x66, 0xe9]); // "café"
    expect(decodeBody(bytes, 'text/html; charset=windows-1252')).toEqual({ text: 'café', charset: 'windows-1252', fellBack: false });
  });
  it('decodes Shift-JIS Japanese text', () => {
    const bytes = Uint8Array.from([0x82, 0xb1, 0x82, 0xf1, 0x82, 0xc9, 0x82, 0xbf, 0x82, 0xcd]); // こんにちは
    const r = decodeBody(bytes, 'text/html; charset=Shift_JIS');
    expect(r.text).toBe('こんにちは');
    expect(r.fellBack).toBe(false);
  });
  it('honours a UTF-8 BOM over a conflicting header and strips it', () => {
    const bytes = Uint8Array.from([0xef, 0xbb, 0xbf, ...enc('héllo')]);
    expect(decodeBody(bytes, 'text/html; charset=windows-1252')).toEqual({ text: 'héllo', charset: 'utf-8', fellBack: false });
  });
  it('sniffs <meta charset> in the first 1024 bytes', () => {
    const head = Uint8Array.from([...enc('<html><head><meta charset="windows-1252"></head><body>caf'), 0xe9]);
    expect(decodeBody(head, 'text/html')).toMatchObject({ text: expect.stringContaining('café'), charset: 'windows-1252', fellBack: false });
  });
  it('sniffs http-equiv content-type meta too', () => {
    const b = enc('<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">');
    expect(decodeBody(b, 'text/html').charset).toBe('windows-1252');
  });
  it('ignores a meta charset beyond the first 1024 bytes', () => {
    const b = enc(`${' '.repeat(1100)}<meta charset="windows-1252">`);
    expect(decodeBody(b, 'text/html')).toMatchObject({ charset: 'utf-8', fellBack: true });
  });
  it('falls back to UTF-8 for an unknown charset and says so', () => {
    expect(decodeBody(enc('plain'), 'text/html; charset=x-no-such-charset')).toEqual({ text: 'plain', charset: 'utf-8', fellBack: true });
  });
  it('falls back to UTF-8 when nothing declares a charset', () => {
    expect(decodeBody(enc('plain'), '')).toEqual({ text: 'plain', charset: 'utf-8', fellBack: true });
  });
  it('never throws on invalid bytes', () => {
    expect(() => decodeBody(Uint8Array.from([0xff, 0xfe, 0xfd, 0x80]), 'text/html; charset=utf-8')).not.toThrow();
  });
});
