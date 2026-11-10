import { describe, it, expect } from 'vitest';
import { normalizeUserInput, rankCandidates } from '../../src/engine/candidates.js';
import { parseHtml, extractUrlRefs } from '../../src/parse/html.js';

const PAGE = 'https://x.com/page/';
const refsOf = (html) => extractUrlRefs(parseHtml(html), PAGE);
const rank = (html, det = []) => rankCandidates(refsOf(html), det, PAGE);
const ev = { snippet: 's', sourceUrl: PAGE, location: { type: 'html_attribute' }, matchedValue: 'm', normalizedValue: 'n', context: '' };

describe('normalizeUserInput', () => {
  it('trims and prepends https:// when there is no scheme', () => {
    expect(normalizeUserInput(' example.com/a ')).toBe('https://example.com/a');
    expect(normalizeUserInput('example.com')).toBe('https://example.com');
  });
  it('treats host:port/path as a host, not a scheme', () => {
    expect(normalizeUserInput('example.com:443/path')).toBe('https://example.com:443/path');
    expect(normalizeUserInput('example.com:8080/path')).toBe('https://example.com:8080/path');
    expect(normalizeUserInput('localhost:3000')).toBe('https://localhost:3000');
  });
  it('keeps http and https URLs as typed', () => {
    expect(normalizeUserInput('http://example.com/a?b=1')).toBe('http://example.com/a?b=1');
    expect(normalizeUserInput('HTTPS://Example.com/')).toBe('HTTPS://Example.com/');
  });
  it('throws unsupported_scheme for other schemes', () => {
    for (const bad of ['view-source:https://x.com', 'javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,hi', 'ftp://x.com/a', 'mailto:a@b.c', 'about:blank', 'blob:https://x.com/1', 'gopher://x.com/', 'FTP://X.COM', 'JavaScript:alert(1)']) {
      expect(() => normalizeUserInput(bad), bad).toThrow('unsupported_scheme');
    }
  });
  it('throws empty_input for blank input', () => {
    expect(() => normalizeUserInput('   ')).toThrow('empty_input');
  });
});

describe('rankCandidates', () => {
  it('puts explicit payload links, meta refresh and detector candidates at priority 1', () => {
    const det = [{ url: 'https://dl.example.net/f', reason: 'meta-refresh', priority: 1, sourceEvidence: ev, depth: 1 }];
    const out = rank('<a href="/files/setup.exe">get</a><form action="/download/start"></form>', det);
    expect(out.filter((c) => c.priority === 1).map((c) => c.url).sort()).toEqual(['https://dl.example.net/f', 'https://x.com/download/start', 'https://x.com/files/setup.exe']);
    expect(out.every((c) => c.depth === 1)).toBe(true);
  });
  it('gives same-origin keyword paths and keyword anchor text priority 2, off-origin keyword links priority 3', () => {
    const out = rank('<a href="/download/page">x</a><a href="/about">Download now</a><a href="/privacy">Privacy</a><a href="https://other.net/get">Get it</a><a href="https://other.net/home">Home</a>');
    const byUrl = Object.fromEntries(out.map((c) => [c.url, c.priority]));
    expect(byUrl['https://x.com/download/page']).toBe(2);
    expect(byUrl['https://x.com/about']).toBe(2);
    expect(byUrl['https://other.net/get']).toBe(3);
    expect('https://x.com/privacy' in byUrl).toBe(false);
    expect('https://other.net/home' in byUrl).toBe(false);
  });
  it('orders by priority then document order and dedupes by normalized URL keeping the best priority', () => {
    const out = rank('<a href="/download/b">b</a><a href="/f/a.exe">a</a><a href="/download/b#x">dup</a><a href="/f/a.exe?x=1">other</a>');
    expect(out.map((c) => c.url)).toEqual(['https://x.com/f/a.exe', 'https://x.com/f/a.exe?x=1', 'https://x.com/download/b']);
  });
  it('drops fragments-only, self, non-http, asset and over-long URLs', () => {
    const long = `/download/${'a'.repeat(4100)}`;
    const out = rank(`<a href="#top">Download</a><a href="${PAGE}">Download</a><a href="javascript:go()">Download</a><a href="mailto:a@b.c">Download</a><a href="/download/logo.png">Download</a><link rel="stylesheet" href="/download.css"><a href="${long}">Download</a>`);
    expect(out).toEqual([]);
  });
  it('caps at 100 candidates', () => {
    const html = Array.from({ length: 300 }, (_, i) => `<a href="/download/${i}">d</a>`).join('');
    expect(rank(html)).toHaveLength(100);
  });
  it('builds evidence from the reference', () => {
    const [c] = rank('<a href="/f/a.exe">get</a>');
    expect(c).toMatchObject({ reason: 'download-link', sourceEvidence: { sourceUrl: PAGE, matchedValue: '/f/a.exe', normalizedValue: 'https://x.com/f/a.exe', location: { type: 'html_attribute', tag: 'a', attribute: 'href' } } });
  });
});
