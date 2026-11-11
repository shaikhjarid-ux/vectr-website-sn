import { describe, it, expect } from 'vitest';
import fixtures, { ROUTES } from '../scripts/staging/fixtures-worker.js';
import { renderStagingReport, CHECKS } from '../scripts/staging/report.mjs';

const get = (path) => fixtures.fetch(new Request(`https://fixtures.example.net${path}`));

describe('staging fixtures worker', () => {
  it('redirects to private and metadata addresses over https (so the IP guard, not the downgrade rule, must block them)', async () => {
    expect((await get('/redirect-private')).headers.get('location')).toBe('https://10.0.0.1/');
    expect((await get('/redirect-metadata')).headers.get('location')).toBe('https://169.254.169.254/latest/meta-data/');
  });
  it('loops between two paths', async () => {
    expect((await get('/loop-a')).headers.get('location')).toBe('https://fixtures.example.net/loop-b');
    expect((await get('/loop-b')).headers.get('location')).toBe('https://fixtures.example.net/loop-a');
  });
  it('chains N redirects then answers', async () => {
    let path = '/chain/6';
    let hops = 0;
    for (;;) {
      const r = await get(path);
      if (r.status !== 302) break;
      hops++;
      path = new URL(r.headers.get('location')).pathname;
    }
    expect(hops).toBe(6);
  });
  it('sets a cookie on /set-cookie and a lying Content-Length on /big-lying', async () => {
    expect((await get('/set-cookie')).headers.get('set-cookie')).toContain('sid=');
    const big = await get('/big-lying');
    expect(big.headers.get('content-length')).toBe('10');
    const reader = big.body.getReader();
    const { value } = await reader.read();
    expect(value.length).toBeGreaterThan(10);
    await reader.cancel();
  });
  it('slow-drip starts streaming and can be cancelled', async () => {
    const r = await get('/slow-drip');
    const reader = r.body.getReader();
    const { value } = await reader.read();
    expect(value.length).toBe(1);
    await reader.cancel();
  });
  it('every advertised route answers and unknown paths 404', async () => {
    for (const p of ROUTES) expect((await get(p)).status, p).not.toBe(404);
    expect((await get('/nope')).status).toBe(404);
  });
});

describe('renderStagingReport', () => {
  it('marks every unrun check as not verified and never as pass', () => {
    const md = renderStagingReport([], { date: '2026-11-10' });
    for (const c of CHECKS) expect(md).toContain(c.title);
    expect(md.match(/\| not verified \|/g)).toHaveLength(CHECKS.length);
    expect(md).not.toMatch(/\| pass \|/);
    expect(md).toContain('DNS rebinding');
    expect(md).toContain('Staging URL: not set');
  });
  it('shows observed results and escapes table separators', () => {
    const md = renderStagingReport([{ id: 'loop', status: 'pass', observed: 'HTTP 502 a|b' }], { date: '2026-11-10', stagingUrl: 'https://s.example' });
    expect(md).toContain('| pass | HTTP 502 a/b |');
    expect(md).toContain('Staging URL: https://s.example');
  });
});
