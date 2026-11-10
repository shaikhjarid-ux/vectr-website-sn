import { describe, it, expect } from 'vitest';
import { redirects } from '../../src/detectors/redirects.js';
import { analyzeScript } from '../../src/analysis/fold.js';
import { makeCtx } from '../helpers/ctx.js';

const script = (src, extra = {}) => ({ ...analyzeScript(src), source: 'inline', ...extra });
const run = (html, opts) => redirects.run(makeCtx(html, opts));
const hop = (url, status = 302) => ({ url, status });

describe('redirects', () => {
  it('has id and version', () => {
    expect(redirects.id).toBe('redirects');
    expect(typeof redirects.version).toBe('string');
  });

  it('meta refresh gives a low auto-triggered finding and a priority-1 candidate', () => {
    const out = run('<meta http-equiv="refresh" content="0;url=https://dl.example.net/f">');
    expect(out.findings).toEqual([expect.objectContaining({ detector: 'redirects', ruleId: 'redirect.meta-refresh', category: 'redirect', proposedSeverity: 'low', autoTriggered: true, target: 'https://dl.example.net/f' })]);
    expect(out.findings[0].evidence).toMatchObject({ location: { type: 'html_attribute', tag: 'meta', attribute: 'content' }, normalizedValue: 'https://dl.example.net/f' });
    expect(out.followCandidates).toEqual([expect.objectContaining({ url: 'https://dl.example.net/f', reason: 'meta-refresh', priority: 1, depth: 1 })]);
  });

  it('script navigation is auto-triggered only at top level', () => {
    const top = run('', { scripts: [script("window.location = 'https://y.com/a'")] });
    expect(top.findings[0]).toMatchObject({ ruleId: 'redirect.script-navigation', proposedSeverity: 'low', autoTriggered: true, target: 'https://y.com/a' });
    expect(top.followCandidates).toEqual([expect.objectContaining({ url: 'https://y.com/a', reason: 'script-navigation', priority: 1 })]);
    const inFn = run('', { scripts: [script("function go(){ window.open('https://y.com/b'); }")] });
    expect(inFn.findings[0]).toMatchObject({ ruleId: 'redirect.script-navigation', autoTriggered: false });
    expect(inFn.findings[0].evidence.location.type).toBe('script_range');
  });

  it('resolves relative script navigation values and skips non-http schemes', () => {
    const out = run('', { scripts: [script("location = '/next'; location.assign('javascript:void(0)');")] });
    expect(out.findings.map((f) => f.target)).toEqual(['https://x.com/next']);
  });

  it('a null-valued navigation adds unsupported_runtime_behavior coverage and no finding', () => {
    const out = run('', { scripts: [script('location = foo + "/a";')] });
    expect(out.findings).toEqual([]);
    expect(out.coverage).toEqual([{ check: 'redirects', page: 'https://x.com/page/', state: 'unknown', reason: 'unsupported_runtime_behavior' }]);
  });

  it('a chain across four registrable domains is medium', () => {
    const chain = [hop('https://a.com/'), hop('https://b.net/'), hop('https://c.org/'), { url: 'https://d.io/', status: 200 }];
    const out = run('', { chain, finalUrl: 'https://d.io/' });
    const f = out.findings.find((x) => x.ruleId === 'redirect.chain-cross-domain');
    expect(f).toMatchObject({ proposedSeverity: 'medium', category: 'redirect' });
    expect(f.evidence.snippet).toContain('a.com');
    expect(f.evidence.snippet).toContain('d.io');
  });

  it('a single crossing is low and three distinct domains are medium', () => {
    const one = run('', { chain: [hop('https://a.com/'), { url: 'https://b.net/', status: 200 }], finalUrl: 'https://b.net/' });
    expect(one.findings.find((x) => x.ruleId === 'redirect.chain-cross-domain').proposedSeverity).toBe('low');
    const three = run('', { chain: [hop('https://a.com/'), hop('https://b.net/'), { url: 'https://c.org/', status: 200 }], finalUrl: 'https://c.org/' });
    expect(three.findings.find((x) => x.ruleId === 'redirect.chain-cross-domain').proposedSeverity).toBe('medium');
  });

  it('www to apex produces nothing; a different subdomain is info', () => {
    const www = run('', { chain: [hop('https://www.x.com/'), { url: 'https://x.com/', status: 200 }], finalUrl: 'https://x.com/' });
    expect(www.findings).toEqual([]);
    const sub = run('', { chain: [hop('https://x.com/'), { url: 'https://app.x.com/', status: 200 }], finalUrl: 'https://app.x.com/' });
    expect(sub.findings.map((f) => f.ruleId)).toEqual(['redirect.final-host-differs']);
    expect(sub.findings[0].proposedSeverity).toBe('info');
  });

  it('treats private-suffix tenants as different domains', () => {
    const out = run('', { chain: [hop('https://evil.github.io/'), { url: 'https://good.github.io/', status: 200 }], finalUrl: 'https://good.github.io/' });
    expect(out.findings.some((f) => f.ruleId === 'redirect.chain-cross-domain')).toBe(true);
  });

  it('a single-entry chain yields nothing', () => {
    expect(run('<p>x</p>').findings).toEqual([]);
  });
});
