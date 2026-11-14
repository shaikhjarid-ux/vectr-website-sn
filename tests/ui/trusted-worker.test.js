// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest';
import { approveWorkerUrl, getWorkerUrlPolicy, createWorkerFactory, WORKER_POLICY_NAME } from '../../src/ui/trusted-worker.js';

const LOC = { origin: 'https://vectr.example', href: 'https://vectr.example/some/page?x=1' };

/** A fake window with a Trusted Types implementation that records policies and wraps values. */
function fakeWindow({ trustedTypes = true } = {}) {
  const created = [];
  const win = {
    location: LOC,
    Worker: vi.fn(function Worker(source) { this.source = source; }),
  };
  if (trustedTypes) {
    win.trustedTypes = {
      createPolicy: vi.fn((name, rules) => {
        created.push(name);
        return { createScriptURL: (input) => ({ __trusted: true, value: rules.createScriptURL(input) }) };
      }),
    };
  }
  return { win, created };
}

describe('approveWorkerUrl', () => {
  it('accepts exactly the same-origin worker script', () => {
    expect(approveWorkerUrl('/js-worker.js', LOC)).toBe('https://vectr.example/js-worker.js');
    expect(approveWorkerUrl('https://vectr.example/js-worker.js', LOC)).toBe('https://vectr.example/js-worker.js');
  });
  it.each([
    'https://evil.example/js-worker.js',
    '//evil.example/js-worker.js',
    '/js-worker.js?x=1',
    '/js-worker.js#frag',
    '/other.js',
    '/js-worker.js/../app.js',
    '/js-worker.jsx',
    '/static/js-worker.js',
    'blob:https://vectr.example/1234',
    'data:text/javascript,alert(1)',
    'javascript:alert(1)',
    '',
  ])('rejects %j', (input) => {
    expect(() => approveWorkerUrl(input, LOC)).toThrow(TypeError);
  });
});

describe('getWorkerUrlPolicy', () => {
  it('creates one named policy per window that mints only the approved URL', () => {
    const { win, created } = fakeWindow();
    const policy = getWorkerUrlPolicy(win);
    expect(getWorkerUrlPolicy(win)).toBe(policy);
    expect(created).toEqual([WORKER_POLICY_NAME]);
    expect(policy.createScriptURL('/js-worker.js').value).toBe('https://vectr.example/js-worker.js');
    expect(() => policy.createScriptURL('https://evil.example/x.js')).toThrow(TypeError);
    expect(() => policy.createScriptURL('/js-worker.js?cache=1')).toThrow(TypeError);
  });
  it('returns null where Trusted Types is not supported', () => {
    expect(getWorkerUrlPolicy(fakeWindow({ trustedTypes: false }).win)).toBeNull();
  });
});

describe('createWorkerFactory', () => {
  it('passes a TrustedScriptURL to the Worker constructor when supported', () => {
    const { win } = fakeWindow();
    const worker = createWorkerFactory(win)();
    expect(win.Worker).toHaveBeenCalledTimes(1);
    expect(worker.source).toEqual({ __trusted: true, value: 'https://vectr.example/js-worker.js' });
  });
  it('reuses the policy across workers', () => {
    const { win, created } = fakeWindow();
    const make = createWorkerFactory(win);
    make(); make();
    expect(created).toHaveLength(1);
  });
  it('falls back to the plain approved URL without Trusted Types', () => {
    const { win } = fakeWindow({ trustedTypes: false });
    expect(createWorkerFactory(win)().source).toBe('https://vectr.example/js-worker.js');
  });
});
