import { describe, it, expect } from 'vitest';
import { hiddenOverlays } from '../../src/detectors/hidden-overlays.js';
import { makeCtx } from '../helpers/ctx.js';

const run = (html) => hiddenOverlays.run(makeCtx(html)).findings;
const rules = (html) => run(html).map((f) => f.ruleId);

describe('hiddenOverlays', () => {
  it('has id and version', () => {
    expect(hiddenOverlays.id).toBe('hidden-overlays');
    expect(typeof hiddenOverlays.version).toBe('string');
  });

  describe('overlay.hidden-iframe', () => {
    it('flags an off-origin iframe with zero width or display:none', () => {
      for (const html of [
        '<iframe src="https://evil.com/x" width="0" height="0"></iframe>',
        '<iframe src="https://evil.com/x" style="display:none"></iframe>',
        '<iframe src="https://evil.com/x" style="visibility: hidden"></iframe>',
        '<iframe src="https://evil.com/x" style="opacity:0"></iframe>',
        '<iframe src="https://evil.com/x" style="width:1px;height:1px"></iframe>',
        '<iframe src="https://evil.com/x" hidden></iframe>',
        '<div style="display:none"><iframe src="https://evil.com/x"></iframe></div>',
      ]) expect(rules(html), html).toEqual(['overlay.hidden-iframe']);
    });
    it('reports tag, attribute, target and confidence', () => {
      const [f] = run('<iframe src="https://evil.com/x" style="display:none"></iframe>');
      expect(f).toMatchObject({ detector: 'hidden-overlays', category: 'interface', proposedSeverity: 'medium', confidence: 'medium', target: 'https://evil.com/x' });
      expect(f.evidence).toMatchObject({ location: { type: 'html_attribute', tag: 'iframe', line: 1 }, normalizedValue: 'https://evil.com/x' });
    });
    it('uses simple .class and #id rules from <style> blocks', () => {
      expect(rules('<style>.hide{display:none} #px{width:0;height:0}</style><iframe class="a hide" src="https://evil.com/1"></iframe><iframe id="px" src="https://evil.com/2"></iframe>')).toEqual(['overlay.hidden-iframe', 'overlay.hidden-iframe']);
    });
    it('ignores rules inside @media blocks and comments', () => {
      expect(rules('<style>@media (max-width:600px){.hide{display:none}} /* .hide{display:none} */</style><iframe class="hide" src="https://evil.com/1"></iframe>')).toEqual([]);
    });
    it('ignores a visible off-origin iframe and a hidden same-origin or same-site one', () => {
      expect(rules('<iframe src="https://evil.com/x" width="600" height="400"></iframe>')).toEqual([]);
      expect(rules('<iframe src="/local" width="0" height="0"></iframe>')).toEqual([]);
      expect(rules('<iframe src="https://sub.x.com/p" style="display:none"></iframe>')).toEqual([]);
      expect(rules('<iframe srcdoc="<p>hi</p>" style="display:none"></iframe>')).toEqual([]);
    });
  });

  describe('overlay.fullscreen-capture', () => {
    it('flags a transparent full-viewport fixed layer containing an anchor', () => {
      const [f] = run('<div style="position:fixed;top:0;left:0;width:100%;height:100%;opacity:0"><a href="https://evil.com/go">x</a></div>');
      expect(f).toMatchObject({ ruleId: 'overlay.fullscreen-capture', proposedSeverity: 'medium', category: 'interface', target: 'https://evil.com/go' });
      expect(f.confidence).not.toBe('high');
    });
    it('flags inset:0 / 100vw 100vh variants and a transparent anchor layer', () => {
      expect(rules('<a href="https://evil.com/g" style="position:absolute;width:100vw;height:100vh;opacity:0">x</a>')).toEqual(['overlay.fullscreen-capture']);
      expect(rules('<div style="position:fixed;top:0;right:0;bottom:0;left:0;opacity:0" onclick="go()">x</div>')).toEqual(['overlay.fullscreen-capture']);
    });
    it('ignores a normal fixed header, a visible modal backdrop and a hidden layer without links', () => {
      expect(rules('<header style="position:fixed;top:0;width:100%;height:60px"><a href="/home">h</a></header>')).toEqual([]);
      expect(rules('<div style="position:fixed;width:100%;height:100%;background:#000"><a href="/x">x</a></div>')).toEqual([]);
      expect(rules('<div style="position:fixed;width:100%;height:100%;opacity:0"></div>')).toEqual([]);
    });
  });

  describe('overlay.offscreen-link', () => {
    it('flags anchors positioned far off-screen', () => {
      const [f] = run('<a href="https://evil.com/off" style="position:absolute;left:-9999px">x</a>');
      expect(f).toMatchObject({ ruleId: 'overlay.offscreen-link', proposedSeverity: 'low', target: 'https://evil.com/off' });
      expect(rules('<div style="position:absolute;top:-5000px"><a href="/a">x</a></div>')).toEqual(['overlay.offscreen-link']);
    });
    it('ignores in-page skip links and on-screen anchors', () => {
      expect(rules('<a href="#main" style="position:absolute;left:-9999px">skip</a>')).toEqual([]);
      expect(rules('<a href="/a" style="position:absolute;left:10px">x</a>')).toEqual([]);
    });
  });

  it('never reports confidence high', () => {
    const html = '<iframe src="https://evil.com/x" width="0"></iframe><div style="position:fixed;width:100%;height:100%;opacity:0"><a href="/g">x</a></div><a href="/o" style="position:absolute;left:-9999px">o</a>';
    const all = run(html);
    expect(all.length).toBeGreaterThanOrEqual(3);
    expect(all.every((f) => f.confidence !== 'high')).toBe(true);
  });
});
