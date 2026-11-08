import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { ESLint } from 'eslint';

const FILES = [
  'package.json', 'wrangler.jsonc', 'vitest.config.js', 'eslint.config.js',
  'scripts/build.mjs', '.github/dependabot.yml', 'README.md', 'LICENSE',
  'SECURITY.md', 'CONTRIBUTING.md', 'docs/threat-model.md',
  'src/ui/index.html', 'src/ui/app.js', 'src/ui/styles.css',
  'src/analysis/js-worker.js', 'tests/repo.test.js',
  'tests/fixtures/lint/banned-sinks.js',
];

function stripJsonc(text) {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') out += text[++i];
      else if (c === '"') inStr = false;
    } else if (c === '"') { inStr = true; out += c; }
    else if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; }
    else if (c === '/' && text[i + 1] === '*') { i += 2; while (!(text[i] === '*' && text[i + 1] === '/')) i++; i++; }
    else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

describe('scaffold', () => {
  it.each(FILES)('has %s', (f) => {
    expect(existsSync(f), `${f} should exist`).toBe(true);
  });

  it('threat model has the required headings', () => {
    const md = readFileSync('docs/threat-model.md', 'utf8');
    for (const h of ['Assets', 'Attacker-controlled inputs', 'Trust boundaries', 'Threats considered', 'Out of scope', 'Residual risks']) {
      expect(md, h).toMatch(new RegExp(`^#{1,3} ${h}\\s*$`, 'm'));
    }
  });

  it('wrangler.jsonc runs the Worker first only for /api/*', () => {
    const cfg = JSON.parse(stripJsonc(readFileSync('wrangler.jsonc', 'utf8')));
    expect(cfg.assets.run_worker_first).toEqual(['/api/*']);
    expect(cfg.main).toBe('src/worker/index.js');
    expect(cfg.assets.directory).toBe('dist');
  });

  it('ESLint rejects the banned sinks under the src/** rules', async () => {
    const eslint = new ESLint({ ignore: false });
    const [result] = await eslint.lintFiles(['tests/fixtures/lint/banned-sinks.js']);
    expect(result.errorCount).toBeGreaterThanOrEqual(5);
  });
});
