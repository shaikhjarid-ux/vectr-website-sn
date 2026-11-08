// Builds dist/: bundles the UI and the analysis Web Worker, compiles Tailwind
// from src/ui/styles.css, and copies index.html and the static headers file.
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');
const p = (...parts) => join(root, ...parts);

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: { app: p('src/ui/app.js'), 'js-worker': p('src/analysis/js-worker.js') },
  outdir: dist,
  bundle: true,
  format: 'esm',
  target: 'es2022',
  minify: true,
  sourcemap: false,
  logLevel: 'warning',
});

execFileSync(
  process.execPath,
  [p('node_modules/@tailwindcss/cli/dist/index.mjs'), '-i', p('src/ui/styles.css'), '-o', join(dist, 'styles.css'), '--minify'],
  { stdio: 'inherit', cwd: root },
);

copyFileSync(p('src/ui/index.html'), join(dist, 'index.html'));
if (!existsSync(p('public/_headers'))) throw new Error('public/_headers is missing');
copyFileSync(p('public/_headers'), join(dist, '_headers'));

console.log('build ok -> dist/');
