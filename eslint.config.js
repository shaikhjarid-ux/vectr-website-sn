import js from '@eslint/js';
import globals from 'globals';

// The HTML-parsing and HTML-injection sinks below are banned in src/ so that
// target-controlled strings can only reach the DOM through textContent and
// createElement. Parsing of target HTML goes through parse5 only.
const BANNED_SINKS = {
  'no-restricted-globals': [
    'error',
    { name: 'DOMParser', message: 'Parse target HTML with parse5 only.' },
  ],
  'no-restricted-properties': [
    'error',
    { property: 'innerHTML', message: 'Use textContent and createElement.' },
    { property: 'outerHTML', message: 'Use textContent and createElement.' },
    { property: 'insertAdjacentHTML', message: 'Use textContent and createElement.' },
    { object: 'document', property: 'write', message: 'document.write is banned.' },
  ],
};

export default [
  // The lint fixture is linted explicitly by tests/repo.test.js, not by `npm run lint`.
  { ignores: ['dist/**', 'node_modules/**', '.superpowers/**', '.wrangler/**', 'tests/fixtures/lint/**', 'playwright-report/**', 'test-results/**'] },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node, ...globals.serviceworker },
    },
  },
  {
    files: ['src/**/*.js', 'tests/fixtures/lint/**/*.js'],
    rules: BANNED_SINKS,
  },
];
