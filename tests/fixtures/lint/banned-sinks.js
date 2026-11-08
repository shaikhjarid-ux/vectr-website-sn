// Fixture: every line below must be rejected by the src/** lint rules.
// This file is excluded from `npm run lint` and linted explicitly by tests/repo.test.js.
export function bad(el, html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  el.innerHTML = html;
  const out = el.outerHTML;
  el.insertAdjacentHTML('beforeend', html);
  document.write(html);
  return [doc, out];
}
