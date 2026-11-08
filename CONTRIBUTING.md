# Contributing

1. Use Node.js 22 or newer.
2. `npm install`, then `npm test`, `npm run lint` and `npm run build` must all pass.
3. Write the failing test first, then the code. Every detector rule needs a
   recall fixture and, if it can misfire, a regression fixture.
4. Never use `DOMParser`, `innerHTML`, `outerHTML`, `insertAdjacentHTML` or
   `document.write` in `src/` (lint enforces this). Target-controlled text is
   rendered with `textContent` and `createElement` only.
5. Never execute, `eval` or load anything from a scanned site.
6. Claims in docs must match what tests demonstrate. Do not write that the tool
   prevents all SSRF, detects all malicious downloads, or proves a site safe.

Security issues: see `SECURITY.md`.
