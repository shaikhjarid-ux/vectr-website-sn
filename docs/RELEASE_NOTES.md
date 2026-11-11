# Release notes: Vectr Website SN Core 0.1.0

Core is a static website safety and hosted-payload scanner: a guarded Cloudflare Worker fetch proxy, a browser-side analysis engine, eight detectors and a report UI. It reports observations with evidence and says what it could not check. It does not run, open or download anything from the sites it scans.

## Demonstrated coverage

These are what the automated tests in this repository actually demonstrate (run with `npm test`; the counts are from the last run before this release note was written):

- Unit and integration tests: 483 passing across the SSRF guard (IANA-derived range tables cross-checked against ipaddr.js on 5,000 random addresses, property tests on URL normalization), DNS answer validation through a DoH resolver, the manual-redirect fetcher (private and metadata targets, loops, hop limit, downgrade refusal, byte cap on bytes actually read, header allowlist, deadlines), the Worker entry (Origin check, size and schema limits, rate limiting, caching rules, Set-Cookie never returned or cached), the HTML and CSS parsers, the bounded static JavaScript analyzer, all eight detectors, the scan engine and the UI renderer.
- Safe rendering: the UI tests render hostile markup, javascript: strings, bidirectional overrides and lone surrogates and assert that no active element or attribute is created and that payload URLs are defanged. Accessibility is checked with axe-core in jsdom (color contrast is not checked there).
- Quality gates: 10 clean pages produce no high findings; every one of the 24 detector rules is recalled by at least one fixture (including location where specified); a property test shows that no single-signal page produces a high finding. **All fixtures are synthetic**, so the clean gate demonstrates behaviour on realistic synthetic pages, not on real sites.
- Headers: `public/_headers` is tested for the exact Content-Security-Policy and the other security headers, and was observed being served by a local `wrangler dev` instance.
- Local Worker checks (`wrangler dev` and curl): requests to loopback, cloud metadata and non-standard ports are refused with 403 blocked_target; requests without an Origin header are refused.

## Not verified

The following were **not** verified and no result should be assumed:

- The IANA special-purpose address and special-use domain tables in `data/` were transcribed by hand because the build environment could not reach iana.org. They must be replaced with the real downloads (commands are in `data/README.md`) before relying on them.
- The browser end-to-end test (`npm run test:e2e`) is written but has not been run: the Playwright browser could not be downloaded in the build environment. Behaviour under the production CSP, real Web Worker loading and rendering in a real browser are therefore unconfirmed.
- Nothing was run against a deployed staging Worker (`docs/staging-report.md` lists every staging check as not verified): fetches to real hosts, DNS lookups through the DoH resolver, the Rate Limiting binding on the Free plan, Cache API behaviour, subrequest counts and CPU time at the 1 MiB cap.
- No real-world clean-site corpus was captured; real captures with dates should be added.

## Residual risks

- **DNS rebinding.** The Worker validates DNS answers and then calls `fetch()` with the hostname, which resolves the name again. An attacker-controlled name can answer differently between the two lookups, and a Worker cannot pin the connection to the validated address. We believe Workers cannot reach private networks and that Cloudflare restricts some destinations, but we do not rely on that. No staging check tests rebinding, and complete SSRF prevention is not claimed.
- **Rate limiting is approximate.** The Rate Limiting binding is per Cloudflare location. If the binding is unavailable the Worker falls back to a limiter built on the Cache API; Cache API entries are local to one data centre and updates are not atomic, so this fallback is a weaker, best-effort control. Neither is a security boundary.
- **Static analysis only.** Runtime behaviour, scripts that depend on runtime values, external stylesheets, content rendered by JavaScript and the contents of downloaded files are out of scope and are reported as coverage gaps (unknown or skipped), never as clean.
- **Data handling.** The address you enter is sent to this site's fetch service and, through it, to the target; target hostnames are sent to Cloudflare's DNS-over-HTTPS resolver. Reports are built in your browser. The Worker logs counters and error codes only, not URLs or content. Cloudflare processes requests under its own terms. Secrets in URL parameters are redacted in reports, exports and displays, but they are sent to the Worker in order to perform the fetch.
- **Known dev-tool advisories.** `npm audit` reports advisories in development tooling dependencies (linting, local Worker runtime). They do not ship to production and were not force-upgraded; review them before publishing.

## Compatibility

Requires Node.js 22 or newer for development. The test package `@cloudflare/vitest-plugin` replaces the deprecated `@cloudflare/vitest-pool-workers` named in the original plan.
