# Release notes: Vectr Website SN Core 0.1.0

Core is a static website safety and hosted-payload scanner: a guarded Cloudflare Worker fetch proxy, a browser-side analysis engine, eight detectors and a report UI. It reports observations with evidence and says what it could not check. It does not run, open or download anything from the sites it scans.

## Demonstrated coverage

These are what the automated tests in this repository actually demonstrate (run with `npm test`; the counts are from the latest run):

- Unit and integration tests: **510 passing** across the SSRF guard (IANA-derived range tables cross-checked against ipaddr.js on 5,000 random addresses, property tests on URL normalization), DNS answer validation through a DoH resolver, the manual-redirect fetcher (private and metadata targets, loops, hop limit, downgrade refusal, byte cap on bytes actually read, header allowlist, deadlines), the Worker entry (Origin check, size and schema limits, rate limiting, caching rules, Set-Cookie never returned or cached), the HTML and CSS parsers, the bounded static JavaScript analyzer, all eight detectors, the scan engine and the UI renderer.
- The IANA tables in data/ are the official downloads, captured 2026-11-12. The generated address ranges matched the earlier hand-typed ranges exactly, and the special-use domain list gained 4 names.
- Browser end-to-end tests (Chromium through Playwright, a local wrangler dev server, a mocked fetch service): 3 pass. The real Web Worker loads with no CSP or Trusted Types violations, hostile markup in file names renders as inert text, and the static page is served with the CSP. These do not test the deployed site.
- Safe rendering: the UI tests render hostile markup, javascript: strings, bidirectional overrides and lone surrogates and assert that no active element or attribute is created and that payload URLs are defanged. Accessibility is checked with axe-core in jsdom (color contrast is not checked there).
- Quality gates: 10 clean pages produce no high findings; every one of the 24 detector rules is recalled by at least one fixture (including location where specified); a property test shows that no single-signal page produces a high finding. **All fixtures are synthetic**, so the clean gate demonstrates behaviour on realistic synthetic pages, not on real sites.
- Headers: `public/_headers` is tested for the exact Content-Security-Policy and the other security headers, and was observed being served by a local `wrangler dev` instance.
- Local Worker checks (`wrangler dev` and curl): requests to loopback, cloud metadata and non-standard ports are refused with 403 blocked_target; requests without an Origin header are refused.
- Staging checks against the deployed Cloudflare Workers (staging report dated 2026-11-14): redirects to private and cloud-metadata addresses are refused (403), a redirect loop and a six-hop chain are stopped (502), a slow-drip body times out at the 8 s deadline (504), an oversized body with a false Content-Length is capped at exactly 1,048,576 bytes, and a Set-Cookie response is not returned or cached. The Rate Limiting binding exists and limits requests on this account's plan, but loosely: in one burst of 40 parallel requests only 2 were refused, so treat it as approximate.

## Not verified

The following were **not** verified and no result should be assumed:

- Not measured on the deployed Worker: DNS rebinding resistance (rebinding is a documented residual risk), the subrequest count per scan, and CPU time at the 1 MiB cap (the oversized-body check completed without a CPU-limit error, which is not a measurement).
- No real-world clean-site corpus was captured; real captures with dates should be added.

## Residual risks

- **DNS rebinding.** The Worker validates DNS answers and then calls `fetch()` with the hostname, which resolves the name again. An attacker-controlled name can answer differently between the two lookups, and a Worker cannot pin the connection to the validated address. We believe Workers cannot reach private networks and that Cloudflare restricts some destinations, but we do not rely on that. No staging check tests rebinding, and complete SSRF prevention is not claimed.
- **Rate limiting is approximate.** The Rate Limiting binding is per Cloudflare location. If the binding is unavailable the Worker falls back to a limiter built on the Cache API; Cache API entries are local to one data centre and updates are not atomic, so this fallback is a weaker, best-effort control. Neither is a security boundary.
- **Static analysis only.** Runtime behaviour, scripts that depend on runtime values, external stylesheets, content rendered by JavaScript and the contents of downloaded files are out of scope and are reported as coverage gaps (unknown or skipped), never as clean.
- **Data handling.** The address you enter is sent to this site's fetch service and, through it, to the target; target hostnames are sent to Cloudflare's DNS-over-HTTPS resolver. Reports are built in your browser. The Worker logs counters and error codes only, not URLs or content. Cloudflare processes requests under its own terms. Secrets in URL parameters are redacted in reports, exports and displays, but they are sent to the Worker in order to perform the fetch.
- **Known dev-tool advisories.** `npm audit` reports advisories in development tooling dependencies (linting, local Worker runtime). They do not ship to production and were not force-upgraded; review them before publishing.

## Compatibility

Requires Node.js 22 or newer for development. The test package `@cloudflare/vitest-plugin` replaces the deprecated `@cloudflare/vitest-pool-workers` named in the original plan. The scanner Worker uses the `global_fetch_strictly_public` compatibility flag so that `fetch()` behaves as if made from the public Internet; without it, Cloudflare refuses fetches to another Worker on the same zone with error 1042.