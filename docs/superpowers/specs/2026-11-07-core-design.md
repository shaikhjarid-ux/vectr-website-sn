# FMHY Safety Auditor: Core (Sub-project 1) Design, v2

Date: 2026-11-07
Status: revised after an external design review; awaiting user review
Changes from v1: see section 19 (review disposition) for every adopted, modified, deferred and rejected recommendation, with reasons.

## 1. Purpose and success criteria

An open-source, $0-infrastructure Website Safety and Hosted Payload Auditor for the digital preservation and piracy communities, aimed at curation into the fmhy.net SafeGuard directory.

The core delivers the foundation every later module builds on: a safe fetching proxy, a deep static-analysis scan engine, a detector pipeline, a report schema, and a safe UI shell.

Success criteria:
- Given a URL, the app fetches the page safely and returns structured findings, each with severity, confidence, category and reviewable evidence.
- Detection is deep: it finds obfuscated, redirected and disguised payloads, analyzes JavaScript structurally, and follows likely download interstitials and same-origin scripts within a measured budget.
- Known-clean sites produce no high-severity findings (false-positive gate, section 16).
- The service cannot be trivially abused as a relay, and malicious page content can neither execute in nor inject into our UI.
- Everything runs on free tiers, and the budgets in section 6 are measurable.
- Public claims match what tests demonstrate (section 18).

## 2. Product principles

1. **Depth over speed.** A scan may take tens of seconds if it yields better evidence, inside a hard deadline.
2. **Evidence first.** Every finding records the rule, the exact location and a bounded snippet. Nerd Mode (sub-project 4) renders this directly.
3. **No single weak signal produces a high-severity finding.** See the severity rules in section 13.
4. **Honest unknowns.** A check that could not run is reported as unknown or skipped with a reason code, never as clean. An incomplete scan is shown as incomplete.
5. **Static analysis only.** We never execute target code, evaluate target expressions, or run a browser. Runtime behavior is reported as out of coverage.
6. **Claims match tests.** We do not advertise prevention or proof we have not demonstrated.

## 3. Threat model (summary; full document is the first deliverable of the plan)

- **Assets:** the Worker's free quota and reputation, our visitors' browsers, third-party sites we fetch, and the integrity of reports.
- **Attacker-controlled inputs:** the submitted URL, every byte of every fetched response (HTML, scripts, headers, redirects), DNS answers for attacker-owned names, and direct calls to `/api/fetch`.
- **Trust boundaries:** browser ↔ Worker; Worker ↔ internet; fetched content ↔ analysis code; analysis output ↔ rendered UI.
- **Threats considered:** SSRF and redirect abuse; DNS tricks; resource exhaustion (bytes, CPU, memory, time, quota); XSS and resource loading from hostile markup; secret leakage through redirects, headers or logs; use of the service as an anonymous scanning relay; cache poisoning or cache leakage; misleading verdicts.
- **Out of scope:** executing or detonating payloads, defending against a compromised Cloudflare account, and any guarantee of detecting all malicious sites.

## 4. Scope

In scope: Worker proxy, SSRF guard, abuse controls, scan engine with bounded depth-1 follow and same-origin script fetching, non-loading HTML parser, detector pipeline, static JavaScript analysis, report schema, safe rendering, hosting and headers, tests, governance files.

Out of scope (later sub-projects): verdict and Nuisance/Malice badges, filter-list matching, threat-feed lookups, Scene Integrity Check, payload size probing, the contextual `distribution-patterns` detector, shareable receipts, Nerd Mode, DoH/ASN/WHOIS enrichment, extra modules.

## 5. Architecture

    Browser (static site served by the Worker's Static Assets)
      UI shell -> Scan engine -> Detector pipeline -> Report
                      |   (parse5 HTML parser; Acorn in a terminable Web Worker)
                      v  POST /api/fetch (same origin)
               Cloudflare Worker (/api/* only)
                 origin check -> rate limit -> SSRF guard -> manual-redirect fetcher
                 -> byte/time caps -> header allowlist -> local cache

Hosting decision: one Worker with Static Assets, not separate Pages and Worker deployments. Requests to static assets are free and unlimited per Cloudflare's billing documentation, so only `/api/*` consumes the 100,000 daily Worker requests. The Worker is configured with `run_worker_first` for `/api/*` only. When the daily quota is exhausted, `/api/*` returns 429 while the static site stays up.

Units:
- **ui/**: renders a Report with `textContent` only. Depends on the Report schema.
- **engine/scan.js**: orchestrates fetches, budgets and detectors. Depends on the fetch client and detector interface.
- **engine/fetchClient.js**: the only code that talks to the Worker.
- **parse/html.js**: wraps parse5. Produces a tree without loading any resource.
- **parse/css.js, parse/srcset.js, parse/url.js**: dedicated small parsers (no naive regex splitting).
- **analysis/js-worker.js**: Acorn analysis inside a terminable Web Worker.
- **net/psl.js**: registrable-domain logic from a build-time Public Suffix List snapshot.
- **detectors/**: independent modules sharing one interface.
- **worker/**: `guard.js` (pure), `ranges.js` (generated IP tables), `fetcher.js`, `limits.js`, `index.js`.
- **schema/report.js**: Report and Finding types plus validator.

## 6. Budgets and counters

Separate counters, because one scan involves different kinds of work:

| Counter | Core v1 limit | Notes |
|---|---|---|
| Logical pages | 1 root + up to 6 followed = 7 max | Depth 1 only; links found on followed pages are not followed |
| Same-origin script fetches | up to 4 | Counted toward Worker invocations |
| Worker invocations per scan | up to 11 (7 pages + 4 scripts) | One `/api/fetch` call per logical fetch. Theoretical ceiling about 9,000 maxed-out scans/day at 100,000 requests/day. This is not a capacity promise |
| Redirect hops per fetch | up to 5 (6 upstream requests) | Each hop revalidated |
| Subrequests per invocation | worst case about 22 (6 fetches, up to 12 DoH lookups, a few cache calls) against the free limit of 50 | Abort with `budget_exhausted` at 40. Cache API calls share the subrequest quota |
| Candidates collected per page | 100, ranked | Dedupe before scheduling |
| Client parallelism | up to 3 concurrent fetches | Below the Worker's 6 simultaneous connections |
| Overall scan deadline | 45 s (client) | Remaining work becomes `scan_deadline_reached` coverage |
| Per-fetch timeout | 8 s (Worker) | |
| HTML body cap | 1 MiB | Benchmark; raise only with CPU evidence |
| Script body cap | 256 KiB | |
| Static decoding passes | 3 | |
| Decoded output per script | 512 KiB | |
| URL candidates extracted per page | 100 | |
| Candidate URL length | 4 KiB | |

These are starting values to benchmark, not standards. They are tuned against the clean-site corpus and recall fixtures.

Cloudflare Workers Free limits verified on 2026-11-07 against Cloudflare's published limits page (last updated 2026-10-29): 100,000 requests/day, 10 ms CPU per request, 128 MB memory, 50 subrequests per request, 6 simultaneous outgoing connections. Recheck before deployment.

## 7. Worker contract: POST /api/fetch

Request: `{ "url": "https://example.com/page", "kind": "page" | "script" }`. Unknown fields, non-JSON, bodies over 8 KiB, and URLs over 4 KiB are rejected.

Response (200): raw bytes of the body (capped, only for text-like content types matching `kind`) with metadata in one header, `x-audit-meta`, containing base64url JSON: `{ finalUrl, chain: [{url, status, location?}], status, contentType, bytesRead, truncated, cache: "hit"|"miss", fetchedAt, headers }`. Returning raw bytes avoids decoding and JSON-escaping megabytes inside the 10 ms CPU budget. Binary or non-matching content types return metadata and an empty body.

Errors: JSON `{ error: "bad_request" | "blocked_target" | "bad_url" | "timeout" | "too_many_redirects" | "upstream_error" | "rate_limited" | "budget_exhausted", detail }` with appropriate status. Rate limiting returns 429 with `Retry-After`.

Fetch rules:
- GET only. Redirect mode `manual`, followed by our loop, with loop detection and a 5-hop cap.
- Outbound requests are built from an allowlist: fixed User-Agent and fixed `Accept` and `Accept-Language`. No cookies, no Authorization, no client-supplied headers, no body.
- HTTPS to HTTP downgrades are not followed; they are recorded in the chain as `downgrade_blocked`.
- The byte cap is enforced on the bytes actually read from the stream (after the runtime's decompression), never on `Content-Length` alone. Whether compressed or decoded bytes are counted is verified in staging.
- Response headers returned to the client come from an allowlist (`content-type`, `content-disposition`, `content-length`, `content-encoding`, `cache-control`, `etag`, `last-modified`, `server`, `x-powered-by`, `location`, plus the security headers Nerd Mode needs). `Set-Cookie`, authentication and proxy headers are never returned.
- The Worker sets its own security headers on every `/api/*` response, because static `_headers` rules apply only to asset responses.

Caching: Cache API, local to one data centre per Cloudflare's documentation, so it is a best-effort cache only. Keys are the normalized final URL under a fixed internal namespace. We never cache responses carrying `Set-Cookie` (we strip it), `Cache-Control: private` or `no-store`. Query strings are preserved in keys. Cache misses and failures are normal and never a scan failure. Cache entries may hold fetched page material for about 10 minutes, which the privacy notice states.

## 8. SSRF guard

Pure functions in `worker/guard.js`, testable without a network.
- Parse once with the WHATWG `URL` class, so unusual IPv4 forms (`127.1`, `0x7f.1`, decimal) and IPv6 forms are normalized, then decide on the normalized host.
- Allow only `http:` and `https:`, ports 80 and 443, and no username or password. Normalize case, IDNA/punycode and trailing dots. Reject `localhost`, `.local`, `.internal` and single-label hosts.
- Classify IP addresses with generated range tables built from the IANA IPv4 and IPv6 special-purpose registries, not a hand-written list. Reject non-global destinations: loopback, private, link-local, CGNAT, multicast, unspecified, documentation, benchmarking, reserved, plus IPv6 unique-local, link-local, IPv4-mapped and zone identifiers. Whether to generate the tables ourselves or use a maintained library such as ipaddr.js is decided in the plan by the test corpus. Parse failure fails closed.
- For hostnames, resolve A and AAAA through Cloudflare's DoH resolver and require every answer, including every address behind CNAME chains, to be global. Any disallowed answer rejects the hostname; we never pick a public answer out of a mixed set. The privacy notice states that target hostnames are sent to this resolver.
- Revalidate every redirect hop with the same checks.

Residual risk, stated plainly: validating DNS and then fetching by hostname leaves a time-of-check/time-of-use gap (DNS rebinding) that a Worker cannot fully close, because `fetch()` resolves the name itself. We believe Workers cannot reach private networks and that Cloudflare restricts some destinations, but we do not rely on that belief: the staging test suite (section 16) probes real behavior, and the release notes document the residual risk. We do not claim complete SSRF prevention.

## 9. Abuse controls and privacy

CORS is not access control: it only governs which browser origins may read responses. It does not stop curl or scripts. So:
- **Origin enforcement:** `/api/fetch` requires `Origin` to equal our origin and `Content-Type: application/json` (which forces a preflight for other sites), blocking other websites from using our visitors' browsers as a relay. Direct non-browser callers are handled by rate limiting.
- **Rate limiting:** the Workers Rate Limiting binding, keyed per client IP, with generous limits. Cloudflare documents these limits as approximate and per location, so they are a best-effort control, not a security boundary. The binding's availability on the Free plan is confirmed at deployment; if unavailable, fall back to a local Cache API counter.
- **Global budget:** the Free-plan daily cap is the backstop. Exceeding it makes `/api/*` return 429 while the site stays up (see section 5).
- **Deferred:** Durable Object coordinated limits and Cloudflare Turnstile. Revisit if abuse appears.
- **Abuse reporting:** README and `SECURITY.md` carry a contact path for takedown and abuse reports.
- **Privacy:** no accounts, no central scan history. Worker logs record counters and error codes, never full URLs, query strings, page content or evidence. Secret-bearing query parameters (token, key, auth, session, signature, access_token and similar) are redacted in reports and logs, without changing the URL actually fetched. No third-party analytics. We do not claim "zero data collection": Cloudflare processes requests and cache entries are temporary.

## 10. Scan engine

`scan(url)` returns a Report.
1. Fetch the root page.
2. Parse with parse5 (section 11). Run detectors. Detectors emit `followCandidates`, each with `url`, `reason`, `priority`, `sourceEvidence` and `depth: 1`.
3. Rank candidates (below), dedupe normalized URLs, and fetch up to 6 follow pages.
4. Fetch up to 4 same-origin external scripts from the root, ranked by document order and skipping well-known library filenames (jquery, bootstrap, react, vue, angular, lodash and similar). Each is analyzed in the JS worker.
5. Run detectors on each followed page.
6. Record coverage per detector and per page, including everything skipped or truncated.

Candidate ranking: (1) explicit download buttons and links, meta refresh, static JS redirect targets, download-related form actions; (2) same-origin paths or anchor text such as download, mirror, get, installer, link, redirect; (3) off-origin targets of those pages, only with strong source context. Hard deadline and budgets from section 6 apply. Depth 2 (interstitial to final host) is deferred until depth-1 recall data exists; the `depth` field keeps it a small change.

## 11. Parsing and detectors

**No live DOM from target markup.** `DOMParser` parses scripts as non-executable but, per MDN, the resulting document can still download image and iframe resources. So we parse the raw HTML string with parse5, which builds a plain object tree and loads nothing. Our own CSP (`img-src 'self' data:`, `frame-src 'none'`) is a second layer.

Interface: `{ id, version, run(ctx) -> { findings, followCandidates?, coverage? } }`. `ctx` holds the parse5 tree, raw HTML, final URL, effective base URL, headers and chain.

URL handling: record both the final response URL and the effective document base (`<base href>`), resolve relative URLs against the effective base, and keep the raw attribute value as evidence. Normalize percent-encoding and extension case with a bounded number of decode passes. Do not treat every query parameter as a filename.

Core detectors:
- **payload-links:** `a[href]`, `area`, `link`, `iframe`, `embed[src]`, `object[data]`, `video[poster]`, `source`, `srcset`, SVG `href`/`xlink:href`, form actions, CSS `url()` and `@import` (style attributes and blocks), and `data-*` attributes only when the attribute name or value is URL-like. Match on the parsed pathname for `.exe .msi .zip .rar .7z .iso .apk .dmg .scr .bat .cmd .ps1 .jar .vbs .lnk .pkg .deb .appimage`. `iframe[srcdoc]` is parsed once as a nested document (depth 1).
- **disguised-filenames:** double extensions, right-to-left override and other control characters, homoglyphs, archive-then-executable patterns.
- **obfuscated-urls:** base64 blobs, `String.fromCharCode` runs, `unescape`, `\xNN`/`\uNNNN` escapes, split-string concatenation. Decoded candidates are re-run through payload-links.
- **redirects:** meta refresh, `location` assignments, `window.open`, HTTP chain hops that cross registrable domains. Registrable-domain logic uses the Public Suffix List, not string splitting.
- **hidden-overlays:** static markup and style heuristics for invisible or full-viewport iframes, click-capture layers and off-screen links. Confidence is capped at medium because we do not compute styles.
- **off-origin-forms:** forms posting to another origin, and password fields on pages whose origin does not match the apparent brand context.
- **uri-schemes:** `data:`, `blob:`, `javascript:` and `ms-*` handler links used for downloads. A `blob:` reference means a runtime resource that was not inspected; it is reported as such.
- **header-hints:** `Content-Disposition` on the root response and on every followed response. Both `filename` and `filename*` are parsed, with `filename*` taking precedence.

Weak indicators are reported as observations, not verdicts. Examples: an executable extension means an executable-looking link was found, not that it contains malware; punycode means the hostname deserves visual review, not that it is malicious; an off-origin form means it posts elsewhere, not that credentials are stolen.

## 12. Static JavaScript analysis

Acorn parses inline scripts and fetched same-origin scripts into syntax trees inside a terminable Web Worker with size and time limits. We never execute, `eval`, or run target code.

A bounded constant folder evaluates only literals: string literals, `+` concatenation, template literals whose expressions resolve to known constants, single-assignment `const`/`var` string constants within a file, `.join('')` on literal arrays, and `atob`, `unescape`, `decodeURIComponent` and `String.fromCharCode` applied to literals. It has fixed step, depth and output limits (section 6).

It looks for static assignments to `location`, `window.open` calls, `document.write` of URLs, programmatic anchors with `download`, and constructed URL fragments. Existing regex signatures remain as a lightweight fallback and triage layer; the AST adds context and cuts pattern-only false positives. If a script cannot be parsed, uses unsupported syntax, needs runtime values, or exceeds a cap, the JavaScript check is recorded as `unknown` or `partial` with a reason code.

## 13. Schemas, severity and coverage

Finding: `{ id, fingerprint, detector, ruleId, category, severity, confidence, title, observations: [{ evidence }] }`
- `category`: payload, obfuscation, redirect, filename, interface, credential, distribution, infrastructure.
- `evidence`: `{ snippet (bounded plain text), sourceUrl (sanitized), location: { type: "html_attribute"|"script_range"|"response_header", tag?, attribute?, line?, column? }, matchedValue (display-sanitized), normalizedValue, context }`.
- `fingerprint`: SHA-256 over a canonical sanitized representation (rule, normalized target with secret-like query values redacted). The same target found through HTML, JavaScript and decoding becomes one finding with several observations.

Report: `{ v: 1, engineVersion, detectorVersions, scannedAt, durationMs, target, finalUrl, pagesScanned: [{ url, status, contentType, bytesRead, truncated, redirectChain }], findings, coverage, fetchStats: { attempted, successful, cached, failed }, headers }` with `target` and `finalUrl` in display-sanitized form.

Coverage: per detector and per page where possible. State is `ok`, `unknown` (attempted, no reliable conclusion) or `skipped` (intentionally not done), with a stable reason code such as `response_truncated`, `fetch_timeout`, `script_parse_limit_reached`, `resource_budget_exhausted`, `scan_deadline_reached`, `external_stylesheet_skipped`, `unsupported_runtime_behavior`.

Severity rules: a lone weak signal (executable extension, punycode, `blob:`, an unrelated mirror link) is `info` or `low`. `medium` requires an obfuscated, redirected or disguised path to an executable-looking target. `high` requires corroboration: two independent detectors agreeing on the same target, or an automatically triggered download path (meta refresh or script navigation leading to an executable-looking target). Confidence is separate from severity and reflects how reliable the detection method is.

## 14. UI and safe rendering

Single page: header with a plain statement that this is static analysis; URL input (client validation for usability only, with all security checks repeated in the Worker); accessible progress states; report overview showing findings count and scan coverage separately; expandable findings (severity, confidence, category, rule, source page, element and attribute, snippet, normalized value, why it matched); a coverage panel listing unknown and skipped checks and pages not inspected; copy-summary and local JSON export.

No bare "safe" verdict. When sub-project 2 adds the Nuisance/Malice badges, wording must be scope-limited (for example "No threats detected within the scanned scope"). The ad-heavy badge you specified remains, with its wording.

Persistent disclaimer: "No detected findings does not establish that a website is safe. This scanner performs static analysis only; it cannot observe all runtime behavior or determine whether a downloaded file is malicious. An incomplete scan is shown as incomplete, not clean."

Rendering rules:
- All target-controlled strings go in through `textContent` and `createElement`. No `innerHTML`, no iframe of fetched content.
- No live `href`, `src` or `style` set from discovered content: displaying a URL must never make the browser fetch it. Payload URLs are defanged (`hxxps://`, `[.]`) and non-clickable; a copy button is provided. Any raw reveal option states the risk.
- Snippets sit in bounded, non-interactive code elements.
- Severity is conveyed with text labels, not color alone. Keyboard operable, visible focus, labeled inputs, responsive cards, restrained screen-reader announcements.

## 15. Hosting and headers

Static Assets `_headers` (asset responses only) set:

    default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
    font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none';
    base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests

plus HSTS (after confirming the domain policy), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy` and `X-Frame-Options: DENY`. Trusted Types (`require-trusted-types-for 'script'`) is tried in report-only mode first. No inline scripts; Web Workers load from `'self'`. The policy is a starting point validated against the deployed site. Vanilla ES modules, Tailwind compiled at build, parse5 and Acorn bundled locally.

## 16. Testing and quality gates

- **Guard and URL:** `127.1`, hex and decimal IPv4, IPv4-mapped IPv6, zone IDs, localhost variants, IDNA, trailing dot, mixed A/AAAA, CNAME chains, IANA special-use ranges. Fuzz and property tests for guard, URL and parser utilities.
- **Redirects:** public to private redirect, loops, excessive hops, malformed `Location`, HTTPS downgrade, credential-bearing redirect URLs.
- **Resource safety:** malformed HTML, image and iframe references, oversized streams, misleading `Content-Length`, compression expansion, slow responses, header-size cap.
- **Cache:** query variants, token-like parameters, `Set-Cookie`, private/no-store, stale entries, miss behavior.
- **API abuse:** large POST, unknown JSON properties, wrong Origin, repeated scans, direct non-browser calls, per-IP limit and 429.
- **Detectors:** positive, negative, obfuscated and hostile-input fixtures for each detector; JS fixtures for the constant folder and AST paths.
- **Coverage:** truncated HTML, parser failure, unsupported JS, skipped resources, exhausted budgets, failed DoH.
- **UI safety:** script tags, event handlers, `javascript:` strings, malformed Unicode and payload URLs in snippets render as inert text. Accessibility checks.
- **False-positive gate:** saved HTML from known-clean sites must yield zero high-severity findings. Every fixture is versioned with its capture date because sites change.
- **Recall gate:** synthetic and sanitized distribution samples must yield the expected rule IDs and evidence locations.
- **Severity calibration test:** a lone weak signal can never produce `high`.
- **Staging verification:** Miniflare tests are not proof of deployed DNS and network behavior. Real Worker deployment is tested against controlled endpoints for redirects, DNS changes, timeouts, subrequest counts, rate limiting, cache locality, and what `fetch()` actually connects to.
- **Regression:** every fixed bug becomes a fixture, and detector versions are tested before release.

## 17. Governance files

`SECURITY.md` (disclosure), `CONTRIBUTING.md`, an open-source licence, dependency lockfile, automated dependency updates, release notes with detector-rule versions, a per-detector document (supported inputs, blind spots, confidence meaning, known false positives), and a retention statement for cache entries and platform logs, noting what is outside our direct control.

## 18. Release claims

We will not state that the scanner prevents all SSRF, detects all malicious downloads, proves a site safe, or collects zero data. Release notes list demonstrated test coverage and the residual risks from sections 8 and 9.

## 19. Review disposition

Each item from the review, with what was independently checked.

| Recommendation | Decision | Reason |
|---|---|---|
| Replace DOMParser with a non-loading parser (parse5) | Adopted | Verified on MDN: parsed documents can still download iframe and img resources. v1 wrongly called it inert |
| Separate page, Worker, subrequest and deadline counters; fix 7 vs 12 | Adopted | v1's "12 fetches" contradicted "1 root + 6". Now 7 pages + 4 scripts = 11 invocations, with every counter defined |
| Corrected scan-volume math | Adopted with caveat | 100,000/7 is about 14,285 and 100,000/11 is about 9,090; both are theoretical ceilings, not capacity |
| Cloudflare Free limits | Verified and adopted | Confirmed on Cloudflare's limits page (updated 2026-10-29). Also found that Cache API calls share the 50-subrequest quota, which the review omitted |
| Cache API is local, not a global counter | Verified and adopted | Confirmed in Cloudflare's Cache documentation |
| Rate limiting via Cache API counter | Modified | Replaced with the Workers Rate Limiting binding (approximate, per location, documented), which the review did not mention. Plan Free-plan availability to be confirmed |
| CORS is not access control | Adopted | Correct. Added Origin enforcement against cross-site relay use, plus rate limits |
| Durable Object global limiter | Deferred | Adds cost and complexity. Not verified here; revisit if abuse appears |
| IANA-based range tables; WHATWG URL parsing | Adopted | Hand-written lists are error-prone. Test corpus decides generated table vs library |
| DNS rebinding as a deployment blocker | Modified | Downgraded to a documented residual risk plus a mandatory staging test. A Worker has no private network of ours behind it, and the claim of complete prevention is dropped |
| Manual redirects, per-hop validation, allowlisted request headers | Adopted | Already planned; now explicit, with downgrade blocking |
| Streaming byte cap, header allowlist, redaction | Adopted | Plus a design change: raw-bytes response with metadata header to protect the 10 ms CPU budget |
| Privacy and no-URL logging | Adopted | No "zero data collection" claim |
| CSP starting policy | Adopted with changes | Added Worker-set headers (static `_headers` do not cover Worker responses), Web Worker note, Trusted Types in report-only |
| Hosting on Cloudflare Pages | Modified | One Worker with Static Assets. Cloudflare documents free unlimited asset requests and `_headers` for it; Pages is not required. Third-party claims that Pages is being phased out were not relied on |
| `<base href>`, expanded elements, srcset/CSS parsers, `filename*` | Adopted | Closes real blind spots |
| External stylesheet fetching | Rejected for Core | Budget better spent on same-origin scripts. Recorded as `external_stylesheet_skipped` |
| Acorn AST inspection in a Web Worker | Adopted | Plus a defined, bounded constant folder; never executes target code |
| `distribution-patterns` ninth detector | Deferred | Needs cross-page aggregation and verdict context, so it belongs in sub-project 2 |
| Weak-indicator wording; severity calibration | Adopted | Added concrete severity rules and a test |
| No green "safe" verdict | Adopted with wording change | Your ad-heavy badge stays; verdict wording must be scope-limited |
| Depth 1 only; defer depth 2 | Adopted | `depth` field keeps depth 2 a later small change |
| Candidate ranking with reasons | Adopted | |
| Parsing and decoding caps | Adopted as starting values | To benchmark |
| Schema additions, fingerprints, coverage reason codes | Adopted | Fingerprint is a plain SHA-256 over a sanitized canonical form; a "keyed" hash adds nothing client-side |
| Accessibility, governance files, fuzz tests, staging tests | Adopted | Cheap and valuable |
| Public Suffix List for registrable domains | Adopted | v1 compared domains without it |
| Threat model first | Adopted | Section 3 summary; full document is the plan's first task |
| Third-party script fetching, binary analysis, receipts, voting | Deferred or out of scope | Per scope in section 4 |
| Independent standards claims (IANA registries, WHATWG URL, OWASP, CSP directives, `filename*` precedence, parse5, Acorn, PSL) | Accepted from background knowledge | Stable and consistent with what I know; I did not re-fetch each. DO limits and OWASP wording were not verified here |

## 20. Next step

After approval of this spec, the writing-plans skill produces the implementation plan for the core.
