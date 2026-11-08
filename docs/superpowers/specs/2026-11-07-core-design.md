# FMHY Safety Auditor: Core (Sub-project 1) Design

Date: 2026-11-07
Status: awaiting review

## 1. Purpose and success criteria

An open-source, $0-infrastructure Website Safety and Hosted Payload Auditor for the digital preservation and piracy communities, aimed at curation into the fmhy.net SafeGuard directory.

The core (this document) delivers the foundation every later module builds on: a safe fetching proxy, a deep static-analysis scan engine, a detector pipeline, a report schema, and a safe UI shell.

Success criteria for the core:
- Given a URL, the app fetches the page safely and returns structured findings, each with severity, confidence and evidence.
- Detection goes beyond visible links: it finds obfuscated, redirected and disguised payloads, and follows likely download interstitials one level deep.
- Known-clean sites produce no high-severity findings (false-positive gate, section 12).
- The app cannot be used to reach private networks, and malicious page content cannot execute in or inject into our UI.
- Everything runs on free tiers.

## 2. Product principles

1. **Depth over speed.** A scan may take several seconds if it produces better evidence.
2. **Evidence first.** Every finding carries the rule ID, the matched snippet and its source URL. Nerd Mode (sub-project 4) renders this directly.
3. **No single weak signal decides a verdict.** Findings have severity and confidence. Verdicts (sub-project 2) combine signals.
4. **Honest unknowns.** If a check can't run (blocked, timed out, truncated), the report says "unknown", never "clean".
5. **Static analysis only.** We never execute target scripts. Runtime behavior we cannot observe is reported as out of coverage.

## 3. Scope

In scope: Worker proxy, SSRF guard, scan engine with bounded depth-1 follow, detector pipeline with the core detectors below, report schema, safe rendering, Cloudflare Pages hosting, tests.

Out of scope (later sub-projects): verdict logic and Nuisance/Malice badges, filter-list matching, threat-feed lookups, Scene Integrity Check, payload size probing, shareable receipts, Nerd Mode, DoH/ASN/WHOIS enrichment, extra modules.

## 4. Architecture

    Browser (static site on Cloudflare Pages)
      UI shell  ->  Scan engine  ->  Detector pipeline  ->  Report
                         |
                         v  POST /api/fetch (same origin)
                  Cloudflare Worker
                    SSRF guard -> manual-redirect fetcher -> size/time caps -> cache

Units and their boundaries:
- **ui/**: renders a Report using `textContent` only. Depends on the Report schema.
- **engine/scan.js**: orchestrates fetches and runs detectors. Depends on the fetch client and detector interface.
- **engine/fetchClient.js**: the only code that talks to the Worker.
- **detectors/**: independent modules sharing one interface. Each is testable alone.
- **worker/**: `guard.js` (pure functions), `fetcher.js`, `index.js` (routing, CORS, cache).
- **schema/report.js**: Report and Finding types plus a validator.

## 5. Worker contract: POST /api/fetch

Request: `{ "url": "https://example.com/page" }`

Response (200): `{ finalUrl, chain: [{url, status, location?}], status, headers, html, truncated, fetchedAt }`

Errors (4xx/5xx): `{ error: "blocked_target" | "bad_url" | "timeout" | "too_many_redirects" | "upstream_error" | "rate_limited", detail }`

Rules:
- http/https only, ports 80 and 443 only, no credentials in the URL.
- Redirects followed manually, up to 5 hops. Every hop is re-validated by the guard. The full `chain` is returned (this seeds the redirect auditor in sub-project 2).
- 8 second total timeout. Body streamed and cut at about 2 MB with `truncated: true`.
- Only text-like content types are returned as `html`. Binary responses return headers and metadata only, with no body.
- Request cookies and auth headers are never sent. Fixed User-Agent.
- CORS allows our own origin only.
- Successful GETs are cached for about 10 minutes (Cache API) to stay within the free daily request budget.
- Per-IP soft rate limit using the Cache API as a counter. This is best effort, not a security boundary.

## 6. SSRF guard

Pure functions in `worker/guard.js`, unit-tested without a network.
- Parse with the standard `URL` class so forms like `127.1`, `0x7f.1`, and decimal IPs are normalized before checks.
- Reject loopback, RFC1918, link-local (including the cloud metadata address), CGNAT, multicast and reserved ranges, plus IPv6 loopback, unique-local, link-local and IPv4-mapped forms.
- Reject `localhost`, `.local`, `.internal`, and bare single-label hostnames.
- For hostnames, resolve A and AAAA through a DoH API and require every answer to be public.
- Limitation, stated openly: DNS rebinding between our check and the fetch cannot be fully closed from a Worker. Workers cannot reach private networks by platform design, so this guard is defense in depth.

## 7. Scan engine

`scan(url)` returns a Report.
1. Fetch the root URL.
2. Run all detectors on the response. Detectors may emit `followCandidates` (URLs worth fetching).
3. Fetch up to 6 follow candidates, depth 1 only. Candidates are:
   - meta-refresh and JS redirect targets;
   - same-origin links whose path or anchor text suggests download, mirror, get, or link pages;
   - off-origin targets of those pages, subject to the guard.
4. Run detectors on each followed page.
5. Hard cap: 12 fetches per scan. When the cap or a failure stops a step, record a `coverage` entry saying what was not checked.

Cache and the Worker budget: the client orchestrates, so each fetch is a separate Worker invocation. Repeat scans of popular URLs mostly hit the cache.

## 8. Detector pipeline

Interface: `{ id, version, run(ctx) -> { findings: Finding[], followCandidates?: string[] } }`. `ctx` holds the parsed `DOMParser` document (inert, no scripts or loads), raw HTML, final URL, headers and chain.

Core detectors:
- **payload-links**: `href`, `src`, `data-*`, `download`, `srcset` and inline-script URLs resolved against the final URL. Matches on the parsed pathname for `.exe .msi .zip .rar .7z .iso .apk .dmg` plus `.scr .bat .cmd .ps1 .jar .vbs .lnk .pkg .deb .appimage`. Handles query-string and fragment tricks.
- **disguised-filenames**: double extensions (`setup.pdf.exe`, `game.exe.zip`), right-to-left override (U+202E) and other control characters, homoglyph lookalikes, and archive-then-executable patterns.
- **obfuscated-urls**: `atob()` and base64 blobs, `String.fromCharCode` runs, `unescape` and `\xNN`/`\uNNNN` sequences, and split-string URL concatenation. Decoded candidates are re-run through payload-links.
- **redirects**: meta refresh, `location` assignments, `window.open`, and HTTP chain hops that cross registrable domains.
- **hidden-overlays**: invisible or full-viewport iframes and click-capture overlays, and offscreen elements containing links.
- **off-origin-forms**: forms that post to a different origin, and password fields on pages that are not the claimed origin.
- **uri-schemes**: `data:`, `blob:`, `javascript:` and `ms-*` handler links used for downloads.
- **header-hints**: `Content-Disposition: attachment` and executable content types on followed responses.

Every detector ships with positive fixtures, negative fixtures and obfuscated variants.

## 9. Schemas

Finding: `{ id, detector, ruleId, severity: "info"|"low"|"medium"|"high", confidence: "low"|"medium"|"high", title, evidence: { snippet, sourceUrl, location? }, meta? }`

Report: `{ v: 1, target, finalUrl, scannedAt, pagesScanned: [{url, status}], findings: Finding[], coverage: [{check, state: "ok"|"unknown"|"skipped", reason?}], headers }`

The schema is versioned from day one so sub-project 4 can serialize it into `?report=` URLs.

## 10. Safe rendering

- UI writes only via `textContent` and `createElement`. No `innerHTML`.
- Evidence snippets are truncated and shown in a non-interactive code element.
- Payload URLs are defanged (`hxxps://`, `[.]`) and not clickable by default. A copy button is provided.
- CSP forbids inline script and third-party origins except those added by later sub-projects.

## 11. Hosting and headers

Cloudflare Pages serves the static site and the Worker route from one origin. A `_headers` file sets CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`. No framework: vanilla ES modules and Tailwind compiled at build time.

## 12. Testing and quality gates

- Worker tests: Vitest with Miniflare. SSRF corpus includes `127.1`, `[::1]`, `::ffff:127.0.0.1`, `169.254.169.254`, decimal and hex IPs, and a public URL that redirects to a private IP.
- Detector tests: positive, negative and obfuscated fixtures per detector, including hostile filenames containing markup.
- **False-positive gate:** a corpus of saved HTML from well-known clean sites (documentation sites, news sites, popular hosting pages, ad-heavy but clean pages) must produce zero high-severity findings. CI fails otherwise.
- **Recall gate:** a corpus of synthetic and sanitized samples of known distribution patterns must produce the expected findings.
- Safety test: render a report containing script tags, event-handler attributes and `javascript:` URLs in snippets, and assert none execute.

## 13. Decisions and trade-offs

- Vanilla JS over a framework: smaller attack surface and no build complexity. Revisit if Nerd Mode needs it.
- Cloudflare Pages over GitHub Pages: real security headers.
- Static analysis only: a headless browser is not available at $0. Runtime-only behavior is reported as out of coverage, never as clean.
- Client-side orchestration: keeps each Worker call short and cacheable.

## 14. Next step

After approval of this spec, the writing-plans skill produces the implementation plan for the core.
