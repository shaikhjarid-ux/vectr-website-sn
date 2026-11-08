# FMHY Safety Auditor Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Core (sub-project 1): a guarded Cloudflare Worker fetch proxy plus a client-side static-analysis scan engine, detector pipeline, report schema and safe UI.

**Architecture:** One Worker serves Static Assets and handles `/api/*` only (`run_worker_first`). The Worker validates, rate-limits, fetches with manual redirects and returns capped raw bytes plus a metadata header. The browser orchestrates scans within budgets, parses HTML with parse5, analyzes JavaScript with Acorn in a terminable Web Worker, runs detectors, and renders a Report with `textContent` only.

**Tech Stack:** Plain JavaScript ES modules with JSDoc types, Node.js 22 or newer, Wrangler, Vitest with `@cloudflare/vitest-pool-workers`, parse5, Acorn, tldts, esbuild, Tailwind CLI, jsdom, axe-core, fast-check, Playwright, ipaddr.js (dev-only cross-check).

**Spec:** `docs/superpowers/specs/2026-11-07-core-design.md`

**Implementation rules:** Treat this plan as a technical specification, not unquestionable instructions. Verify every library API, Cloudflare constraint, security assumption and test expectation against current documentation. If a step is unsafe, unreliable, needlessly complex or contradicts the project's purpose, stop and explain before implementing it. Never record a security check as passed unless it was actually run and verified; unverified checks are recorded as "not verified".

## Global Constraints

Every task's requirements include these (values copied from the spec).

- Static analysis only: never execute, `eval` or run target code, and never run a browser against targets. Runtime behavior is reported as out of coverage.
- Parse target HTML with parse5 only. Never `DOMParser`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` (lint-enforced in `src/`). Target-controlled strings render via `textContent` and `createElement`.
- Budgets: pages 7 (1 root + up to 6 followed, depth 1 only); same-origin scripts 4; Worker invocations 11; redirect hops 5 (6 upstream requests); client parallelism 3; overall scan deadline 45 s; per-fetch timeout 8 s; HTML cap 1 MiB; script cap 256 KiB; static decoding passes 3; decoded output 512 KiB per script; URL candidates 100 per page; candidate URL length 4 KiB; subrequest abort at 40 (free limit 50).
- Workers Free limits (verified 2026-11-07): 100,000 requests/day, 10 ms CPU, 128 MB memory, 50 subrequests, 6 simultaneous connections. Recheck before deploying.
- Fetch rules: GET only; redirect mode `manual` with per-hop revalidation; fixed User-Agent, Accept and Accept-Language only; no cookies, Authorization, client headers or body; HTTPS-to-HTTP downgrade not followed; byte cap on bytes actually read; response header allowlist; never return `Set-Cookie`.
- Targets: http/https only, ports 80 and 443 only, no username or password. Hostnames that are special-use names (IANA Special-Use Domain Names registry, last updated 2026-05-22, which applies to listed names and all their subdomains, so `*.localhost` is included), any `.arpa` name, `internal`, and single-label names are rejected; `example.com`, `example.net`, `example.org` are allowed because they resolve publicly and the DoH check still applies.
- Secrets in URLs: every report field, export and display passes through `sanitizeReport`/`redactUrl`/`redactText`; original URLs live only in transient scan state needed to perform fetches.
- DNS lookups share the same 8 s deadline and abort signal as the upstream fetch.
- Browser-to-Worker requests use `credentials: 'omit'`.
- Rate limiting is best-effort abuse protection (approximate, per Cloudflare location, shared IPs aggregate users); it is never an SSRF boundary.
- Error codes: `bad_request`, `blocked_target`, `bad_url`, `timeout`, `too_many_redirects`, `upstream_error`, `rate_limited`, `budget_exhausted`.
- Coverage reason codes include `response_truncated`, `fetch_timeout`, `script_parse_limit_reached`, `resource_budget_exhausted`, `scan_deadline_reached`, `external_stylesheet_skipped`, `unsupported_runtime_behavior`.
- Severity: a lone weak signal is `info` or `low`; `medium` needs an obfuscated, redirected or disguised path to an executable-looking target; `high` needs two independent detectors agreeing on one target, or an automatically triggered download path.
- CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`.
- UI: no bare "safe" verdict. Persistent disclaimer text, exactly: "No detected findings does not establish that a website is safe. This scanner performs static analysis only; it cannot observe all runtime behavior or determine whether a downloaded file is malicious. An incomplete scan is shown as incomplete, not clean."
- Never claim: prevents all SSRF, detects all malicious downloads, proves a site safe, zero data collection.
- No inline scripts, no third-party analytics, dependencies bundled locally.

## Review Focus

Inputs the spec implies but its tests do not cover, most likely first. Each has a test in the owning task.

- A URL pasted without a scheme, with spaces, with a port (`example.com:443/path`, `example.com:8080/path`), or with `view-source:`, `javascript:` or `file:` (Task 22): scheme-less input, including host:port, becomes `https://`; other schemes give a clear error.
- A JavaScript-rendered shell page with almost no HTML (Task 22): the report says static coverage is limited, never an empty "clean" result.
- A target that is not an HTML page: direct `.exe`/`.zip` link, 403/503, or a challenge or captcha page (Task 22): reported as skipped or blocked with a reason, plus the target-URL finding for binaries.
- Non-UTF-8 pages: windows-1252, Shift-JIS, BOM (Task 8): decoded correctly so extracted URLs are not corrupted; unknown charset falls back to UTF-8 and is noted.
- A link farm with hundreds of identical payload links (Task 14): one finding with a capped observation list and a total count.

## File Structure

    src/shared/{url-safety.js, codes.js}        redaction, defang, error and reason codes
    src/schema/report.js                         typedefs, validator, fingerprint
    src/worker/{ranges.js (generated), ip.js, guard.js, resolve.js, fetcher.js, limits.js, headers.js, index.js}
    src/engine/{budget.js, decode.js, fetchClient.js, candidates.js, scan.js}
    src/parse/{url.js, srcset.js, css.js, html.js}
    src/net/psl.js
    src/analysis/{fold.js, analyzer.js, js-worker.js}
    src/detectors/{index.js, payload-links.js, disguised-filenames.js, obfuscated-urls.js, redirects.js, hidden-overlays.js, forms-and-schemes.js, header-hints.js}
    src/ui/{render.js, app.js, index.html, styles.css}
    public/_headers   data/iana-*.csv   scripts/{build.mjs, gen-ranges.mjs, staging/}
    tests/ (mirrors src/), tests/fixtures/{clean,recall,lint}/   docs/ (threat-model, detectors/, staging-report, release notes)

Shared typedefs (defined in Task 2, used everywhere): `Severity` info|low|medium|high; `Confidence` low|medium|high; `Category` payload|obfuscation|redirect|filename|interface|credential|distribution|infrastructure; `ChainEntry {url, status, location?, note?}`; `Evidence {snippet, sourceUrl, location: {type: 'html_attribute'|'script_range'|'response_header', tag?, attribute?, line?, column?}, matchedValue, normalizedValue, context}`; `CoverageEntry {check, page?, state: 'ok'|'unknown'|'skipped', reason?}`.

---

### Task 1: Scaffold, governance and lint bans

**Files:** Create `package.json`, `wrangler.jsonc`, `vitest.config.js`, `eslint.config.js`, `scripts/build.mjs`, `.github/dependabot.yml`, `README.md`, `LICENSE` (MIT as default, owner may change), `SECURITY.md` (disclosure and abuse reports through GitHub private vulnerability reporting), `CONTRIBUTING.md`, `docs/threat-model.md`, stubs `src/ui/{index.html,app.js,styles.css}` and `src/analysis/js-worker.js` (replaced in Tasks 13 and 23), `tests/repo.test.js`, `tests/fixtures/lint/banned-sinks.js`.
**Interfaces:** Produces npm scripts `test`, `lint`, `build` (writes `dist/`), `dev`; `wrangler.jsonc` with `main: "src/worker/index.js"`, `assets: {directory: "dist", run_worker_first: ["/api/*"]}`, a `ratelimits` binding `FETCH_LIMITER` (`namespace_id: "1001"`, simple, limit 30, period 60) and var `ENVIRONMENT`.

- [ ] **Step 1:** Write `tests/repo.test.js` asserting: the files above exist; `docs/threat-model.md` has headings `Assets`, `Attacker-controlled inputs`, `Trust boundaries`, `Threats considered`, `Out of scope`, `Residual risks`; parsed `wrangler.jsonc` has `assets.run_worker_first` equal to `["/api/*"]`; running ESLint on `tests/fixtures/lint/banned-sinks.js` (uses `DOMParser`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) with the repo config applied to `src/**`-style rules returns at least 5 errors.
- [ ] **Step 2:** Run `npx vitest run tests/repo.test.js`. Expected: FAIL (files missing).
- [ ] **Step 3:** Create the scaffold. Install dev and runtime dependencies from the Tech Stack line (parse5, acorn, tldts as runtime, bundled). ESLint: `no-restricted-globals` for `DOMParser`; `no-restricted-properties` for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`. `scripts/build.mjs`: esbuild-bundle `src/ui/app.js` and `src/analysis/js-worker.js` into `dist/`, compile Tailwind from `src/ui/styles.css`, copy `src/ui/index.html` and `public/_headers`. Threat model: spec section 3, plus the DNS-rebinding residual risk from spec section 8 under `Residual risks`.
- [ ] **Step 4:** Run `npx vitest run`, `npm run lint`, `npm run build`. Expected: all pass or exit 0.
- [ ] **Step 5:** Commit `chore: scaffold project, governance files, lint bans`.

### Task 2: Shared URL safety, codes and report schema

**Files:** Create `src/shared/url-safety.js`, `src/shared/codes.js`, `src/schema/report.js`, `tests/shared/url-safety.test.js`, `tests/schema/report.test.js`.
**Interfaces:** Produces:
- `redactUrl(url: string): string` (replaces values of params named token, key, auth, session, signature, access_token, apikey, api_key, password, secret, case-insensitive, with `REDACTED`).
- `defang(url: string): string`; `displayUrl(url: string): string` = `defang(redactUrl(url))`.
- `makeFingerprint(ruleId: string, normalizedTarget: string): Promise<string>` (hex SHA-256 of `ruleId + "\n" + redactUrl(normalizedTarget)`).
- `redactText(text: string): string` (redacts the same parameter names inside free text such as snippets: `name=value` after `?`, `&` or `;`); `sanitizeReport(report: Report): Report` (returns a deep copy where every URL-bearing field is passed through `redactUrl` and every snippet, matchedValue, normalizedValue and context through `redactText`: `target`, `finalUrl`, `pagesScanned[].url` and `redirectChain`, chain entries `url` and `location`, evidence `sourceUrl`, `snippet`, `matchedValue`, `normalizedValue`, `context`, and finding `observations`).
- `validateReport(report: unknown): {ok: boolean, errors: string[]}`; constants `SEVERITIES`, `CONFIDENCES`, `CATEGORIES`, `COVERAGE_STATES`; `ERROR_CODES`, `REASON_CODES` in `codes.js` (values from Global Constraints).
- Report shape per spec section 13 (`v`, `engineVersion`, `detectorVersions`, `scannedAt`, `durationMs`, `target`, `finalUrl`, `pagesScanned`, `findings`, `coverage`, `fetchStats`, `headers`); Finding adds `id`, `fingerprint`, `observations`, `observationCount`.

- [ ] **Step 1:** Tests: `redactUrl('https://a.com/?token=abc&q=1')` equals `'https://a.com/?token=REDACTED&q=1'` and leaves `?q=1` untouched; `defang('https://a.b.example/x.exe?x=1')` equals `'hxxps://a[.]b[.]example/x.exe?x=1'`; fingerprints are equal for two URLs differing only in a `token` value and differ for different rule IDs; `validateReport` rejects a missing `v`, severity `'critical'`, and coverage state `'maybe'`, and accepts a minimal valid report; `sanitizeReport` test: build a report with `?token=SECRET123` in every URL-bearing field listed above and in snippet text, then assert `JSON.stringify(sanitizeReport(report))` does not contain `SECRET123` while non-secret parameters survive.
- [ ] **Step 2:** Run `npx vitest run tests/shared tests/schema`. Expected: FAIL.
- [ ] **Step 3:** Implement the signatures above. Use `URL`/`URLSearchParams` for redaction, preserving all other parameters and ordering; fall back to returning the input unchanged if it does not parse. Fingerprint via `crypto.subtle.digest`.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `feat: shared url safety, codes and report schema`.

### Task 3: IANA range tables and IP classification

**Files:** Create `data/iana-ipv4-special.csv`, `data/iana-ipv6-special.csv`, `data/iana-special-use-domains.csv` (downloaded from the IANA special-purpose address and special-use domain registries, capture dates in `data/README.md`), `scripts/gen-ranges.mjs`, `src/worker/ranges.js` and `src/worker/special-domains.js` (generated, committed), `src/worker/ip.js`, `tests/worker/ip.test.js`.
**Interfaces:** Produces `parseIp(text: string): {version: 4 | 6, bytes: Uint8Array} | null` (dotted IPv4; IPv6 with compression and embedded IPv4; zone identifiers return null) and `isGlobalIp(ip: string): boolean` (false on any parse failure), and `isSpecialUseHost(host: string): boolean` (true when the normalized host equals or is a subdomain of a registry name, or ends in `.arpa`, or equals or ends in `.internal`; `example.com`, `example.net`, `example.org` and their subdomains are excluded by a documented allowlist). Decision: generate our own tables, because there is no runtime dependency or per-request cost; ipaddr.js is a dev-only cross-check.

- [ ] **Step 1:** Tests, `isGlobalIp` false for `0.0.0.0 10.1.2.3 127.0.0.1 169.254.169.254 100.64.0.1 172.16.0.1 192.168.1.1 192.0.2.1 198.51.100.1 203.0.113.1 224.0.0.1 255.255.255.255 :: ::1 fc00::1 fe80::1 ff02::1 2001:db8::1 ::ffff:127.0.0.1 ::ffff:10.0.0.1 ::ffff:8.8.8.8 fe80::1%eth0 not-an-ip`; true for `8.8.8.8 1.1.1.1 2606:4700:4700::1111`. `isSpecialUseHost` is true for `localhost admin.localhost api.localhost a.b.localhost x.test foo.home.arpa a.onion 1.0.0.10.in-addr.arpa service.arpa anything.invalid x.local corp.internal` and false for `example.com www.example.org latest.com myexample.com test-site.com`. Cross-check: for 5,000 random addresses (fast-check), whenever ipaddr.js `range()` is not `'unicast'`, `isGlobalIp` is false.
- [ ] **Step 2:** Run `npx vitest run tests/worker/ip.test.js`. Expected: FAIL.
- [ ] **Step 3:** `gen-ranges.mjs` reads the CSVs, writes the domain list to `special-domains.js` (label-boundary matching, so `latest.com` does not match `test`), and writes `RANGES` as `{v4: [[startInt, endInt]], v6: [[startBigInt, endBigInt]]}` for every entry whose Globally Reachable value is not `True`. IPv6 additionally requires membership in `2000::/3`; IPv4-mapped `::ffff:0:0/96` is always non-global. `isGlobalIp` does a binary search.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: IANA-derived IP classification`.

### Task 4: SSRF guard

**Files:** Create `src/worker/guard.js`, `tests/worker/guard.test.js`.
**Consumes:** `isGlobalIp(ip: string): boolean`, `parseIp`, `isSpecialUseHost(host: string): boolean` (Task 3).
**Interfaces:** Produces `normalizeTarget(input: string): GuardResult` with `GuardResult = {ok: true, url: string, host: string, hostKind: 'domain' | 'ip'} | {ok: false, reason: 'bad_url' | 'blocked_target', detail: string}`; `checkResolved(addresses: string[]): {ok: true} | {ok: false, reason: 'blocked_target', detail: string}`.

- [ ] **Step 1:** Tests, `normalizeTarget` returns `blocked_target` for `http://127.1/`, `http://0x7f.1/`, `http://2130706433/`, `http://[::1]/`, `http://[::ffff:127.0.0.1]/`, `http://localhost/`, `http://a.local/`, `http://a.internal/`, `http://admin.localhost/`, `http://api.localhost/`, `http://x.test/`, `http://intranet/`, `https://example.com:8443/`, `https://u:p@example.com/`; `bad_url` for `ftp://example.com/` and `not a url`; ok for `https://Example.COM./a?b#c` with `host === 'example.com'`, for `http://x.com:80/` and `https://x.com:443/`, and for `https://münchen.de/` with `host === 'xn--mnchen-3ya.de'`. `checkResolved(['93.184.216.34', '10.0.0.1'])` is blocked (one bad answer rejects all). Property (fast-check): for any string input the function never throws, and every ok result has an http/https URL whose IP host (if any) is global.
- [ ] **Step 2:** Run `npx vitest run tests/worker/guard.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Parse once with `new URL` (it normalizes IPv4 forms and IDNA); strip a trailing dot; decide on `url.hostname`; reject single-label hosts and any host for which `isSpecialUseHost` is true; ports only 80/443 (empty means scheme default); IP hosts must satisfy `isGlobalIp`.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: SSRF guard`.

### Task 5: DoH resolution policy

**Files:** Create `src/worker/resolve.js`, `tests/worker/resolve.test.js`.
**Consumes:** `checkResolved` (Task 4).
**Interfaces:** Produces `resolveHost(host: string, fetchFn: typeof fetch, signal?: AbortSignal): Promise<{ok: true, addresses: string[], subrequests: 2} | {ok: false, reason: 'doh_failed' | 'no_answer' | 'timeout', subrequests: number}>` and `assertPublicHost(host: string, fetchFn: typeof fetch, signal?: AbortSignal): Promise<{ok: true, subrequests: number} | {ok: false, reason: 'blocked_target' | 'doh_failed' | 'no_answer' | 'timeout', detail: string, subrequests: number}>`. IP-literal hosts skip DoH (`subrequests: 0`).

- [ ] **Step 1:** Tests with a mock `fetchFn`: requests go to `https://cloudflare-dns.com/dns-query?name=<host>&type=A` and `type=AAAA` with `accept: application/dns-json`; exactly 2 calls; a CNAME chain ending in A `10.0.0.1` is blocked; A public plus AAAA `::1` is blocked; Status 3 (NXDOMAIN) gives `no_answer`; HTTP 500 or malformed JSON gives `doh_failed` and `assertPublicHost` fails closed; an already-aborted or later-aborted `signal` gives `timeout` and both DoH requests receive that signal.
- [ ] **Step 2:** Run `npx vitest run tests/worker/resolve.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Run A and AAAA in parallel; collect `data` of Answer records with type 1 or 28 (the answer list already contains the CNAME chain); pass all through `checkResolved`.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: DoH resolution policy`.

### Task 6: Manual-redirect fetcher

**Files:** Create `src/worker/fetcher.js`, `tests/worker/fetcher.test.js`.
**Consumes:** `normalizeTarget`, `assertPublicHost`.
**Interfaces:** Produces `LIMITS = {maxHops: 5, timeoutMs: 8000, pageBytes: 1048576, scriptBytes: 262144, subrequestAbort: 40}`, `HEADER_ALLOWLIST: string[]`, and `fetchTarget(url: string, opts: {kind: 'page' | 'script', fetchFn: typeof fetch}): Promise<FetchOutcome>` with `FetchOutcome = {ok: true, finalUrl: string, chain: ChainEntry[], status: number, contentType: string, bytesRead: number, truncated: boolean, headers: Record<string, string>, body: Uint8Array, subrequests: number} | {ok: false, error: ErrorCode, detail: string, chain: ChainEntry[]}`.

- [ ] **Step 1:** Tests via injected `fetchFn`: outbound request is GET with `redirect: 'manual'` and headers exactly `user-agent`, `accept`, `accept-language`; 302 to `http://10.0.0.1/` gives `blocked_target` with the chain recorded; a redirect loop and a 6-hop chain give `too_many_redirects`; https to http redirect gives `blocked_target` with chain note `downgrade_blocked`; `Content-Length: 10` with a 2 MiB stream gives `truncated: true`, `bytesRead: 1048576`; `Set-Cookie` and `Authorization` never appear in `headers`; `application/zip` for kind `page` gives `ok: true`, empty body, content type preserved; kind `script` returns a body only for javascript or ecmascript content types; a never-resolving `fetchFn` (fake timers) gives `timeout`; more than 40 simulated subrequests gives `budget_exhausted`; every hop calls `assertPublicHost` with the shared deadline signal; a DoH lookup that hangs past the 8 s deadline gives `timeout` (the deadline covers DNS as well as the fetch).
- [ ] **Step 2:** Run `npx vitest run tests/worker/fetcher.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. One shared `AbortController` deadline across all hops; read the body stream chunk by chunk counting bytes actually received and cancel the stream at the cap; count every `fetchFn` call plus resolver `subrequests`; resolve `Location` against the current URL.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: guarded manual-redirect fetcher`.

### Task 7: Worker entry, abuse controls, cache, headers

**Files:** Create `src/worker/index.js`, `src/worker/limits.js`, `src/worker/headers.js`, `tests/worker/index.test.js`; modify `wrangler.jsonc` (confirm bindings).
**Consumes:** `fetchTarget`, `LIMITS`.
**Interfaces:** Produces `export default {fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response>}` with `Env {FETCH_LIMITER: {limit(o: {key: string}): Promise<{success: boolean}>}, ENVIRONMENT: string}`; `validateRequest(request: Request): Promise<{ok: true, body: {url: string, kind: 'page' | 'script'}} | {ok: false, status: number, error: ErrorCode}>`; `encodeMeta(meta: object): string` (base64url JSON); `securityHeaders(): Record<string, string>`. Cache key `https://cache.internal/fetch/<kind>/<normalized url>`.

- [ ] **Step 1:** Tests through `SELF.fetch` (vitest-pool-workers), mocking upstream via `fetchMock`: GET gives 405; missing or foreign `Origin` gives 403 `bad_request`; wrong content type gives 415; unknown JSON field gives 400; body over 8 KiB gives 413; URL over 4 KiB gives 400; limiter `success:false` gives 429 with `Retry-After` and `rate_limited`; success returns upstream bytes with `x-audit-meta` decoding to `finalUrl, chain, truncated, cache, status, contentType, bytesRead, headers`; a second identical request reports `cache: 'hit'`; upstream `Cache-Control: no-store` or `private` never caches; `Set-Cookie` appears neither in the response nor in `meta.headers`; every `/api/*` response carries `securityHeaders()`; non-`/api` paths are not handled by the Worker.
- [ ] **Step 2:** Run `npx vitest run tests/worker/index.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Order: method, Origin, content type, size, JSON schema, rate limit (key is `cf-connecting-ip`), `fetchTarget`, cache read before fetch and write after (only cacheable responses, `ctx.waitUntil`), then response with raw body and meta header. Map failures to the spec error codes.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: worker entry with origin check, rate limit, cache`.

### Task 8: Client fetch client, budgets, body decoding

**Files:** Create `src/engine/budget.js`, `src/engine/decode.js`, `src/engine/fetchClient.js`, `tests/engine/{budget,decode,fetchClient}.test.js`.
**Interfaces:** Produces:
- `DEFAULT_LIMITS = {pages: 7, scripts: 4, invocations: 11, parallel: 3, deadlineMs: 45000}`; `createBudget(limits?: Partial<typeof DEFAULT_LIMITS>, now?: () => number): {tryAcquire(kind: 'page' | 'script'): boolean, stats(): {pages: number, scripts: number, invocations: number}, deadlineReached(): boolean, remainingMs(): number}`; `runPool<T>(thunks: (() => Promise<T>)[], limit: number): Promise<T[]>`.
- `decodeBody(bytes: Uint8Array, contentType: string): {text: string, charset: string, fellBack: boolean}` (BOM, then header charset, then `<meta charset>` in the first 1024 bytes, else UTF-8 with `fellBack: true`).
- `createFetchClient(opts?: {fetchFn?: typeof fetch}): {fetchDoc(url: string, kind: 'page' | 'script', signal?: AbortSignal): Promise<FetchedDoc | FetchFailure>}`; `FetchedDoc = {finalUrl, chain, status, contentType, bytesRead, truncated, cache, headers, text, charset, fellBack, isHtml, isBinary}`; `FetchFailure = {error: ErrorCode, detail: string}`.

- [ ] **Step 1:** Tests: `decodeBody` decodes windows-1252 bytes for `café` (header charset), Shift-JIS Japanese text, a UTF-8 BOM, a `<meta charset>` sniff, and an unknown charset falls back with `fellBack: true`; budget refuses the 8th page, 5th script and 12th invocation, and `deadlineReached()` is true after the fake clock passes 45000; `runPool` never exceeds 3 concurrent thunks; `fetchDoc` decodes `x-audit-meta`, marks `application/zip` as `isBinary`, and maps a 429 body to `{error: 'rate_limited'}`; every request to `/api/fetch` is made with `credentials: 'omit'`.
- [ ] **Step 2:** Run `npx vitest run tests/engine`. Expected: FAIL.
- [ ] **Step 3:** Implement. `decodeBody` uses `TextDecoder` with the resolved label and catches unsupported labels.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `feat: fetch client, budget and charset decoding`.

### Task 9: URL, srcset and CSS utilities

**Files:** Create `src/parse/{url,srcset,css}.js`, `tests/parse/{url,srcset,css}.test.js`.
**Interfaces:** Produces `resolveUrl(raw: string, base: string): string | null`; `normalizeForMatch(url: string): {url: string, passes: number, truncated: boolean}` (percent-decode up to 3 passes, drop fragment); `extensionOf(url: string): string | null` (last path segment of the parsed pathname, decoded, lowercase, no dot; query strings are never considered); `PAYLOAD_EXTENSIONS: Set<string>` (`exe msi zip rar 7z iso apk dmg scr bat cmd ps1 jar vbs lnk pkg deb appimage`); `looksUrlLike(attrName: string, value: string): boolean`; `queryFilenames(url: string): string[]` (values, decoded with the same bounded passes and capped at 256 characters, of query parameters named `file`, `filename`, `fname`, `name`, `download`, `dl`, `attachment`, `path`, `f`, case-insensitive) and `extensionOfFilename(name: string): string | null` (extension of the last path-like segment of a bare filename); `parseSrcset(value: string): string[]`; `extractCssUrls(css: string): string[]`.

- [ ] **Step 1:** Tests: `resolveUrl('../a.exe', 'https://x.com/d/e/')` equals `'https://x.com/d/a.exe'`; `extensionOf('https://x.com/a/Setup.EXE?x=.zip#y')` is `'exe'` and `extensionOf('https://x.com/dl?file=a.exe')` is `null`; `normalizeForMatch('https://x.com/a%252eexe')` ends in `.exe` with `passes: 2`, and a 5-layer encoding returns `truncated: true` at 3 passes; `parseSrcset('a.jpg 1x, data:image/png;base64,AAA,BBB 2x')` yields both URLs intact; `extractCssUrls('@import url("a.css"); .x{background:url( \'b.png\' )} /* url(c.png) */')` equals `['a.css', 'b.png']`; `queryFilenames('https://x.com/dl?file=a.exe&q=1')` equals `['a.exe']`, `file=a%252eexe` yields `['a.exe']`, and `?q=a.exe` yields `[]`; `extensionOfFilename('dir/Setup.EXE')` is `'exe'`; `looksUrlLike('data-id', '123')` is false and `looksUrlLike('data-url', 'https://x.com/a.exe')` is true. Property: `normalizeForMatch` terminates on random strings.
- [ ] **Step 2:** Run `npx vitest run tests/parse`. Expected: FAIL.
- [ ] **Step 3:** Implement. `parseSrcset` follows the HTML spec's rule that a candidate URL ends at whitespace, so commas inside the URL are kept. `extractCssUrls` strips comments first.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `feat: url, srcset and css utilities`.

### Task 10: Non-loading HTML tree and URL references

**Files:** Create `src/parse/html.js`, `tests/parse/html.test.js`.
**Consumes:** Task 9 utilities.
**Interfaces:** Produces `parseHtml(html: string): HtmlTree` (parse5 `parse` with `sourceCodeLocationInfo: true`); `effectiveBase(tree: HtmlTree, finalUrl: string): string`; `extractUrlRefs(tree: HtmlTree, baseUrl: string): UrlRef[]` with `UrlRef = {raw: string, resolved: string | null, tag: string, attribute: string, text?: string, line: number | null, column: number | null, source: 'attribute' | 'style' | 'srcset' | 'srcdoc' | 'meta-refresh'}`; `textContentOf(tree: HtmlTree): string`; `snippetAround(html: string, offset: number, max?: number): string` (never longer than 200 characters).

- [ ] **Step 1:** Tests: `<base href="/d/">` makes a relative link resolve against it while `raw` stays as written; `<img src=x onerror=alert(1)>` yields only `raw: 'x'`; `data-id="123"` yields no ref and `data-url="https://x.com/a.exe"` does; `iframe[srcdoc]` is parsed one level deep (a nested srcdoc inside it is ignored); `<meta http-equiv="refresh" content="0;url=https://d.net/f">` yields a `meta-refresh` ref; `object[data]`, `embed[src]`, `video[poster]`, svg `xlink:href`, `form[action]`, `style` attributes and `<style>` blocks are covered; a 1 MiB single-line HTML document parses in under 2 s and every `snippetAround` result is at most 200 characters; random bytes never throw (property).
- [ ] **Step 2:** Run `npx vitest run tests/parse/html.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement with parse5 only. First `<base href>` wins. Anchor `text` is collapsed text content truncated to 100 characters.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: non-loading html tree and url refs`.

### Task 11: Public Suffix List logic

**Files:** Create `src/net/psl.js`, `tests/net/psl.test.js`.
**Interfaces:** Produces `registrableDomain(host: string): string | null` and `crossesRegistrableDomain(hostA: string, hostB: string): boolean`, using tldts with `allowPrivateDomains: true`; IP hosts compare literally.

- [ ] **Step 1:** Tests: `registrableDomain('a.example.co.uk')` is `'example.co.uk'`; `crossesRegistrableDomain('a.example.co.uk', 'b.example.co.uk')` is false; `crossesRegistrableDomain('evil.github.io', 'good.github.io')` is true; `crossesRegistrableDomain('www.x.com', 'x.com')` is false; two different IPs cross, the same IP does not.
- [ ] **Step 2:** Run `npx vitest run tests/net`. Expected: FAIL.
- [ ] **Step 3:** Implement the two functions with tldts.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: registrable domain logic`.

### Task 12: Static JavaScript analysis and constant folder

**Files:** Create `src/analysis/fold.js`, `tests/analysis/fold.test.js`.
**Interfaces:** Produces `analyzeScript(source: string, opts?: Partial<ScriptLimits>): ScriptAnalysis` with `ScriptLimits = {maxSourceBytes: 262144, maxPasses: 3, maxOutputBytes: 524288, maxSteps: 10000, maxDepth: 50}`; `ScriptAnalysis = {status: 'ok' | 'partial' | 'unknown', reason?: string, navigations: Navigation[], urls: FoldedUrl[]}`; `Navigation = {kind: 'location' | 'open' | 'write' | 'anchor-download', value: string | null, topLevel: boolean, start: number, end: number}`; `FoldedUrl = {value: string, via: string[], start: number, end: number}`.

- [ ] **Step 1:** Tests: `window.location = 'ht'+'tps://x.com/a.exe'` gives a `location` navigation with value `'https://x.com/a.exe'` and `topLevel: true`; `location.href = atob('aHR0cHM6Ly94LmNvbS9hLmV4ZQ==')` folds with `via` containing `'atob'`; `String.fromCharCode(...)`, `unescape('%68%74...')`, a template literal over a `const`, and `['ht','tp://x.com/a.exe'].join('')` all fold; `const base='https://x.com'; window.open(base + '/a.exe')` folds and a navigation inside a function has `topLevel: false`; an unresolvable variable gives `value: null` and `status: 'partial'`; a syntax error gives `status: 'unknown'`, reason `script_parse_failed`; source over 256 KiB gives `unknown` with `script_parse_limit_reached`; four nested `atob` layers stop at 3 passes with `partial` and `script_parse_limit_reached`; `document.createElement('a')` with `download` and `href` gives `anchor-download`. With `globalThis.eval` and `Function` replaced by throwing stubs, analysis still completes (it never executes target code).
- [ ] **Step 2:** Run `npx vitest run tests/analysis/fold.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement with Acorn (`ecmaVersion: 'latest'`, location ranges, `allowHashBang`, wrapped in try/catch). The folder evaluates only literal-derived values with the step, depth, pass and output limits, resolving single-assignment `const`/`var` string constants within the file; every other expression yields unknown.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: static JS analysis with bounded constant folder`.

### Task 13: Terminable analysis Worker wrapper

**Files:** Create `src/analysis/analyzer.js`; replace stub `src/analysis/js-worker.js`; create `tests/analysis/analyzer.test.js`.
**Consumes:** `analyzeScript`, `ScriptAnalysis`.
**Interfaces:** Produces `createAnalyzer(opts: {workerFactory: () => Worker, timeoutMs?: number}): {analyze(source: string, meta: {source: 'inline' | 'external', url?: string}): Promise<ScriptAnalysis & {source: 'inline' | 'external', url?: string}>, dispose(): void}` (default `timeoutMs` 3000).

- [ ] **Step 1:** Tests with fake workers: a normal reply resolves with the analysis plus `source`; a worker that never answers is terminated after the timeout and resolves `{status: 'unknown', reason: 'script_analysis_timeout'}`; the next call uses a fresh worker; `dispose()` terminates the current worker.
- [ ] **Step 2:** Run `npx vitest run tests/analysis/analyzer.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement the wrapper; `js-worker.js` posts `analyzeScript(event.data.source)` back.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: terminable script analyzer`.

### Task 14: Detector framework and finding finalization

**Files:** Create `src/detectors/index.js`, `tests/detectors/index.test.js`.
**Consumes:** `makeFingerprint`, `UrlRef`, `ScriptAnalysis`, `ChainEntry`, `HtmlTree`.
**Interfaces:** Produces:
- `DetectorContext = {pageUrl: string, finalUrl: string, baseUrl: string, html: string, tree: HtmlTree, headers: Record<string, string>, chain: ChainEntry[], refs: UrlRef[], scripts: (ScriptAnalysis & {source: 'inline' | 'external', url?: string})[]}`.
- `RawFinding = {detector: string, ruleId: string, category: Category, proposedSeverity: Severity, confidence: Confidence, title: string, target: string, evidence: Evidence, autoTriggered?: boolean}`; `Candidate = {url: string, reason: string, priority: 1 | 2 | 3, sourceEvidence: Evidence, depth: 1}`; `Detector = {id: string, version: string, run(ctx: DetectorContext): {findings: RawFinding[], followCandidates?: Candidate[], coverage?: CoverageEntry[]}}`.
- `runDetectors(ctx: DetectorContext, detectors: Detector[]): Promise<{raw: RawFinding[], candidates: Candidate[], coverage: CoverageEntry[]}>` (a throwing detector yields a coverage `unknown` entry, never a crash).
- `finalizeFindings(raw: RawFinding[]): Promise<Finding[]>`.

- [ ] **Step 1:** Tests: two raws with the same `ruleId` and `target` become one finding with 2 observations; 500 identical raws become one finding with `observationCount: 500` and at most 20 observations; a lone `payload.link.executable` proposed `high` is `low`; the same target flagged by `payload-links` and by `redirects` (both proposed medium or higher) may reach `high`; an `autoTriggered` raw whose target has a payload extension may reach `high`; any other uncorroborated `high` is capped to `medium`; a detector that throws produces coverage `{state: 'unknown'}`.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/index.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Group by fingerprint of `(ruleId, target)`; `id` is `${ruleId}:${fingerprint.slice(0, 12)}`; severity is the highest proposed within the group, then capped by the corroboration rule over all findings sharing the same `target`; weak rules (`payload.link.*`, `uri.blob-reference`, `uri.javascript-href`, `filename.homoglyph`) are capped at `low` when no other finding shares the target; confidence is the highest among observations at the final severity.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: detector framework and finding finalization`.

### Task 15: payload-links detector

**Files:** Create `src/detectors/payload-links.js`, `tests/detectors/payload-links.test.js`.
**Interfaces:** Produces `payloadLinks: Detector` (`id: 'payload-links'`) and `classifyPayloadUrl(url: string): {ruleId: 'payload.link.executable' | 'payload.link.archive' | 'payload.link.query-filename', severity: Severity, extension: string} | null` (reused by Task 17). A pathname extension is checked first; otherwise `queryFilenames` values whose `extensionOfFilename` is a payload extension give `payload.link.query-filename` (proposes `low`, confidence `low`); arbitrary query values are never considered. Executable extensions (`exe msi scr bat cmd ps1 jar vbs lnk pkg deb appimage apk dmg iso`) propose `low`; archives (`zip rar 7z`) propose `info`; confidence `medium`.

- [ ] **Step 1:** Tests using a fixture and `extractUrlRefs`: `<a href="/dl/setup.exe">` yields `payload.link.executable` with evidence tag `a`, attribute `href`; `<a href="/dl?file=a.exe">` and `<a href="/dl?file=a%252eexe">` yield `payload.link.query-filename`, `<a href="/dl?q=a.exe">` yields nothing, and `/a.exe?x=1#frag` yields `payload.link.executable` (pathname match); `srcset`-listed `.zip`, `link[href=x.exe]`, CSS `url(a.iso)` and `data-url="…/a.exe"` are found; `data-id` is not; `normalizedValue` is the resolved URL.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/payload-links.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement `classifyPayloadUrl` with `extensionOf` and `PAYLOAD_EXTENSIONS`, and the detector over `ctx.refs`.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: payload-links detector`.

### Task 16: disguised-filenames detector

**Files:** Create `src/detectors/disguised-filenames.js`, `tests/detectors/disguised-filenames.test.js`.
**Interfaces:** Produces `disguisedFilenames: Detector`; it inspects the last decoded path segment of every ref, `queryFilenames` values, and `download` attribute values. Rules: `filename.double-extension` (medium), `filename.control-chars` (medium), `filename.archive-executable` (medium), `filename.homoglyph` (low); category `filename`.

- [ ] **Step 1:** Tests: `invoice.pdf.exe` and `readme.txt.scr` give `filename.double-extension`; `photo\u202Egpj.exe` gives `filename.control-chars`; `Setup.exe.zip` gives `filename.archive-executable`; a Cyrillic `р` inside `рayload.exe` gives `filename.homoglyph`; `my.file.v2.zip` and `report.pdf` give nothing.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/disguised-filenames.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Double-extension requires a document or media extension (`pdf doc docx xls xlsx txt jpg jpeg png gif mp3 mp4`) followed by an executable one; control characters are U+202A–U+202E and U+2066–U+2069; homoglyph means mixed Latin and non-Latin letters in one segment.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: disguised-filenames detector`.

### Task 17: obfuscated-urls detector

**Files:** Create `src/detectors/obfuscated-urls.js`, `tests/detectors/obfuscated-urls.test.js`.
**Consumes:** `classifyPayloadUrl`, `ScriptAnalysis`.
**Interfaces:** Produces `obfuscatedUrls: Detector`. Rules: `obfuscation.decoded-payload-url` (medium, when `classifyPayloadUrl` matches), `obfuscation.decoded-url` (info). Inline event-handler attributes and HTML attribute values get a regex fallback for base64 blobs of 24+ characters that decode to `http(s)://…`. Scripts with status `unknown` or `partial` add coverage entries carrying their reason.

- [ ] **Step 1:** Tests: inline script `location='ht'+'tp://x.com/a.exe'` yields `obfuscation.decoded-payload-url`; `data-u="aHR0cHM6Ly94LmNvbS9hLmV4ZQ=="` is found; `unescape('%68%74%74%70…')` is found; base64 of an image header and benign `'a'+'b'` yield nothing; a script with status `partial` and reason `script_parse_limit_reached` yields a coverage entry with that reason.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/obfuscated-urls.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement over `ctx.scripts[*].urls` and the attribute fallback.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: obfuscated-urls detector`.

### Task 18: redirects detector

**Files:** Create `src/detectors/redirects.js`, `tests/detectors/redirects.test.js`.
**Consumes:** `crossesRegistrableDomain`, `registrableDomain`.
**Interfaces:** Produces `redirects: Detector`. Rules: `redirect.meta-refresh` (low, `autoTriggered: true`), `redirect.script-navigation` (low; `autoTriggered` equals `topLevel`), `redirect.chain-cross-domain` (low for one crossing, medium when 3 or more distinct registrable domains), `redirect.final-host-differs` (info). Meta-refresh and script navigation targets with a resolved value become priority-1 `followCandidates`. A navigation with `value: null` adds coverage `{reason: 'unsupported_runtime_behavior'}`.

- [ ] **Step 1:** Tests: meta refresh `0;url=https://dl.example.net/f` gives the finding and a priority-1 candidate; a chain across four registrable domains gives `redirect.chain-cross-domain` medium; `www.x.com` to `x.com` gives none; `window.open` inside a function is not `autoTriggered`; a `null`-valued navigation gives the coverage entry.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/redirects.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement over `ctx.refs` (`meta-refresh` source), `ctx.scripts[*].navigations` and `ctx.chain`.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: redirects detector`.

### Task 19: hidden-overlays detector

**Files:** Create `src/detectors/hidden-overlays.js`, `tests/detectors/hidden-overlays.test.js`.
**Interfaces:** Produces `hiddenOverlays: Detector`; confidence never above `medium`. Rules: `overlay.hidden-iframe` (medium), `overlay.fullscreen-capture` (medium), `overlay.offscreen-link` (low). It reads inline `style` attributes and simple `.class`/`#id` selectors from `<style>` blocks.

- [ ] **Step 1:** Tests: an off-origin iframe with `width="0"` or `style="display:none"` gives `overlay.hidden-iframe`; a `position:fixed;width:100%;height:100%;opacity:0` element containing an anchor gives `overlay.fullscreen-capture`; `left:-9999px` anchors give `overlay.offscreen-link`; a visible same-origin iframe and a normal fixed header give nothing; no finding has confidence `high`.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/hidden-overlays.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement a small declaration parser for inline and block styles; document in the file header that computed styles are not evaluated.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: hidden-overlays detector`.

### Task 20: Forms and URI-scheme detectors

**Files:** Create `src/detectors/forms-and-schemes.js`, `tests/detectors/forms-and-schemes.test.js`.
**Interfaces:** Produces `offOriginForms: Detector` and `uriSchemes: Detector`. Rules: `form.off-origin-action` (low), `form.password-off-origin` (medium: a password input inside a form whose action crosses the registrable domain; brand-context matching is deferred), `uri.data-download` (medium: `data:` URL with an executable or archive MIME type, or with `download`), `uri.blob-reference` (info, plus coverage `skipped` reason `blob_not_inspected`), `uri.javascript-href` (info), `uri.ms-handler` (medium: `ms-appinstaller:` and `ms-msdt:`).

- [ ] **Step 1:** Tests: a form posting to another registrable domain gives `form.off-origin-action`, with a password field `form.password-off-origin`; a same-site form gives none; `data:application/x-msdownload;base64,…` gives `uri.data-download`; a `blob:` href gives the info finding and the skipped coverage; `javascript:void(0)` gives info; `ms-appinstaller:?source=…` gives `uri.ms-handler`.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/forms-and-schemes.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement both detectors over the tree and `ctx.refs`.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: form and uri-scheme detectors`.

### Task 21: header-hints detector

**Files:** Create `src/detectors/header-hints.js`, `tests/detectors/header-hints.test.js`.
**Interfaces:** Produces `parseContentDisposition(value: string): {type: string, filename: string | null}` (`filename*` in `charset'lang'percent-encoded` form takes precedence over `filename`) and `headerHints: Detector`. Rules: `header.content-disposition-attachment` (info; low when the filename is a payload extension), `header.executable-content-type` (low) for `application/x-msdownload`, `application/vnd.microsoft.portable-executable`, `application/x-dosexec`, `application/x-msdos-program`, `application/java-archive`.

- [ ] **Step 1:** Tests: `attachment; filename="a.exe"; filename*=UTF-8''%e2%82%ac.exe` returns filename `€.exe`; malformed percent-encoding in `filename*` falls back to `filename`; an attachment with `setup.exe` gives low severity; `inline` gives nothing; each listed content type gives `header.executable-content-type`.
- [ ] **Step 2:** Run `npx vitest run tests/detectors/header-hints.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement the parser and detector over `ctx.headers` (evidence location type `response_header`).
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: header-hints detector`.

### Task 22: Scan engine

**Files:** Create `src/engine/candidates.js`, `src/engine/scan.js`, `tests/engine/{candidates,scan}.test.js`, fixtures `tests/fixtures/scan/*.html`.
**Consumes:** every earlier module; the detector list `[payloadLinks, disguisedFilenames, obfuscatedUrls, redirects, hiddenOverlays, offOriginForms, uriSchemes, headerHints]`.
**Interfaces:** Produces `normalizeUserInput(input: string): string` (trim; the input has a scheme only if it matches `^[a-z][a-z0-9+.-]*://` or starts with one of `view-source:`, `javascript:`, `file:`, `data:`, `ftp:`, `mailto:`, `about:`, `blob:`; otherwise prepend `https://`, so `host:port/path` is treated as a host; throws `Error('unsupported_scheme')` for the non-http schemes); `rankCandidates(refs: UrlRef[], detectorCandidates: Candidate[], pageUrl: string): Candidate[]` (dedupe normalized URLs, priority 1 explicit download links, meta refresh, script redirects and download form actions; priority 2 same-origin paths or anchor text matching download, mirror, get, installer, link, redirect; priority 3 off-origin targets with strong context; at most 100 collected); `scan(url: string, deps: {client: {fetchDoc}, analyzer: {analyze}, detectors?: Detector[], budget?: Budget, now?: () => number}): Promise<Report>`.

- [ ] **Step 1:** Tests with a fake client: links found on followed pages are never fetched (depth 1); at most 6 followed pages in priority order; a candidate URL longer than 4 KiB is dropped; at most 4 same-origin scripts, skipping filenames matching `jquery|bootstrap|react|vue|angular|lodash`; deadline passage records `scan_deadline_reached`; a linked stylesheet records `external_stylesheet_skipped`; truncation records `response_truncated`; `rate_limited` failures become coverage and still produce a valid Report (`validateReport` ok). Review Focus: `normalizeUserInput(' example.com/a ')` equals `'https://example.com/a'`, `example.com:443/path` becomes `https://example.com:443/path`, `example.com:8080/path` becomes `https://example.com:8080/path` (the guard later rejects port 8080 with `blocked_target`), and the bad schemes throw `unsupported_scheme`; scanning `https://example.com/download?token=SECRET123` fetches the full URL (the fake client records it) while `JSON.stringify` of the returned Report does not contain `SECRET123`; a JavaScript-rendered shell (under 200 characters of text plus one script) adds coverage `{check: 'static-coverage', state: 'unknown', reason: 'unsupported_runtime_behavior'}`; a root `application/zip` response gives coverage `binary_not_inspected` skipped plus a `payload.link.archive` finding for the target; 403, 503 and a body containing `Just a moment...` or `captcha` give coverage `unknown` with reason `fetch_blocked_or_challenge`.
- [ ] **Step 2:** Run `npx vitest run tests/engine/candidates.test.js tests/engine/scan.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement. Flow: fetch root → decode → `parseHtml` → refs → analyze inline scripts → `runDetectors` → rank → fetch followed pages and scripts through `runPool` with parallel 3 under the budget → run detectors on each page → `finalizeFindings` → Report with `engineVersion: '0.1.0'`, `detectorVersions`, `fetchStats`, `durationMs`.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `feat: scan engine`.

### Task 23: UI shell and safe rendering

**Files:** Replace stubs `src/ui/{index.html,app.js,styles.css}`; create `src/ui/render.js`, `tests/ui/render.test.js`.
**Consumes:** `scan`, `displayUrl`, `Report`.
**Interfaces:** Produces `renderReport(report: Report, root: HTMLElement): void`; `renderProgress(state: {phase: 'fetching' | 'parsing' | 'following' | 'analyzing' | 'done', detail?: string}, root: HTMLElement): void`; `reportToSummaryText(report: Report): string`; `exportReportJson(report: Report): string` (includes `v` and `coverage`; always runs `sanitizeReport` first, as do `reportToSummaryText` and every render path); `startApp(doc: Document, deps: {scan: typeof scan}): void`.

- [ ] **Step 1:** Tests (jsdom plus axe-core): a hostile report whose title, snippet, matchedValue and sourceUrl contain `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `javascript:alert(1)`, a U+202E override and a lone surrogate renders with zero `script, img, iframe, a[href], [onerror]` elements and `root.textContent` containing the hostile strings literally; payload URLs appear defanged and are not wrapped in anchors; the overview shows findings count and scan coverage as separate items; every finding shows severity, confidence, category, rule, source page and element/attribute as text; the exact disclaimer is present with zero findings and with findings; an incomplete scan shows the coverage panel and the word "incomplete"; no element shows the word "safe" as a verdict; axe reports no violations (color-contrast rule disabled under jsdom); `exportReportJson` output parses and has `v: 1`; a report with `?token=SECRET123` in every URL-bearing field, rendered and exported, never shows `SECRET123` in the DOM text, the summary text or the JSON.
- [ ] **Step 2:** Run `npx vitest run tests/ui`. Expected: FAIL.
- [ ] **Step 3:** Implement with `createElement` and `textContent` only (lint enforces). Use labeled input, visible focus classes, text severity labels, an `aria-live="polite"` progress region, and responsive cards. `startApp` runs `normalizeUserInput`, shows friendly errors, and creates the analyzer with `new Worker('/js-worker.js')`.
- [ ] **Step 4:** Run the test, then `npm run lint` and `npm run build`. Expected: PASS, clean, exit 0.
- [ ] **Step 5:** Commit `feat: UI shell with safe rendering`.

### Task 24: Static security headers

**Files:** Create `public/_headers`, `tests/headers.test.js`.
**Interfaces:** Produces the `_headers` rules for `/*`.

- [ ] **Step 1:** Test parses `public/_headers` and asserts: the CSP equals the Global Constraints string exactly; `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains` or `preload` until the domain policy is confirmed); `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`; `Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()`; `X-Frame-Options: DENY`; a separate `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`; the rule count is at most 100 and each line at most 2,000 characters.
- [ ] **Step 2:** Run `npx vitest run tests/headers.test.js`. Expected: FAIL.
- [ ] **Step 3:** Write the file.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit `feat: static security headers`.

### Task 25: Quality gates and corpora

**Files:** Create `tests/fixtures/clean/*.html` + `manifest.json` (`{file, description, capturedOn}` or `{file, description, synthetic: true}`), `tests/fixtures/recall/*.html` + `manifest.json` (`{file, expected: [{ruleId, tag?, attribute?}]}`), `tests/gates/{clean,recall,severity}.test.js`.

- [ ] **Step 1:** Tests: the clean gate scans every clean fixture through `scan` with a fake client and asserts zero `high` findings and that the manifest has `capturedOn` or `synthetic: true` for every file; the recall gate asserts every expected `ruleId` (and location when given) appears; the severity gate (fast-check over generators of single-signal pages: one executable link, punycode host, `blob:` link, one unrelated mirror link) asserts no finding is `high`.
- [ ] **Step 2:** Run `npx vitest run tests/gates`. Expected: FAIL (fixtures missing).
- [ ] **Step 3:** Author at least 10 clean fixtures (documentation site, news article, ad-heavy page with trackers and no payloads, official vendor download page with a legitimate installer link, forum with many links, store page, blog, SPA shell, file-host landing page, wiki page) as reduced or synthetic captures, and at least one recall fixture per detector rule (every `ruleId` defined in Tasks 15–21).
- [ ] **Step 4:** Run the gates. Expected: PASS. Fix detector false positives or recall gaps in the owning detector, adding a regression fixture for each.
- [ ] **Step 5:** Commit `test: clean-site, recall and severity gates`.

### Task 26: Browser end-to-end test

**Files:** Create `tests/e2e/ui.spec.js`, `playwright.config.js`.
**Interfaces:** Produces `npm run test:e2e` (builds, serves with `wrangler dev`, runs Playwright).

- [ ] **Step 1:** Write the spec: route-intercept `/api/fetch` with canned responses from a recall fixture that has an obfuscated inline script and a hostile fixture with markup in filenames; submit a URL. Assert: the report renders and the obfuscation finding appears (proves the real Web Worker ran); no `securitypolicyviolation` events and no console errors; no `dialog` event fires; every network request is same-origin (no request to a hostile URL).
- [ ] **Step 2:** Run `npm run test:e2e`. Expected: FAIL until wired.
- [ ] **Step 3:** Add the Playwright config and the npm script; fix any CSP or Worker-path issue the test exposes in the owning file.
- [ ] **Step 4:** Run `npm run test:e2e`. Expected: PASS.
- [ ] **Step 5:** Commit `test: browser end-to-end safety checks`.

### Task 27: Staging verification, detector docs, release claims

**Files:** Create `scripts/staging/{fixtures-worker.js, run.mjs}`, `docs/staging-report.md`, `docs/detectors/<id>.md` (8 files), `docs/RELEASE_NOTES.md`, `tests/docs.test.js`.
**Interfaces:** Produces `npm run staging` (`STAGING_URL`, optional `STAGING_PRIVATE_DNS_HOST` naming a DNS record the owner controls that resolves to `10.0.0.1`). The optional DNS check is named "Private DNS answer rejection" and is not a rebinding test; true DNS rebinding (answers that change between validation and connection) stays a documented residual risk unless a separate controlled test is built. Without the hostname the check is recorded as "not verified" and nothing else is blocked.

- [ ] **Step 1:** Write `tests/docs.test.js`: each detector doc has headings `Supported inputs`, `Blind spots`, `Confidence`, `False positives`; `README.md`, `docs/**` and `RELEASE_NOTES.md` contain none of "prevents all SSRF", "detects all malicious", "proves a site safe", "zero data collection"; release notes have a `Residual risks` heading mentioning DNS rebinding and a `Demonstrated coverage` heading.
- [ ] **Step 2:** Run `npx vitest run tests/docs.test.js`. Expected: FAIL.
- [ ] **Step 3:** Write the docs. Write `fixtures-worker.js` (a second Worker we own) serving: redirect to `http://10.0.0.1/`, redirect to `http://169.254.169.254/`, loop, 6-hop chain, slow-drip body, a body larger than the cap with a lying `Content-Length`, and a `Set-Cookie` response. `run.mjs` calls the staging `/api/fetch` against each, plus the Private DNS answer rejection check when `STAGING_PRIVATE_DNS_HOST` is set, and records: blocked or failed as expected, the subrequest count, whether the Rate Limiting binding exists on the Free plan, cache locality across repeated requests, and CPU time for a page at the cap. Record every result, including skipped checks, in `docs/staging-report.md`. If the binding is unavailable on Free, implement `createCacheLimiter(cache: Cache): {limit(o: {key: string}): Promise<{success: boolean}>}` (30 per 60 s per key, configurable) in `src/worker/limits.js` with a unit test, bind it in `index.js`, and state in `README.md` and the release notes that Cache API entries are local to one data centre, so this limiter is a weaker best-effort control than the binding. If CPU at 1 MiB exceeds budget, lower `LIMITS.pageBytes` and say so in the report.
- [ ] **Step 4:** Run `npx vitest run`, `npm run lint`, `npm run build`, `npm run test:e2e`, then `npm run staging` against a deployed staging Worker. Expected: all pass, with `docs/staging-report.md` filled in.
- [ ] **Step 5:** Commit `docs: staging report, detector docs, release notes`.

## Owner Setup Checklist (for a beginner owner)

Claude tells the owner when each item is needed; nothing here blocks the tasks before it.

| When | What | Why |
|---|---|---|
| Before Task 1 | Allow network access (at least npm) for Claude's code execution, or run the tasks on your own computer with Node.js 22+ | Dependencies must be installed to run any test |
| Before Task 1 is pushed | Create a GitHub repository for the project | Holds the code; needed for Dependabot and vulnerability reporting |
| Before relying on `SECURITY.md` | In the repository settings, enable private vulnerability reporting, and confirm it is on | `SECURITY.md` points reporters there |
| Before Task 26 | Install the Playwright browser (`npx playwright install chromium`) | End-to-end test needs a real browser |
| Before Task 27 | Create a free Cloudflare account and run `npx wrangler login` | Needed to deploy the staging Worker and run real tests |
| During Task 27 | Check whether the Rate Limiting binding works on the Free plan and whether caching works on your domain (`workers.dev` or custom) | Results go in `docs/staging-report.md`; the app works without cache |
| Optional, Task 27 | A DNS record you control (for example `private-test.<your-domain>`) pointing to `10.0.0.1`, set as `STAGING_PRIVATE_DNS_HOST` | Enables the Private DNS answer rejection check; skip if you have no domain |
