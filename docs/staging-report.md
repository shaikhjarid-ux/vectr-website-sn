# Staging report

Generated: 2026-11-14
Staging URL: https://vectr-website-sn.vectr-sn.workers.dev

Status values: **pass** and **fail** were observed against the deployed staging Worker; **info** was recorded but is not a pass/fail check; **not verified** means the check was not run or could not be observed, and nothing should be assumed about it.

| Check | Expected | Status | Observed |
|---|---|---|---|
| Redirect to a private address is blocked | 403 blocked_target | pass | HTTP 403 blocked_target in 570 ms |
| Redirect to the cloud metadata address is blocked | 403 blocked_target | pass | HTTP 403 blocked_target in 53 ms |
| Redirect loop is stopped | 502 too_many_redirects | pass | HTTP 502 too_many_redirects in 50 ms |
| Six redirect hops are refused | 502 too_many_redirects | pass | HTTP 502 too_many_redirects in 77 ms |
| Slow-drip body hits the 8 s deadline | 504 timeout | pass | HTTP 504 timeout in 8067 ms |
| Oversized body with a lying Content-Length is capped by bytes read | 200 with truncated true and bytesRead 1048576 | pass | HTTP 200 in 65 ms; truncated true, bytesRead 1048576 |
| Set-Cookie is never returned or cached | no set-cookie, second request is a cache miss | pass | first HTTP 200 in 69 ms; second cache miss; cookie leaked false |
| Private DNS answer rejection (not a rebinding test) | 403 blocked_target for a hostname that resolves to 10.0.0.1 | not verified | STAGING_PRIVATE_DNS_HOST not set |
| Rate Limiting binding exists on this plan and limits requests | some 429 responses within a burst, no 503 | pass | 40 requests from one key: 2 x 429, 0 x 503 |
| Cache behaviour across repeated requests | recorded only (Cache API entries are local to one data centre) | info | 5 repeated requests: hit, hit, hit, hit, hit |
| Subrequest count per scan | recorded only (logged by the Worker; read with wrangler tail) | not verified | the Worker logs the count; read it with wrangler tail (not observable over HTTP) |
| CPU time for a page at the 1 MiB cap | within the Free plan CPU limit (read from the Cloudflare dashboard) | not verified | wall time for a small page 54 ms; CPU time at 1 MiB must be read from the Cloudflare dashboard |

DNS rebinding (answers that change between validation and connection) is not tested by any check above and remains a documented residual risk.
