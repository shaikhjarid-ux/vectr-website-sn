# Staging report

Generated: 2026-11-11
Staging URL: not set

Status values: **pass** and **fail** were observed against the deployed staging Worker; **info** was recorded but is not a pass/fail check; **not verified** means the check was not run or could not be observed, and nothing should be assumed about it.

| Check | Expected | Status | Observed |
|---|---|---|---|
| Redirect to a private address is blocked | 403 blocked_target | not verified | not run |
| Redirect to the cloud metadata address is blocked | 403 blocked_target | not verified | not run |
| Redirect loop is stopped | 502 too_many_redirects | not verified | not run |
| Six redirect hops are refused | 502 too_many_redirects | not verified | not run |
| Slow-drip body hits the 8 s deadline | 504 timeout | not verified | not run |
| Oversized body with a lying Content-Length is capped by bytes read | 200 with truncated true and bytesRead 1048576 | not verified | not run |
| Set-Cookie is never returned or cached | no set-cookie, second request is a cache miss | not verified | not run |
| Private DNS answer rejection (not a rebinding test) | 403 blocked_target for a hostname that resolves to 10.0.0.1 | not verified | not run |
| Rate Limiting binding exists on this plan and limits requests | some 429 responses within a burst, no 503 | not verified | not run |
| Cache behaviour across repeated requests | recorded only (Cache API entries are local to one data centre) | not verified | not run |
| Subrequest count per scan | recorded only (logged by the Worker; read with wrangler tail) | not verified | not run |
| CPU time for a page at the 1 MiB cap | within the Free plan CPU limit (read from the Cloudflare dashboard) | not verified | not run |

DNS rebinding (answers that change between validation and connection) is not tested by any check above and remains a documented residual risk.
