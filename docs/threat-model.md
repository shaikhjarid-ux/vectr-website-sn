# Threat model

Summary of spec section 3, plus the DNS-rebinding residual risk from spec section 8.

## Assets

The Worker's free quota and reputation, our visitors' browsers, third-party sites we fetch, and the integrity of reports.

## Attacker-controlled inputs

The submitted URL, every byte of every fetched response (HTML, scripts, headers, redirects), DNS answers for attacker-owned names, and direct calls to `/api/fetch`.

## Trust boundaries

Browser to Worker; Worker to internet; fetched content to analysis code; analysis output to rendered UI.

## Threats considered

SSRF and redirect abuse; DNS tricks; resource exhaustion (bytes, CPU, memory, time, quota); XSS and resource loading from hostile markup; secret leakage through redirects, headers or logs; use of the service as an anonymous scanning relay; cache poisoning or cache leakage; misleading verdicts.

## Out of scope

Executing or detonating payloads, defending against a compromised Cloudflare account, and any guarantee of detecting all malicious sites.

## Residual risks

DNS rebinding: validating DNS and then fetching by hostname leaves a time-of-check/time-of-use gap that a Worker cannot fully close, because `fetch()` resolves the name itself. We believe Workers cannot reach private networks and that Cloudflare restricts some destinations, but we do not rely on that belief. The staging suite probes real behavior and the release notes document this risk. We do not claim complete SSRF prevention.

Rate limiting is approximate, per Cloudflare location, and is abuse protection, not a security boundary.
