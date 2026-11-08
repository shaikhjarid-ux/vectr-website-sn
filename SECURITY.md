# Security policy

## Reporting a vulnerability

Please report security problems through GitHub private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for a vulnerability.

## Abuse and takedown reports

If you believe this service is being used to scan your site abusively, or you
want a result removed, report it the same way (private vulnerability reporting)
and include the hostname and approximate time. Reports contain no stored scan
history: scans run in the visitor's browser and are not kept centrally.

## Scope

In scope: the Worker proxy (SSRF guard, abuse controls, cache), the scan
engine, and the UI's handling of hostile page content. Out of scope: findings
about third-party sites that are scanned, and the limits listed under
"Residual risks" in `docs/threat-model.md`.
