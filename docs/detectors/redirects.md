# redirects

Finds automatic navigation and redirects that cross sites.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `redirect.meta-refresh` | low | a meta refresh to an http(s) URL |
| `redirect.script-navigation` | low | location assignment, location.assign/replace, window.open or an anchor download created by script |
| `redirect.chain-cross-domain` | low or medium | HTTP redirects that cross registrable domains; medium with three or more distinct domains |
| `redirect.final-host-differs` | info | final host differs from the requested host without crossing a registrable domain (a leading www. is ignored) |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

Meta refresh references, folded navigations from the script analyzer (top-level navigations are marked auto-triggered), and the redirect chain recorded by the fetch service for every fetched page. Registrable domains use the Public Suffix List including private suffixes such as github.io.

## Blind spots

Redirects performed after user interaction, timers or network responses are only seen when the script statically contains the target. HTTPS-to-HTTP downgrades are not followed. Navigation targets that cannot be folded add an unsupported_runtime_behavior coverage entry.

## Confidence

High for HTTP chains and meta refresh, medium for script navigation.

## False positives

Login and payment flows, link trackers, CDNs and country redirects all cross domains legitimately. A single hop is low severity by design.
