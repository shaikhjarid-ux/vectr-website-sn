# obfuscated-urls

Reports URLs that script obfuscation hid, after a bounded static decode.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `obfuscation.decoded-payload-url` | medium | a decoded URL that looks like a payload |
| `obfuscation.decoded-url` | info | a decoded URL recovered through atob, unescape, decodeURI(Component), String.fromCharCode or join |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

Folded URLs from the static JavaScript analyzer (string literals, concatenation, template literals, single-assignment constants, join on literal arrays, and the decoders above, with limits of 3 decoding passes, 50 nesting levels, 10,000 steps and 512 KiB of output) and base64 or base64url blobs of 24 or more characters in any HTML attribute that decode to an http(s) URL.

## Blind spots

Nothing is ever executed. Values that depend on runtime state, network responses, user input, eval, new Function, or on variables that are reassigned are unknown. Scripts that fail to parse, exceed 256 KiB or time out are reported as coverage entries, not findings. External scripts are fetched only for the root page, from the same origin, at most four, skipping well-known library file names.

## Confidence

Medium for decoded payload URLs, low for other decoded URLs. A decoded URL proves that obfuscation was used, not that the destination is harmful.

## False positives

Legitimate scripts sometimes build URLs by concatenation or encode them for analytics. Plain concatenation of a non-payload URL is deliberately not reported.
