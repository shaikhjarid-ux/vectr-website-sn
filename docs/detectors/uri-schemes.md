# uri-schemes

Reports unusual URL schemes used for downloads or handler launches.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `uri.data-download` | medium | a data: URL with an executable or archive media type, or a data: link on an anchor with a download attribute |
| `uri.blob-reference` | info | a blob: reference to a runtime resource (recorded as skipped coverage, blob_not_inspected) |
| `uri.javascript-href` | info | a javascript: link in an href attribute |
| `uri.ms-handler` | medium | ms-appinstaller: and ms-msdt: links |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

The scheme of every resolved URL reference. Targets of data: and javascript: findings are truncated to 80 characters.

## Blind spots

Other custom protocol handlers are not listed. The contents of data: and blob: payloads are not decoded or inspected.

## Confidence

Medium. The blob and javascript rules are weak indicators and stay at low severity unless another finding shares the target.

## False positives

javascript:void(0) links are everywhere and are reported once as info. data: downloads are used by some web apps for user-generated files.
