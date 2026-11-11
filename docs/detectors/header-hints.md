# header-hints

Reads Content-Disposition and executable Content-Type hints from responses.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `header.content-disposition-attachment` | info or low | the response is served as an attachment (low when the file name has a payload extension) |
| `header.executable-content-type` | low | Content-Type is application/x-msdownload, vnd.microsoft.portable-executable, x-dosexec, x-msdos-program or java-archive |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

Response headers of the root page and of every followed page, as returned by the fetch service (an allowlist of headers; cookies are never included). filename* is preferred over filename and decoded as UTF-8 or ISO-8859-1; a malformed filename* falls back to filename.

## Blind spots

Only the headers of pages that were actually fetched are seen, and only for the allowlisted header names. Responses to requests made with different headers (for example a real browser) may differ.

## Confidence

Medium. These describe how a server labels a response, not what the file is.

## False positives

Many sites serve ordinary documents, exports and images as attachments, and some serve archives as application/java-archive.
