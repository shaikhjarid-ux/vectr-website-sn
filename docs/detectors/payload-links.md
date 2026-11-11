# payload-links

Finds links to executable-looking files and archives in the page.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `payload.link.executable` | low | exe msi scr bat cmd ps1 jar vbs lnk pkg deb appimage apk dmg iso in the URL path |
| `payload.link.archive` | info | zip rar 7z in the URL path |
| `payload.link.query-filename` | low | a file-name-like query parameter (file, filename, name, download, dl, path, f, fname, attachment) ending in a payload extension |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

Resolved http and https URLs from every URL reference the HTML parser extracts: anchors, area, link, iframe, embed, object, video, audio, source, form actions, srcset candidates, CSS url() and @import in style attributes and style blocks, srcdoc iframes one level deep, meta refresh targets, and data-* attributes that look like URLs. Extensions are read from the decoded path (up to three percent-decoding passes, query string and fragment excluded) and from file-name query parameters.

## Blind spots

Links created only at runtime by scripts are covered by the obfuscated-urls and redirects detectors, not this one. A file served from an extension-less URL (for example /download?id=7) is only seen through its response headers (header-hints) when that URL is followed. Payload content is never downloaded or inspected.

## Confidence

Medium for path extensions and low for query file names. Archives propose info because they are common and benign.

## False positives

Legitimate installers on a vendor site, source archives and documentation PDFs-as-zip are all flagged. A lone link stays at low severity by design; it only matters together with other signals.
