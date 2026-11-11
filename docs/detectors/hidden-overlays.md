# hidden-overlays

Looks for invisible iframes, click-capture layers and off-screen links in the markup.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `overlay.hidden-iframe` | medium | an off-site iframe hidden by display:none, visibility:hidden, opacity 0, zero or 1 px size, or the hidden attribute (also when an ancestor is hidden) |
| `overlay.fullscreen-capture` | medium | a transparent full-viewport fixed or absolute layer that contains a link or has a click handler |
| `overlay.offscreen-link` | low | a link positioned 1000 px or more off-screen |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

Inline style attributes and simple .class and #id rules from style blocks. Rules inside @media or any other at-rule are ignored, as are other selectors; specificity is not modelled.

## Blind spots

Computed styles are not evaluated. External stylesheets are never fetched (a skipped-coverage entry is recorded), so hiding done in a stylesheet is missed. Layers created or changed by script at runtime are not seen.

## Confidence

Medium for hidden iframes, low for the other two. No rule reports high confidence.

## False positives

Analytics and consent iframes are often hidden on purpose, and accessibility skip links are positioned off-screen (in-page # links are skipped).
